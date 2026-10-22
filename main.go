// Package main —— PHP 漏洞（php2shell / CVE-2026-109618、CVE-2026-109619）批量排查工具
//
// 架构：Go 后端（x/crypto/ssh 扫描 + net/http 本地服务）+ 浏览器界面（HTML/CSS/JS 内嵌）。
// 纯 Go、零 cgo，可从 Windows 直接交叉编译出 macOS / Linux 版本。
// 服务只监听 127.0.0.1，不对外暴露；凭据不落盘；远端探测脚本经 stdin 执行，不在目标机留文件。
//
// 仅用于授权环境下的自查与补丁，属防御性排查。
//
// Author : Bian Chengxu（边承旭）
// Email  : bianqiang@gmail.com
// Website: https://www.spark8.xyz
// License: MIT
package main

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed ui/index.html
var uiFS embed.FS

// ---------------------------------------------------------------------------
// 作者与版本信息（单一信息源：界面“关于”、报告页脚、CLI 横幅、LICENSE 全部由此派生）
// ---------------------------------------------------------------------------
const (
	appName    = "PHPScan"
	appVersion = "1.0.0"
	// 作者艺名 / 本名
	authorNameEN = "Bian Chengxu"
	authorNameZH = "边承旭"
	// 联系方式
	authorEmail = "bianqiang@gmail.com"
	authorSite  = "https://www.spark8.xyz"
	// 开源地址（发布到 GitHub 后如需调整，改这里即可）
	repoURL = "https://github.com/bianqiang-ui/phpscan-go"
)

// authorName 返回“艺名（中文名）”，用于报告页脚。
func authorName() string {
	return authorNameEN + "（" + authorNameZH + "）"
}

// authorLine 生成“作者 · 邮箱 · 站点”单行署名，用于 CLI 横幅。
func authorLine() string {
	return authorName() + " · " + authorEmail + " · " + authorSite
}

// ---------------------------------------------------------------------------
// 远端探测脚本（内嵌，不落盘）。find 已排除虚拟文件系统与 docker overlay。
// ---------------------------------------------------------------------------
const remoteScript = `phpbin=$(find / \( -path /proc -o -path /sys -o -path /dev -o -path /var/lib/docker -o -path /mnt -o -path /media -o -path /run \) -prune -o -type f \( -name 'php' -o -name 'php-fpm*' -o -name 'php-cgi' \) -print 2>/dev/null | while read b; do case "$b" in /etc/rc.d/init.d/*|/etc/init.d/*) continue;; esac; v=$("$b" -v 2>/dev/null | head -1); [ -n "$v" ] && echo "$b => $v"; done)
pkg=$( (dpkg -l 2>/dev/null | awk '/^ii/{print $2" "$3}' | grep -i php; rpm -qa 2>/dev/null | grep -i php) | head -30 )
vhost=$(grep -rhiEo 'php[0-9.]*fpm.sock|fastcgi_pass[ ]+[^;]*php[0-9.]*' /etc/nginx /etc/apache2 /etc/httpd /usr/local/nginx 2>/dev/null | sort -u)
dockerphp=$(docker ps -a --format '{{.Names}}' 2>/dev/null | while read c; do v=$(docker exec "$c" php -v 2>/dev/null | head -1); if [ -z "$v" ]; then v=$(docker exec "$c" find / -name php -type f 2>/dev/null | head -1 | xargs -r -I{} sh -c '{} -v 2>/dev/null | head -1'); fi; [ -n "$v" ] && echo "$c => $v"; done)
echo "PHPBIN::${phpbin}"
echo "PKG::${pkg}"
echo "VHOST::${vhost}"
echo "DOCKER::${dockerphp}"`

// 修复版本（低于即中招）
var fixVer = map[int]int{2: 35, 3: 36, 4: 27, 5: 12}

// PHP 各运行模式（SAPI）说明，写入报告（中英双语）
const sapiGuideZH = `PHP 同一版本通常包含三个不同用途的二进制（都可能是中招版本，需分别升级）：
  1) sbin/php-fpm  →  fpm-fcgi（PHP-FPM / FastCGI Process Manager）：
     通过 FastCGI 给 Nginx / Apache(mod_proxy_fcgi) 提供 PHP 服务，是线上网站的主流运行方式，修复重点。
  2) bin/php-cgi  →  cgi-fcgi（CGI / FastCGI 网关）：
     处理 CGI 或 FastCGI 请求，常见于旧式 CGI 部署。
  3) bin/php  →  cli（Command Line Interface，命令行）：
     终端直接执行的 PHP，如 cron 计划任务、后台脚本。
说明：上述三者版本号相同（例如都是 8.2.28），但作用不同；只升级其中一个，另两个仍是中招版本。`

const sapiGuideEN = `A single PHP installation usually ships three binaries for different SAPIs
(all of them may be vulnerable, and each one needs its own upgrade):
  1) sbin/php-fpm  ->  fpm-fcgi (PHP-FPM / FastCGI Process Manager):
     Serves PHP to Nginx or Apache (mod_proxy_fcgi) over FastCGI. This is how
     most production sites run PHP, and it is the priority for patching.
  2) bin/php-cgi  ->  cgi-fcgi (CGI / FastCGI gateway):
     Handles CGI or FastCGI requests; typical of legacy CGI deployments.
  3) bin/php  ->  cli (Command Line Interface):
     PHP run straight from a shell — cron jobs, background scripts.
Note: all three report the same version string (e.g. 8.2.28) but serve different
roles. Upgrading only one of them leaves the other two vulnerable.`

var (
	reVersion = regexp.MustCompile(`PHP\s+([\d.]+)`)
	reTriple  = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	reMarker  = regexp.MustCompile(`^[A-Z]+::`)
)

// ---------------------------------------------------------------------------
// 数据结构
// ---------------------------------------------------------------------------
type Cred struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type ScanConfig struct {
	Targets string `json:"targets"`
	Creds   []Cred `json:"creds"`
	Ports   []int  `json:"ports"`
	Threads int    `json:"threads"`
	Jump    string `json:"jump"`
	Script  string `json:"script"`
	Lang    string `json:"lang"` // zh / en，决定日志与报告语言
}

type Record struct {
	IP     string `json:"ip"`
	Status string `json:"status"`
	Port   string `json:"port"`
	User   string `json:"user"`
	PHP    string `json:"php"`
	Docker string `json:"docker"`
	Vhost  string `json:"vhost"`
	Pkg    string `json:"pkg"`
	Detail string `json:"detail"`
	Ver    string `json:"ver"`
}

type Event struct {
	Seq     int     `json:"seq"`
	Kind    string  `json:"kind"`
	Message string  `json:"message,omitempty"`
	Done    int     `json:"done,omitempty"`
	Total   int     `json:"total,omitempty"`
	Record  *Record `json:"record,omitempty"`
}

// ---------------------------------------------------------------------------
// 会话状态（单任务，互斥保护）
// ---------------------------------------------------------------------------
type Session struct {
	mu        sync.Mutex
	events    []Event
	records   []Record
	counts    map[string]int
	running   bool
	stopCh    chan struct{}
	seq       int
	exportDir string
	lang      string // 当前任务语言，供停止提示等使用
}

var sess = &Session{
	counts: map[string]int{"vuln": 0, "safe": 0, "unknown": 0, "error": 0, "stopped": 0},
}

func (s *Session) addEvent(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	e.Seq = s.seq
	s.events = append(s.events, e)
}

func (s *Session) log(format string, args ...interface{}) {
	s.addEvent(Event{Kind: "log", Message: fmt.Sprintf(format, args...)})
}

// ---------------------------------------------------------------------------
// 版本判定
// ---------------------------------------------------------------------------
func judge(ver string) string {
	m := reTriple.FindStringSubmatch(ver)
	if m == nil {
		return "unknown"
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	if major < 8 || (major == 8 && minor <= 1) {
		return "vuln" // 8.1 及更早 EOL，无官方补丁
	}
	if fix, ok := fixVer[minor]; ok {
		if patch >= fix {
			return "safe"
		}
		return "vuln"
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// 目标解析：单行 IP / CIDR / 区间(10.0.0.1-50 或 10.0.0.1-10.0.0.50)
// ---------------------------------------------------------------------------
func ip4ToUint(ip net.IP) uint32 {
	if len(ip) < 4 {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uintToIP4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func parseTargets(text string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.Contains(line, "/"):
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
			base := ipnet.IP.To4()
			if base == nil {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if ones == 0 {
				continue
			}
			size := uint64(1) << uint(bits-ones)
			if size > 1<<20 {
				continue // 过大网段跳过
			}
			start := ip4ToUint(base)
			lo, hi := start, start+uint32(size)-1
			if size > 2 { // 与 Python ipaddress.hosts() 一致：排除网络号与广播号
				lo, hi = start+1, start+uint32(size)-2
			}
			for i := lo; i <= hi; i++ {
				add(uintToIP4(i).String())
			}
		case strings.Contains(line, "-"):
			parts := strings.SplitN(line, "-", 2)
			a := net.ParseIP(strings.TrimSpace(parts[0]))
			if a == nil {
				continue
			}
			a = a.To4()
			if a == nil {
				continue
			}
			bs := strings.TrimSpace(parts[1])
			var b net.IP
			if strings.Contains(bs, ".") {
				b = net.ParseIP(bs).To4()
			} else {
				n, err := strconv.Atoi(bs)
				if err != nil || n < 0 || n > 255 {
					continue
				}
				b = net.IPv4(a[0], a[1], a[2], byte(n))
			}
			if b == nil {
				continue
			}
			s1, e1 := ip4ToUint(a), ip4ToUint(b)
			if e1 < s1 || e1-s1 > 10000 {
				continue
			}
			for i := s1; i <= e1; i++ {
				add(uintToIP4(i).String())
			}
		default:
			if ip := net.ParseIP(line); ip != nil {
				add(ip.String())
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return ip4ToUint(net.ParseIP(out[i]).To4()) < ip4ToUint(net.ParseIP(out[j]).To4())
	})
	return out
}

// ---------------------------------------------------------------------------
// 远端输出解析
// ---------------------------------------------------------------------------
func extractBlock(marker, text string) string {
	capture := false
	var buf []string
	for _, ln := range strings.Split(text, "\n") {
		if strings.HasPrefix(ln, marker) {
			capture = true
			if rest := strings.TrimSpace(strings.TrimPrefix(ln, marker)); rest != "" {
				buf = append(buf, rest)
			}
			continue
		}
		if reMarker.MatchString(ln) {
			capture = false
			continue
		}
		if capture {
			buf = append(buf, ln)
		}
	}
	return strings.Join(buf, "\n")
}

func parseRemote(out, ip string, port int, user string, lang string) Record {
	php := extractBlock("PHPBIN::", out)
	pkg := extractBlock("PKG::", out)
	vhost := extractBlock("VHOST::", out)
	docker := extractBlock("DOCKER::", out)

	worst := "safe"
	var detailOrder []string
	detailCount := map[string]int{}
	for _, line := range strings.Split(php+"\n"+docker, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := reVersion.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		st := judge(m[1])
		var key string
		switch st {
		case "vuln":
			worst = "vuln"
			key = T(lang, "d.vuln", m[1])
		case "unknown":
			if worst != "vuln" {
				worst = "unknown"
			}
			key = T(lang, "d.unknown", m[1])
		default:
			continue
		}
		if _, ok := detailCount[key]; !ok {
			detailOrder = append(detailOrder, key)
		}
		detailCount[key]++
	}
	// 同版本合并计数，例：中招:8.2.28 ×3
	details := make([]string, 0, len(detailOrder))
	for _, k := range detailOrder {
		if n := detailCount[k]; n > 1 {
			details = append(details, fmt.Sprintf("%s ×%d", k, n))
		} else {
			details = append(details, k)
		}
	}

	// 版本摘要按版本号聚合，例：PHP 8.2.28 ×3; PHP 8.0.26 ×3
	vers := map[string]int{}
	for _, line := range strings.Split(php+"\n"+docker, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := reVersion.FindStringSubmatch(line); m != nil {
			vers[m[1]]++
		}
	}
	keys := make([]string, 0, len(vers))
	for k := range vers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, T(lang, "ver.php", k, vers[k]))
	}
	ver := strings.Join(parts, T(lang, "ver.join"))
	if strings.TrimSpace(docker) != "" {
		ver += T(lang, "ver.dockJoin") + T(lang, "ver.docker") + ":" +
			strings.ReplaceAll(docker, "\n", T(lang, "ver.dockJoin"))
	}

	return Record{
		IP: ip, Port: strconv.Itoa(port), User: user, Status: worst,
		PHP: php, Docker: docker, Vhost: vhost, Pkg: pkg,
		Detail: strings.Join(details, ";"), Ver: ver,
	}
}

// ---------------------------------------------------------------------------
// SSH 扫描
// ---------------------------------------------------------------------------
func tcpProbe(addr string, t time.Duration) bool {
	c, err := net.DialTimeout("tcp", addr, t)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

type execResult struct {
	out []byte
	err error
}

func runRemote(client *ssh.Client, script string, timeout time.Duration, lang string) ([]byte, error) {
	s, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	s.Stdin = strings.NewReader(script)
	ch := make(chan execResult, 1)
	go func() {
		o, e := s.Output("bash -s")
		ch <- execResult{o, e}
	}()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-time.After(timeout):
		s.Signal(ssh.SIGKILL)
		return nil, fmt.Errorf("%s", T(lang, "d.timeout", timeout))
	}
}

func dialTarget(addr, user, pass string, timeout time.Duration, sock func() (net.Conn, error)) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	if sock != nil {
		conn, err := sock()
		if err != nil {
			return nil, err
		}
		ncc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
		if err != nil {
			return nil, err
		}
		return ssh.NewClient(ncc, chans, reqs), nil
	}
	return ssh.Dial("tcp", addr, cfg)
}

func scanOne(ip string, ports []int, creds []Cred, jump *ssh.Client, script string, timeout time.Duration, stopCh chan struct{}, lang string) Record {
	lastErr := T(lang, "d.unknownErr")
	for _, port := range ports {
		select {
		case <-stopCh:
			return Record{IP: ip, Status: "stopped", Detail: T(lang, "d.stopped")}
		default:
		}
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		if jump == nil && !tcpProbe(addr, 3*time.Second) {
			lastErr = T(lang, "d.portClosed", port)
			continue
		}
		for _, c := range creds {
			var client *ssh.Client
			var connected bool
			for attempt := 0; attempt < 2; attempt++ {
				select {
				case <-stopCh:
					return Record{IP: ip, Status: "stopped", Detail: T(lang, "d.stopped")}
				default:
				}
				var sockFn func() (net.Conn, error)
				if jump != nil {
					sockFn = func() (net.Conn, error) { return jump.Dial("tcp", addr) }
				}
				var err error
				client, err = dialTarget(addr, c.User, c.Pass, timeout, sockFn)
				if err == nil {
					connected = true
					break
				}
				lastErr = T(lang, "d.connFail", port, err)
			}
			if !connected {
				continue
			}
			out, err := runRemote(client, script, 120*time.Second, lang)
			client.Close()
			if err != nil {
				return Record{IP: ip, Status: "error", Detail: T(lang, "d.execFail", err)}
			}
			return parseRemote(string(out), ip, port, c.User, lang)
		}
	}
	return Record{IP: ip, Status: "error", Detail: lastErr}
}

// ---------------------------------------------------------------------------
// 扫描主流程
// ---------------------------------------------------------------------------
func (s *Session) run(cfg ScanConfig) {
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		s.addEvent(Event{Kind: "done"})
	}()

	lang := normLang(cfg.Lang)
	targets := parseTargets(cfg.Targets)
	if len(targets) == 0 {
		s.log("%s", T(lang, "log.noTarget"))
		return
	}
	script := strings.TrimSpace(cfg.Script)
	if script == "" {
		script = remoteScript
	}
	threads := cfg.Threads
	if threads < 1 {
		threads = 12
	}
	timeout := 6 * time.Second

	var jump *ssh.Client
	if strings.TrimSpace(cfg.Jump) != "" && len(cfg.Creds) > 0 {
		ju, jh, jp := parseJump(cfg.Jump)
		addr := net.JoinHostPort(jh, strconv.Itoa(jp))
		c, err := dialTarget(addr, ju, cfg.Creds[0].Pass, 8*time.Second, nil)
		if err != nil {
			s.log(T(lang, "log.jumpFail"), err)
		} else {
			jump = c
			s.log(T(lang, "log.jumpOK"), cfg.Jump)
			defer jump.Close()
		}
	}

	s.log(T(lang, "log.start"), len(targets), len(cfg.Creds))

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var counterMu sync.Mutex
	done := 0
	stop := s.stopCh

loop:
	for _, ip := range targets {
		select {
		case <-stop:
			break loop
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			rec := scanOne(ip, cfg.Ports, cfg.Creds, jump, script, timeout, stop, lang)

			s.mu.Lock()
			s.records = append(s.records, rec)
			s.counts[rec.Status] = s.counts[rec.Status] + 1
			s.mu.Unlock()

			s.addEvent(Event{Kind: "result", Record: &rec})

			var lines []string
			lines = append(lines, T(lang, "res.head", rec.IP, rec.Status, rec.Port, rec.User))
			if rec.PHP != "" {
				lines = append(lines, T(lang, "res.php", strings.ReplaceAll(rec.PHP, "\n", "  |  ")))
			}
			if rec.Docker != "" {
				lines = append(lines, T(lang, "res.docker", strings.ReplaceAll(rec.Docker, "\n", "  |  ")))
			}
			if rec.Vhost != "" {
				lines = append(lines, T(lang, "res.vhost", strings.ReplaceAll(rec.Vhost, "\n", "  |  ")))
			}
			if rec.Detail != "" {
				lines = append(lines, T(lang, "res.detail", rec.Detail))
			}
			s.addEvent(Event{Kind: "log", Message: strings.Join(lines, "\n")})

			counterMu.Lock()
			done++
			cur := done
			counterMu.Unlock()
			s.addEvent(Event{Kind: "progress", Done: cur, Total: len(targets)})
		}(ip)
	}
	wg.Wait()
	s.log("%s", T(lang, "log.done"))
}

func parseJump(s string) (user, host string, port int) {
	port = 22
	if i := strings.LastIndex(s, ":"); i > 0 {
		if p, err := strconv.Atoi(s[i+1:]); err == nil {
			port = p
			s = s[:i]
		}
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		user = s[:i]
		host = s[i+1:]
	} else {
		host = s
	}
	return
}

// ---------------------------------------------------------------------------
// 报告导出
// ---------------------------------------------------------------------------
func statusName(st, lang string) string {
	switch st {
	case "vuln", "safe", "unknown", "error", "stopped":
		return T(lang, "st."+st)
	}
	return st
}

func buildReports(records []Record, dir, lang string) (csvPath, htmlPath, mdPath string, counts map[string]int, err error) {
	counts = map[string]int{"vuln": 0, "safe": 0, "unknown": 0, "error": 0, "stopped": 0}
	for _, r := range records {
		counts[r.Status]++
	}
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	ts := time.Now().Format("20060102_150405")
	csvPath = filepath.Join(dir, "php_report_"+ts+".csv")
	htmlPath = filepath.Join(dir, "php_report_"+ts+".html")
	mdPath = filepath.Join(dir, "php_report_"+ts+".md")

	// CSV
	f, err := os.Create(csvPath)
	if err != nil {
		return
	}
	f.WriteString("\xef\xbb\xbf") // UTF-8 BOM，Excel 直接打开不乱码
	w := csv.NewWriter(f)
	w.Write([]string{
		T(lang, "col.ip"), T(lang, "col.port"), T(lang, "col.user"), T(lang, "col.status"),
		T(lang, "col.php"), T(lang, "col.docker"), T(lang, "col.vhost"), T(lang, "col.detail"),
	})
	for _, r := range records {
		w.Write([]string{r.IP, r.Port, r.User, statusName(r.Status, lang), r.PHP, r.Docker, r.Vhost, r.Detail})
	}
	w.Flush()
	f.Close()

	// HTML
	var rows strings.Builder
	for _, r := range records {
		rows.WriteString("<tr><td>" + esc(r.IP) + "</td><td>" + esc(r.Port) + "</td><td>" + esc(r.User) +
			"</td><td class=\"" + r.Status + "\">" + esc(statusName(r.Status, lang)) + "</td><td><pre>" + esc(r.PHP) +
			"</pre></td><td><pre>" + esc(r.Docker) + "</pre></td><td><pre>" + esc(r.Vhost) +
			"</pre></td><td>" + esc(r.Detail) + "</td></tr>")
	}
	htmlDoc := "<!doctype html><html lang=\"" + lang + "\"><head><meta charset=\"utf-8\"><title>" +
		esc(T(lang, "rep.title")) + " " + ts + "</title>" +
		"<style>body{font-family:system-ui,Arial;margin:24px;color:#222}" +
		".cards{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}" +
		".card{padding:12px 18px;border-radius:10px;color:#fff;min-width:110px}" +
		".card.vuln{background:#e74c3c}.card.safe{background:#27ae60}.card.unknown{background:#f39c12}.card.error{background:#7f8c8d}" +
		"table{border-collapse:collapse;width:100%;font-size:13px}" +
		"th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}" +
		"th{background:#f4f6f8}pre{margin:0;white-space:pre-wrap;font-size:12px}" +
		"td.vuln{color:#e74c3c;font-weight:700}td.safe{color:#27ae60;font-weight:700}td.unknown{color:#f39c12;font-weight:700}" +
		"footer{margin-top:20px;padding-top:12px;border-top:1px solid #e4e7ec;font-size:12px;color:#667085;line-height:1.7}" +
		"footer a{color:#2563eb;text-decoration:none}footer a:hover{text-decoration:underline}</style>" +
		"</head><body><h2>" + esc(T(lang, "rep.title")) + "</h2>" +
		"<p>" + esc(T(lang, "rep.genAt")) + "：" + ts + " ｜ " + esc(T(lang, "rep.cve")) +
		"：php2shell (CVE-2026-109618 / CVE-2026-109619)</p>" +
		"<div class=\"cards\">" +
		"<div class=\"card vuln\"><div>" + esc(T(lang, "st.vuln")) + "</div><b>" + strconv.Itoa(counts["vuln"]) + "</b></div>" +
		"<div class=\"card safe\"><div>" + esc(T(lang, "st.safe")) + "</div><b>" + strconv.Itoa(counts["safe"]) + "</b></div>" +
		"<div class=\"card unknown\"><div>" + esc(T(lang, "st.unknown")) + "</div><b>" + strconv.Itoa(counts["unknown"]) + "</b></div>" +
		"<div class=\"card error\"><div>" + esc(T(lang, "st.error")) + "</div><b>" + strconv.Itoa(counts["error"]) + "</b></div>" +
		"</div><table><thead><tr><th>" + esc(T(lang, "col.ip")) + "</th><th>" + esc(T(lang, "col.port")) +
		"</th><th>" + esc(T(lang, "col.user")) + "</th><th>" + esc(T(lang, "col.status")) +
		"</th><th>" + esc(T(lang, "col.php")) + "</th>" +
		"<th>" + esc(T(lang, "col.docker")) + "</th><th>" + esc(T(lang, "col.vhost")) +
		"</th><th>" + esc(T(lang, "col.detail")) + "</th></tr></thead><tbody>" + rows.String() +
		"</tbody></table><h3>" + esc(T(lang, "rep.sapi")) + "</h3><pre>" + esc(T(lang, "sapi")) + "</pre>" +
		"<footer>" + esc(T(lang, "rep.footer", appName, authorName())) +
		"<br><a href=\"mailto:" + esc(authorEmail) + "\">" + esc(authorEmail) + "</a>" +
		" ｜ <a href=\"" + esc(authorSite) + "\">" + esc(authorSite) + "</a>" +
		"</footer></body></html>"
	if err = os.WriteFile(htmlPath, []byte(htmlDoc), 0o644); err != nil {
		return
	}

	// Markdown
	head := []string{
		T(lang, "col.ip"), T(lang, "col.port"), T(lang, "col.user"), T(lang, "col.status"),
		T(lang, "col.php"), T(lang, "col.docker"), T(lang, "col.vhost"), T(lang, "col.detail"),
	}
	var md strings.Builder
	md.WriteString("# " + T(lang, "rep.title") + "\n\n")
	md.WriteString(T(lang, "md.generated", T(lang, "rep.genAt"), ts) + "\n")
	md.WriteString(T(lang, "md.cve", T(lang, "rep.cve")) + "\n")
	md.WriteString(T(lang, "md.summary",
		counts["vuln"], counts["safe"], counts["unknown"], counts["error"]) + "\n\n")
	md.WriteString("| " + strings.Join(head, " | ") + " |\n")
	md.WriteString("|" + strings.Repeat("------|", len(head)) + "\n")
	for _, r := range records {
		md.WriteString("| " + strings.Join([]string{
			mdEsc(r.IP), mdEsc(r.Port), mdEsc(r.User), mdEsc(statusName(r.Status, lang)),
			mdEsc(r.PHP), mdEsc(r.Docker), mdEsc(r.Vhost), mdEsc(r.Detail)}, " | ") + " |\n")
	}
	md.WriteString("\n## " + T(lang, "rep.sapi") + "\n\n" + T(lang, "sapi") + "\n")
	md.WriteString("\n---\n\n" + T(lang, "rep.footer", appName, authorName()) +
		" ｜ <" + authorEmail + "> ｜ " + authorSite + "\n")
	err = os.WriteFile(mdPath, []byte(md.String()), 0o644)
	return
}

func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}

func mdEsc(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

// ---------------------------------------------------------------------------
// HTTP 接口
// ---------------------------------------------------------------------------
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := uiFS.ReadFile("ui/index.html")
		if err != nil {
			http.Error(w, T(langEN, "api.uiMissing"), 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// 已有实例探测：用于「本机已在运行则直接复用」的判断
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"ok": true})
	})

	// 退出程序（供界面上的“退出程序”按钮调用，仅本机可访问）
	mux.HandleFunc("/api/quit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true})
		go func() {
			time.Sleep(200 * time.Millisecond)
			os.Exit(0)
		}()
	})

	mux.HandleFunc("/api/script", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"script": remoteScript})
	})

	// 作者与版本信息（界面“关于”页从此读取，保证与二进制内的署名一致）
	mux.HandleFunc("/api/about", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"app":     appName,
			"version": appVersion,
			"author":  authorNameEN,
			"authorC": authorNameZH,
			"email":   authorEmail,
			"site":    authorSite,
			"repo":    repoURL,
			"license": "MIT",
		})
	})

	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		sess.mu.Lock()
		running := sess.running
		sess.mu.Unlock()
		if running {
			writeJSON(w, map[string]interface{}{"ok": false, "msg": T(langEN, "api.busy")})
			return
		}
		var cfg ScanConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "msg": T(langEN, "api.badParam")})
			return
		}
		if len(cfg.Creds) == 0 {
			writeJSON(w, map[string]interface{}{"ok": false, "msg": T(langEN, "api.noCred")})
			return
		}
		if len(cfg.Ports) == 0 {
			cfg.Ports = []int{22, 2222, 36000}
		}
		sess.mu.Lock()
		sess.events = nil
		sess.records = nil
		sess.seq = 0
		sess.counts = map[string]int{"vuln": 0, "safe": 0, "unknown": 0, "error": 0, "stopped": 0}
		sess.running = true
		sess.stopCh = make(chan struct{})
		sess.lang = normLang(cfg.Lang)
		sess.mu.Unlock()
		go sess.run(cfg)
		writeJSON(w, map[string]interface{}{"ok": true})
	})

	mux.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		sess.mu.Lock()
		if sess.running && sess.stopCh != nil {
			close(sess.stopCh)
		}
		lang := normLang(sess.lang)
		sess.mu.Unlock()
		sess.log("%s", T(lang, "log.stop"))
		writeJSON(w, map[string]interface{}{"ok": true})
	})

	mux.HandleFunc("/api/poll", func(w http.ResponseWriter, r *http.Request) {
		since := 0
		if v := r.URL.Query().Get("since"); v != "" {
			since, _ = strconv.Atoi(v)
		}
		sess.mu.Lock()
		var evs []Event
		if since < len(sess.events) {
			evs = append(evs, sess.events[since:]...)
		}
		counts := map[string]int{}
		for k, v := range sess.counts {
			counts[k] = v
		}
		running := sess.running
		total := len(sess.events)
		sess.mu.Unlock()
		writeJSON(w, map[string]interface{}{
			"events": evs, "total": total, "running": running, "counts": counts,
		})
	})

	mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Dir  string `json:"dir"`
			Lang string `json:"lang"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		lang := normLang(req.Lang)
		dir := strings.TrimSpace(req.Dir)
		if dir == "" {
			dir = defaultReportDir()
		}
		sess.mu.Lock()
		recs := append([]Record{}, sess.records...)
		sess.mu.Unlock()
		if len(recs) == 0 {
			writeJSON(w, map[string]interface{}{"ok": false, "msg": T(lang, "api.noResult")})
			return
		}
		csvP, htmlP, mdP, counts, err := buildReports(recs, dir, lang)
		if err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "msg": err.Error()})
			return
		}
		sess.mu.Lock()
		sess.exportDir = dir
		sess.mu.Unlock()
		writeJSON(w, map[string]interface{}{
			"ok": true, "dir": dir, "counts": counts,
			"files": []map[string]string{
				{"label": T(lang, "file.md"), "name": filepath.Base(mdP)},
				{"label": T(lang, "file.csv"), "name": filepath.Base(csvP)},
				{"label": T(lang, "file.html"), "name": filepath.Base(htmlP)},
			},
		})
	})

	mux.HandleFunc("/api/download", func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Query().Get("name"))
		sess.mu.Lock()
		dir := sess.exportDir
		sess.mu.Unlock()
		if dir == "" || name == "" || name == "." {
			http.Error(w, "无文件", 404)
			return
		}
		p := filepath.Join(dir, name)
		w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
		http.ServeFile(w, r, p)
	})

	// 启动参数
	cliLang := detectLang()
	noBrowser := false
	port := defaultPort
	for _, a := range os.Args[1:] {
		switch {
		case a == "--no-browser" || a == "-n":
			noBrowser = true
		case strings.HasPrefix(a, "--port="):
			if p, e := strconv.Atoi(strings.TrimPrefix(a, "--port=")); e == nil && p > 0 {
				port = p
			}
		case a == "--version" || a == "-v":
			printVersion(cliLang)
			return
		case a == "--help" || a == "-h":
			printHelp(cliLang)
			return
		}
	}

	// 先尝试固定端口；若已被占用且是本程序的既有实例，直接复用（不再起第二个进程）
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		probe := fmt.Sprintf("http://127.0.0.1:%d/api/ping", port)
		if resp, e := http.Get(probe); e == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				url := fmt.Sprintf("http://127.0.0.1:%d/", port)
				printBanner(cliLang)
				fmt.Println(T(cliLang, "cli.started"))
				fmt.Println(fmt.Sprintf(T(cliLang, "cli.open"), url))
				if !noBrowser {
					openBrowser(url)
				}
				return
			}
		}
		// 端口被别的程序占用：改用系统随机端口
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println(fmt.Sprintf(T(cliLang, "cli.fail"), err))
			os.Exit(1)
		}
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/", ln.Addr().(*net.TCPAddr).Port)
	printBanner(cliLang)
	fmt.Println(T(cliLang, "cli.started"))
	fmt.Println(fmt.Sprintf(T(cliLang, "cli.open"), url))
	fmt.Println(T(cliLang, "cli.close"))
	if !noBrowser {
		openBrowser(url)
	}
	srv := &http.Server{Handler: mux}
	srv.Serve(ln)
}

// 默认监听端口（固定端口便于记忆与复用；被占用时自动回退随机端口）
const defaultPort = 8787

func defaultReportDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "php_scan_reports", time.Now().Format("20060102_150405"))
	}
	return filepath.Join(".", "php_scan_reports")
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

// ---------------------------------------------------------------------------
// 署名输出（版本 / 帮助 / 启动横幅）
// ---------------------------------------------------------------------------

// printBanner 输出“应用名 版本 + 作者署名”，启动时打印一次。
func printBanner(lang string) {
	fmt.Printf("%s %s\n", appName, appVersion)
	fmt.Println(fmt.Sprintf(T(lang, "cli.by"), authorLine()))
}

// printVersion 输出完整版本与作者信息（--version）。
func printVersion(lang string) {
	fmt.Printf("%s %s\n", appName, appVersion)
	fmt.Println(fmt.Sprintf(T(lang, "cli.by"), authorLine()))
	fmt.Println(T(lang, "about.contact") + ": " + authorEmail)
	fmt.Println(T(lang, "about.site") + ": " + authorSite)
	fmt.Println(T(lang, "about.license") + ": MIT")
}

// printHelp 输出命令行用法（--help）。
func printHelp(lang string) {
	name := filepath.Base(os.Args[0])
	fmt.Println(fmt.Sprintf(T(lang, "cli.usage"), name))
	fmt.Println(T(lang, "cli.optPort"))
	fmt.Println(T(lang, "cli.optNB"))
	fmt.Println(T(lang, "cli.optVer"))
	fmt.Println(T(lang, "cli.optHelp"))
	fmt.Println()
	printBanner(lang)
}
