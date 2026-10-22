package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// ---------------------------------------------------------------------------
// 轻量国际化：内置简体中文与英文两套文案，运行时按语言代码取值。
// 未命中词条自动回退英文，避免界面出现空的占位。
// ---------------------------------------------------------------------------

const (
	langZH = "zh"
	langEN = "en"
)

// messages[语言][词条]
var messages = map[string]map[string]string{
	langZH: {
		// 状态
		"st.vuln":    "中招",
		"st.safe":    "安全",
		"st.unknown": "需核实",
		"st.error":   "失败/不通",
		"st.stopped": "已停止",

		// 扫描流程日志
		"log.noTarget": "没有解析到任何有效 IP",
		"log.jumpFail": "跳板机连接失败: %v，改为直连",
		"log.jumpOK":   "跳板机已连接: %s",
		"log.start":    "开始扫描，目标 %d 台，凭据 %d 组。",
		"log.done":     "扫描结束。可点“导出报告”。",
		"log.stop":     "已请求停止，正在结束…",

		// 单台结果日志
		"res.head":   "[%s] 判定=%s 端口=%s 用户=%s",
		"res.php":    "  PHP版本: %s",
		"res.docker": "  容器PHP: %s",
		"res.vhost":  "  vhost: %s",
		"res.detail": "  备注: %s",

		// 明细片段
		"d.vuln":       "中招:%s",
		"d.unknown":    "核实:%s",
		"d.execFail":   "执行探测失败: %v",
		"d.connFail":   "连接失败 port=%d (%v)",
		"d.portClosed": "端口不通 port=%d（TCP 预探测 3 秒无响应，跳过）",
		"d.timeout":    "执行超时 %s",
		"d.unknownErr": "未知错误",
		"d.stopped":    "已停止",

		// 版本聚合
		"ver.php":      "PHP %s ×%d",
		"ver.docker":   "容器",
		"ver.join":     "; ",
		"ver.dockJoin": " | ",

		// 接口提示
		"api.busy":      "已有扫描在进行中",
		"api.badParam":  "参数解析失败",
		"api.noCred":    "请先添加至少一组凭据",
		"api.noResult":  "暂无结果可导出",
		"api.uiMissing": "界面资源缺失",
		"api.noFile":    "无文件",

		// 报告
		"rep.title":    "PHP 漏洞排查报告",
		"rep.genAt":    "生成时间",
		"rep.cve":      "漏洞",
		"rep.sapi":     "PHP 组件（运行模式）说明",
		"col.ip":       "IP",
		"col.port":     "端口",
		"col.user":     "用户名",
		"col.status":   "判定",
		"col.php":      "PHP版本明细",
		"col.docker":   "容器PHP",
		"col.vhost":    "vhost所用PHP",
		"col.detail":   "备注",
		"file.md":      "Markdown 报告",
		"file.csv":     "CSV 表格",
		"file.html":    "HTML 报告",
		"md.summary":   "- 汇总：中招 **%d** / 安全 **%d** / 需核实 **%d** / 失败 **%d**",
		"md.generated": "- %s：%s",
		"md.cve":       "- %s：php2shell（CVE-2026-109618 / CVE-2026-109619）",

		// SAPI 说明
		"sapi": sapiGuideZH,

		// 报告页脚署名
		"rep.footer": "本报告由 %s 生成 · %s",

		// 关于本工具
		"about.title":     "关于本工具",
		"about.desc":      "通过 SSH 批量清点服务器上的 PHP 版本，内置 php2shell（CVE-2026-109618 / CVE-2026-109619）检测规则。",
		"about.defensive": "仅供授权环境下的自查与补丁，属防御性排查。",
		"about.author":    "作者",
		"about.contact":   "联系",
		"about.site":      "网站",
		"about.repo":      "源码仓库",
		"about.version":   "版本",
		"about.license":   "许可协议",

		// 命令行
		"cli.started": "PHP 漏洞批量排查工具已启动",
		"cli.open":    "请在浏览器打开: %s",
		"cli.close":   "（关闭此窗口即退出程序）",
		"cli.fail":    "无法启动本地服务: %v",
		"cli.by":      "作者: %s",
		"cli.usage":   "用法: %s [选项]",
		"cli.optPort": "  --port=8787     指定本地服务端口（默认 8787）",
		"cli.optNB":   "  --no-browser    启动但不自动打开浏览器",
		"cli.optVer":  "  --version       显示版本与作者信息",
		"cli.optHelp": "  --help          显示此帮助",
	},
	langEN: {
		// Status
		"st.vuln":    "Vulnerable",
		"st.safe":    "Safe",
		"st.unknown": "Review",
		"st.error":   "Failed",
		"st.stopped": "Stopped",

		// Scan flow log
		"log.noTarget": "No valid IP address could be parsed",
		"log.jumpFail": "Bastion host unreachable: %v — falling back to direct connection",
		"log.jumpOK":   "Bastion host connected: %s",
		"log.start":    "Scan started — %d target(s), %d credential set(s).",
		"log.done":     "Scan finished. You may now export the report.",
		"log.stop":     "Stop requested, shutting down…",

		// Per-host result log
		"res.head":   "[%s] status=%s port=%s user=%s",
		"res.php":    "  PHP: %s",
		"res.docker": "  Container PHP: %s",
		"res.vhost":  "  vhost: %s",
		"res.detail": "  Note: %s",

		// Detail fragments
		"d.vuln":       "vulnerable:%s",
		"d.unknown":    "review:%s",
		"d.execFail":   "probe failed: %v",
		"d.connFail":   "connection failed port=%d (%v)",
		"d.portClosed": "port closed port=%d (no response to the 3s TCP pre-check, skipped)",
		"d.timeout":    "execution timed out after %s",
		"d.unknownErr": "unknown error",
		"d.stopped":    "stopped",

		// Version aggregation
		"ver.php":      "PHP %s ×%d",
		"ver.docker":   "container",
		"ver.join":     "; ",
		"ver.dockJoin": " | ",

		// API messages
		"api.busy":      "A scan is already running",
		"api.badParam":  "Invalid request parameters",
		"api.noCred":    "Add at least one credential set first",
		"api.noResult":  "No results to export yet",
		"api.uiMissing": "UI asset missing",
		"api.noFile":    "File not found",

		// Report
		"rep.title":    "PHP Vulnerability Scan Report",
		"rep.genAt":    "Generated at",
		"rep.cve":      "Advisory",
		"rep.sapi":     "PHP components (SAPI modes) explained",
		"col.ip":       "IP",
		"col.port":     "Port",
		"col.user":     "User",
		"col.status":   "Status",
		"col.php":      "PHP versions found",
		"col.docker":   "Container PHP",
		"col.vhost":    "PHP used by vhosts",
		"col.detail":   "Notes",
		"file.md":      "Markdown report",
		"file.csv":     "CSV spreadsheet",
		"file.html":    "HTML report",
		"md.summary":   "- Summary: **%d** vulnerable / **%d** safe / **%d** need review / **%d** failed",
		"md.generated": "- %s: %s",
		"md.cve":       "- %s: php2shell (CVE-2026-109618 / CVE-2026-109619)",

		// SAPI guide
		"sapi": sapiGuideEN,

		// Report footer credit
		"rep.footer": "Report generated by %s · %s",

		// About
		"about.title":     "About",
		"about.desc":      "Batch SSH inventory of PHP versions across servers, with a built-in php2shell (CVE-2026-109618 / CVE-2026-109619) rule.",
		"about.defensive": "For authorised self-assessment and patching only — a defensive audit tool.",
		"about.author":    "Author",
		"about.contact":   "Contact",
		"about.site":      "Website",
		"about.repo":      "Repository",
		"about.version":   "Version",
		"about.license":   "License",

		// CLI
		"cli.started": "PHP vulnerability scanner started",
		"cli.open":    "Open in your browser: %s",
		"cli.close":   "(Closing this window stops the program)",
		"cli.fail":    "Cannot start local server: %v",
		"cli.by":      "Author: %s",
		"cli.usage":   "Usage: %s [options]",
		"cli.optPort": "  --port=8787     Local server port (default 8787)",
		"cli.optNB":   "  --no-browser    Start without opening a browser",
		"cli.optVer":  "  --version       Show version and author",
		"cli.optHelp": "  --help          Show this help",
	},
}

// T 返回指定语言的文案；带参数时按 fmt.Sprintf 处理。
func T(l string, key string, args ...interface{}) string {
	m, ok := messages[l]
	if !ok {
		m = messages[langEN]
	}
	s, ok := m[key]
	if !ok {
		if s2, ok2 := messages[langEN][key]; ok2 {
			s = s2
		} else {
			s = key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// normLang 把任意语言标识规整为 zh / en（默认 en）。
func normLang(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(s, "zh"), strings.HasPrefix(s, "cn"):
		return langZH
	default:
		return langEN
	}
}

// detectLang 猜测命令行输出语言，用于 --version / --help 与启动横幅。
//
// 优先级：PHPSCAN_LANG（显式指定）> 系统语言环境变量 > 默认简体中文。
// 注意：Windows 本身没有 LANG / LC_ALL 概念，Git Bash、MSYS 等终端会自行注入
// （常见为 en_US.UTF-8），若直接采信会让中文用户看到英文提示，故在 Windows 上
// 只认 PHPSCAN_LANG，其余情况回落到简体中文。
func detectLang() string {
	if v := os.Getenv("PHPSCAN_LANG"); strings.TrimSpace(v) != "" {
		return normLang(v)
	}
	if runtime.GOOS == "windows" {
		return langZH
	}
	for _, k := range []string{"LANG", "LC_ALL"} {
		if v := os.Getenv(k); strings.TrimSpace(v) != "" {
			return normLang(v)
		}
	}
	return langZH
}
