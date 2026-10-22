# 发布到 GitHub / Publishing to GitHub

本仓库已初始化完毕：源码已提交、`v1.0.0` 标签已打好。下面只需把代码推上去。

The repo is already initialised locally: source committed, `v1.0.0` tag created.
All that remains is pushing it up.

当前提交 / Current commit:

```
2a1688e (main, tag: v1.0.0) Add PHPScan: bulk SSH PHP inventory scanner (php2shell)
Author: Bian Chengxu <bianqiang@gmail.com>
```

---

## 方案 A：自动发布（推荐 / Recommended）

GitHub Actions 会在云端构建四个平台的二进制，并自动创建 Release —— **公开仓库免费**，
你不用在本地上传任何二进制文件。

The workflow builds all four binaries **in the cloud** and publishes the Release
automatically. Free for public repos, and you upload nothing by hand.

### 步骤 / Steps

1. **创建空仓库** — 打开 <https://github.com/new>
   - Repository name: `phpscan-go`
   - 选 **Public**（公开仓库 Actions 免费 / public = free Actions minutes）
   - **不要**勾选 "Add a README file" / "Add .gitignore" / "Choose a license"
     （仓库里已经有了，勾了会导致推送冲突）

2. **运行发布脚本**（Windows 双击 `publish.bat`，macOS/Linux 执行 `./publish.sh`）

   或者手动执行 / or run manually:

   ```bash
   git remote add origin https://github.com/<你的用户名>/phpscan-go.git
   git push -u origin main
   git push origin v1.0.0
   ```

3. **授权** — 首次推送会弹出浏览器登录窗口（Git Credential Manager），
   用你已登录的 GitHub 账号点 **Authorize** 即可，只需一次。

4. **等待构建** — 打开 `https://github.com/<用户名>/phpscan-go/actions`，
   约 2–3 分钟后 `release` 工作流变绿，Release 页面就会出现四个文件：

   | 文件 | 平台 |
   |---|---|
   | `phpscan-windows-amd64.exe` | Windows 64 位 |
   | `phpscan-darwin-arm64` | macOS Apple 芯片（M 系列） |
   | `phpscan-darwin-amd64` | macOS Intel |
   | `phpscan-linux-amd64` | Linux 64 位 |

   每个文件都附带 `.sha256` 校验和。

---

## 方案 B：手动上传本地已编译的二进制

如果你不想等 Actions，或云端构建失败，可以把 `dist/` 里**已经编译好**的四个文件
直接传到 Release。

If you'd rather not wait (or CI fails), upload the four binaries already built in `dist/`.

### B1. 用 GitHub 网页（最简单）

1. 先按方案 A 的第 1、3 步把**源码**推上去（只需 `git push -u origin main`，不用推 tag）
2. 打开 `https://github.com/<用户名>/phpscan-go/releases/new`
3. Tag version 填 `v1.0.0`，标题填 `PHPScan v1.0.0`
4. 把 `dist/` 下这 8 个文件**拖进**页面底部的上传区：
   `phpscan-windows-amd64.exe`、`phpscan-darwin-arm64`、`phpscan-darwin-amd64`、
   `phpscan-linux-amd64`，以及各自的 `.sha256`
5. 点 **Publish release**

### B2. 用 gh 命令行（需先安装 <https://cli.github.com>）

```bash
gh auth login                    # 只需一次
gh release create v1.0.0 \
  dist/phpscan-windows-amd64.exe \
  dist/phpscan-darwin-arm64 \
  dist/phpscan-darwin-amd64 \
  dist/phpscan-linux-amd64 \
  dist/*.sha256 \
  --title "PHPScan v1.0.0" \
  --notes "首个公开版本：批量 SSH 清点服务器 PHP 版本，内置 php2shell 检测规则。中英双语界面与报告。"
```

> 注意：若你同时推了 `v1.0.0` 标签，Actions 也会创建同名 Release。
> 两种方案**选一个**即可，避免文件重复。

---

## 发布后检查清单 / Post-publish checklist

- [ ] Releases 页面能看到四个平台的二进制
- [ ] README 首页渲染正常（中英双语都有）
- [ ] Actions 的 release 工作流是绿色的
- [ ] 下载 Windows 版双击能打开浏览器界面（无黑框）
- [ ] 「关于」页显示作者 Bian Chengxu（边承旭）与邮箱、网站

## 常见问题 / Troubleshooting

**推送被拒 (403)**：浏览器授权没完成，或仓库名/用户名写错。重新 `git push` 再授权一次。

**推送被拒 (non-fast-forward)**：你在网页创建仓库时勾选了 README/LICENSE。
解决：先 `git pull --rebase origin main` 再推，或者删掉仓库重建一个纯空的。

**Actions 构建失败**：`go.mod` 声明的 Go 版本高于 workflow 里 `setup-go` 的版本。
本仓库已把 workflow 设为 `go-version: "stable"`，一般不会出现。

**以后发新版本**：改完代码后执行
```bash
git add -A && git commit -m "描述"
git tag -a v1.0.1 -m "说明"
git push origin main && git push origin v1.0.1
```
Actions 会自动发布新版本。
