@echo off
chcp 65001 >nul
setlocal

REM ============================================================
REM  PHPScan — 一键发布到 GitHub（Windows）
REM
REM  用法：
REM    1. 先在 https://github.com/new 创建一个**空仓库**
REM       （Public；不要勾选 Add README / .gitignore / LICENSE）
REM    2. 把下面 REPO 改成 你的用户名/仓库名
REM    3. 双击运行本脚本，按提示在浏览器中完成一次授权
REM ============================================================

set REPO=bianqiang-ui/phpscan-go

echo.
echo ============================================================
echo   PHPScan 发布到 GitHub
echo   目标仓库: https://github.com/%REPO%
echo ============================================================
echo.
echo 前提确认：你已在 https://github.com/new 创建好【空仓库】 %REPO%
echo 若还没创建，请现在去创建（不要勾选任何初始化选项），然后回车继续。
pause

echo.
echo [1/4] 设置远程地址...
git remote remove origin 2>nul
git remote add origin https://github.com/%REPO%.git
git remote -v

echo.
echo [2/4] 推送源码（若弹出登录窗口，用浏览器授权即可）...
git push -u origin main
if errorlevel 1 goto :fail

echo.
echo [3/4] 推送版本标签 v1.0.0（GitHub Actions 会自动构建并发布四个平台二进制）...
git push origin v1.0.0
if errorlevel 1 goto :fail

echo.
echo [4/4] 完成！
echo.
echo   仓库地址     https://github.com/%REPO%
echo   构建进度     https://github.com/%REPO%/actions
echo   发布下载     https://github.com/%REPO%/releases
echo.
echo GitHub Actions 约 2-3 分钟后会构建出四个平台的二进制并自动创建 Release。
echo.
pause
goto :eof

:fail
echo.
echo 推送失败。常见原因：
echo   1. 仓库还没在网页上创建 —— 先去 https://github.com/new 创建空仓库
echo   2. 仓库名写错了 —— 修改本脚本第 15 行的 REPO 变量
echo   3. 授权被拒 —— 重新运行，在弹出的浏览器窗口点 Authorize
echo.
echo 若想手动上传本地已编译好的四个二进制（不等 Actions），见 PUBLISH.md 的“方案 B”。
echo.
pause
