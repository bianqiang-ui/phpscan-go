#!/usr/bin/env bash
# ============================================================
#  PHPScan — 一键发布到 GitHub（macOS / Linux）
#
#  用法：
#    1. 先在 https://github.com/new 创建一个**空仓库**
#       （Public；不要勾选 Add README / .gitignore / LICENSE）
#    2. 把下面 REPO 改成 你的用户名/仓库名
#    3. chmod +x publish.sh && ./publish.sh
# ============================================================
set -e

REPO="bianqiang-ui/phpscan-go"

echo "============================================================"
echo "  PHPScan 发布到 GitHub"
echo "  目标仓库: https://github.com/${REPO}"
echo "============================================================"
echo
echo "前提确认：你已在 https://github.com/new 创建好【空仓库】 ${REPO}"
echo "若还没创建，请现在去创建（不要勾选任何初始化选项），然后回车继续。"
read -r _

echo "[1/4] 设置远程地址..."
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/${REPO}.git"
git remote -v

echo "[2/4] 推送源码..."
git push -u origin main

echo "[3/4] 推送版本标签 v1.0.0..."
git push origin v1.0.0

echo "[4/4] 完成！"
echo
echo "  仓库地址   https://github.com/${REPO}"
echo "  构建进度   https://github.com/${REPO}/actions"
echo "  发布下载   https://github.com/${REPO}/releases"
echo
echo "GitHub Actions 约 2-3 分钟后会构建出四个平台的二进制并自动创建 Release。"
