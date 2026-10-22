#!/usr/bin/env bash
# Build all release targets. Pure Go, no cgo — cross-compiles from any platform.
set -euo pipefail

NAME=phpscan
OUT=${OUT:-dist}
LDFLAGS="-s -w"

mkdir -p "$OUT"

echo "== linux/amd64   =="
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$OUT/$NAME-linux-amd64" .

echo "== darwin/arm64  =="
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$OUT/$NAME-darwin-arm64" .

echo "== darwin/amd64  =="
GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$OUT/$NAME-darwin-amd64" .

echo "== windows/amd64 (GUI subsystem: no console window) =="
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS -H windowsgui" -o "$OUT/$NAME-windows-amd64.exe" .

echo
ls -lh "$OUT"
