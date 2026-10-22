@echo off
rem Build all release targets on Windows. Pure Go, no cgo, no external toolchain.

set NAME=phpscan
set OUT=dist
set LDFLAGS=-s -w

if not exist "%OUT%" mkdir "%OUT%"

echo == linux/amd64 ==
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0
go build -ldflags "%LDFLAGS%" -o "%OUT%\%NAME%-linux-amd64" .
if errorlevel 1 goto fail

echo == darwin/arm64 ==
set GOOS=darwin
set GOARCH=arm64
go build -ldflags "%LDFLAGS%" -o "%OUT%\%NAME%-darwin-arm64" .
if errorlevel 1 goto fail

echo == darwin/amd64 ==
set GOOS=darwin
set GOARCH=amd64
go build -ldflags "%LDFLAGS%" -o "%OUT%\%NAME%-darwin-amd64" .
if errorlevel 1 goto fail

echo == windows/amd64 (GUI subsystem: no console window) ==
set GOOS=windows
set GOARCH=amd64
go build -ldflags "%LDFLAGS% -H windowsgui" -o "%OUT%\%NAME%-windows-amd64.exe" .
if errorlevel 1 goto fail

echo.
dir "%OUT%"
echo BUILD OK
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
