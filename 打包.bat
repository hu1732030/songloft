@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0"

REM ========== 0. Flutter 路径（按本机修改）==========
set "FLUTTER=flutter"
if exist "D:\software\flutter\bin\flutter.bat" set "FLUTTER=D:\software\flutter\bin\flutter.bat"

REM 绝对路径输出，避免 impellerc 写 ..\ 相对路径失败
set "WEB_OUT=%~dp0clients\player-build\web-embedded"

REM ========== 1. 前端 web-embedded ==========
echo [1/3] Flutter web-embedded ...
if exist "%WEB_OUT%" (
  echo 清理旧产物: %WEB_OUT%
  rmdir /s /q "%WEB_OUT%"
)
mkdir "%WEB_OUT%" 2>nul

pushd clients\player
call "%FLUTTER%" build web --release --no-web-resources-cdn --no-wasm-dry-run --dart-define=DEPLOY_MODE=embedded --output="%WEB_OUT%"
if errorlevel 1 (
  echo Flutter 构建失败
  popd
  pause
  exit /b 1
)
popd

REM 部署模式标记（与 build-frontend.sh 一致）
> "%WEB_OUT%\deploy-mode.js" echo var _deployMode = 'embedded';

REM ========== 2. Go Linux arm64 ==========
echo [2/3] Go linux/arm64 ...
set CGO_ENABLED=0
set GOOS=linux
set GOARCH=arm64
go build -ldflags="-s -w" -o songloft-linux-arm64 .
if errorlevel 1 (
  echo Go linux/arm64 失败
  pause
  exit /b 1
)

REM ========== 3. Go Windows amd64 ==========
echo [3/3] Go windows/amd64 ...
set GOOS=windows
set GOARCH=amd64
set GOAMD64=v1
go build -ldflags="-s -w" -o songloft.exe .
if errorlevel 1 (
  echo Go windows/amd64 失败
  pause
  exit /b 1
)

echo.
echo 完成: songloft-linux-arm64 / songloft.exe（已嵌入 web）
pause
