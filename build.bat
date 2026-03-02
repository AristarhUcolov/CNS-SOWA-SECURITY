@echo off
echo ============================================
echo  Building S.O.W.A Security Software
echo  by C.N.S (Clear Net Sky)
echo ============================================
echo.

:: Set variables
set APP_NAME=sowa-security
set VERSION=1.0.0
set BUILD_DIR=build
set LDFLAGS=-s -w -X main.appVersion=%VERSION%

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

:: Build for Windows AMD64
echo [BUILD] Compiling for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o %BUILD_DIR%\%APP_NAME%.exe .\cmd\sowa\

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

:: Copy web files
echo [BUILD] Copying web files...
if not exist %BUILD_DIR%\web mkdir %BUILD_DIR%\web
xcopy /E /I /Y web %BUILD_DIR%\web > nul

:: Create data directories
echo [BUILD] Creating data directories...
if not exist %BUILD_DIR%\data\blacklist mkdir %BUILD_DIR%\data\blacklist
if not exist %BUILD_DIR%\data\whitelist mkdir %BUILD_DIR%\data\whitelist
if not exist %BUILD_DIR%\data\config mkdir %BUILD_DIR%\data\config

echo.
echo ============================================
echo  Build complete!
echo  Output: %BUILD_DIR%\%APP_NAME%.exe
echo ============================================
echo.
echo To run: cd %BUILD_DIR% ^& %APP_NAME%.exe
echo Web UI: http://localhost:8080
echo.
pause
