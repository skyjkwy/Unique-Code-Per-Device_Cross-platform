@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "BUILD=%ROOT%\build"

set "PAUSE_ON_EXIT="
if "%~1"=="" set "PAUSE_ON_EXIT=pause"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] Visual Studio Installer not found.
    if defined PAUSE_ON_EXIT !PAUSE_ON_EXIT!
    exit /b 1
)

for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo [ERROR] MSVC toolchain not found.
    if defined PAUSE_ON_EXIT !PAUSE_ON_EXIT!
    exit /b 1
)

call "%VSPATH%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 (
    echo [ERROR] Failed to initialize the MSVC environment.
    if defined PAUSE_ON_EXIT !PAUSE_ON_EXIT!
    exit /b 1
)

set "CMAKE_BIN=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set "NINJA_BIN=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if exist "%NINJA_BIN%" set "PATH=%NINJA_BIN%;%PATH%"

set "CMAKE=cmake"
if exist "%CMAKE_BIN%\cmake.exe" set "CMAKE=%CMAKE_BIN%\cmake.exe"

echo [INFO] Configuring...
"%CMAKE%" -S "%ROOT%" -B "%BUILD%" -G Ninja -DCMAKE_BUILD_TYPE=Release %*
if errorlevel 1 (
    if defined PAUSE_ON_EXIT !PAUSE_ON_EXIT!
    exit /b 1
)

echo [INFO] Building...
"%CMAKE%" --build "%BUILD%" --config Release
if errorlevel 1 (
    echo [ERROR] Build failed.
    if defined PAUSE_ON_EXIT !PAUSE_ON_EXIT!
    exit /b 1
)

echo [OK] Build finished. Output: %BUILD%
if defined PAUSE_ON_EXIT !PAUSE_ON_EXIT!
