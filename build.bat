@echo off

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "BUILD=%ROOT%\build"

if /i "%~1"=="clean" (
    if exist "%BUILD%" (
        echo [INFO] Cleaning %BUILD% ...
        powershell -NoProfile -Command "Remove-Item -Recurse -Force '%BUILD%'"
        echo [OK] Cleaned.
    ) else (
        echo [OK] Nothing to clean.
    )
    exit /b 0
)

if /i "%~1"=="-h" (
    echo Usage:
    echo   build.bat                  Build with GUI auto-detection, pause on exit.
    echo   build.bat clean            Remove the entire build directory.
    echo   build.bat [cmake-args...]  Pass extra args to CMake, e.g. -DBUILD_GUI=OFF.
    exit /b 0
)

set "PAUSE_ON_EXIT="
if "%~1"=="" set "PAUSE_ON_EXIT=pause"

rem --- MSVC toolchain ---
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] Visual Studio Installer not found.
    if defined PAUSE_ON_EXIT %PAUSE_ON_EXIT%
    exit /b 1
)

for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo [ERROR] MSVC toolchain not found.
    if defined PAUSE_ON_EXIT %PAUSE_ON_EXIT%
    exit /b 1
)

call "%VSPATH%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 (
    echo [ERROR] Failed to initialize the MSVC environment.
    if defined PAUSE_ON_EXIT %PAUSE_ON_EXIT%
    exit /b 1
)

set "CMAKE_BIN=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set "NINJA_BIN=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if exist "%NINJA_BIN%" set "PATH=%NINJA_BIN%;%PATH%"

set "CMAKE=cmake"
if exist "%CMAKE_BIN%\cmake.exe" set "CMAKE=%CMAKE_BIN%\cmake.exe"

rem --- Auto-detect Qt prefix (skip if user passed -DCMAKE_PREFIX_PATH=) ---
set "CMAKE_QT="
set "TMP_QT_PROBE=%TEMP%\build_qt_probe.txt"
del /q "%TMP_QT_PROBE%" 2>nul

set "HAS_QT_PREFIX=0"
for %%a in (%*) do (
    echo %%a | findstr /b /c:"-DCMAKE_PREFIX_PATH=" >nul 2>nul && set "HAS_QT_PREFIX=1"
)

if "%HAS_QT_PREFIX%"=="0" (
    powershell -NoProfile -Command ^
      "$found=$null;" ^
      "foreach($c in @('C:\Qt','C:\Program Files\Qt')){" ^
      "  if(Test-Path $c){" ^
      "    $cfg=Get-ChildItem $c -Recurse -Filter 'Qt6Config.cmake' -ErrorAction SilentlyContinue | Select-Object -First 1;" ^
      "    if($cfg){ $found=Split-Path (Split-Path $cfg.FullName -Parent); break }" ^
      "  }" ^
      "}" ^
      "if($found){ Set-Content -Path '%TMP_QT_PROBE%' -Value $found }" 2>nul

    if exist "%TMP_QT_PROBE%" (
        set /p QT_PREFIX=<"%TMP_QT_PROBE%"
        del /q "%TMP_QT_PROBE%"
        set "CMAKE_QT=-DCMAKE_PREFIX_PATH=%QT_PREFIX%"
        echo [INFO] Detected Qt at: %QT_PREFIX%
    ) else (
        echo [INFO] Qt 6 not auto-detected. GUI tools will be skipped. Pass -DCMAKE_PREFIX_PATH to enable.
    )
)

echo [INFO] Configuring...
"%CMAKE%" -S "%ROOT%" -B "%BUILD%" -G Ninja -DCMAKE_BUILD_TYPE=Release %CMAKE_QT% %*
if errorlevel 1 (
    if defined PAUSE_ON_EXIT %PAUSE_ON_EXIT%
    exit /b 1
)

echo [INFO] Building...
"%CMAKE%" --build "%BUILD%" --config Release
if errorlevel 1 (
    echo [ERROR] Build failed.
    if defined PAUSE_ON_EXIT %PAUSE_ON_EXIT%
    exit /b 1
)

rem --- Clean intermediate files ---
echo [INFO] Removing intermediate files...

for %%f in (license_stage1.dll license_stage1.lib license_stage1.exp hashgen.exe embed_key.exe final_hash.h license.exp license.lib) do (
    if exist "%BUILD%\%%f" del /q "%BUILD%\%%f"
    for /r "%BUILD%" %%a in (%%f) do @if exist "%%a" del /q "%%a"
)
for %%d in (generated stage1 lib) do (
    if exist "%BUILD%\%%d" rmdir /s /q "%BUILD%\%%d"
    for /r "%BUILD%" %%a in (%%d) do @if exist "%%a" rmdir /s /q "%%a"
)
for %%f in ("%BUILD%\*.pdb") do @if exist "%%f" del /q "%%f"

findstr /b /c:"BUILD_TESTS:BOOL=OFF" "%BUILD%\CMakeCache.txt" >nul 2>&1
if not errorlevel 1 (
    for /r "%BUILD%" %%a in (core_roundtrip.exe) do @if exist "%%a" del /q "%%a"
)

rem --- Deploy Qt runtime if GUI built ---
if exist "%BUILD%\bin\license_system.exe" (
    echo [INFO] Deploying Qt runtime to bin\ ...
    powershell -NoProfile -Command ^
      "$cache='%BUILD%\CMakeCache.txt';" ^
      "$bin='%BUILD%\bin';" ^
      "$qtPath=$null;" ^
      "if(Test-Path $cache){" ^
      "  foreach($line in Get-Content $cache){" ^
      "    if($line -match '^Qt6Core_DIR:PATH=(.+)$'){" ^
      "      $p=$Matches[1].Replace('/','\');" ^
      "      $qtPath=Split-Path (Split-Path (Split-Path $p) -Parent) -Parent;" ^
      "      break;" ^
      "    }" ^
      "  }" ^
      "}" ^
      "if(-not $qtPath -and (Test-Path 'C:\Qt')){" ^
      "  $qtPath=Get-ChildItem 'C:\Qt' -Directory | Sort-Object Name -Descending | Select-Object -First 1 | ForEach-Object { Get-ChildItem $_.FullName -Directory | Sort-Object Name -Descending | Select-Object -First 1 } | ForEach-Object { $_.FullName };" ^
      "}" ^
      "if($qtPath){" ^
      "  $dep=Join-Path $qtPath 'bin\windeployqt.exe';" ^
      "  if(Test-Path $dep){ & $dep --release --no-translations --no-system-d3d-compiler --no-opengl-sw (Join-Path $bin 'license_system.exe') }" ^
      "}"
)

echo [OK] Build finished. Output: %BUILD%
if defined PAUSE_ON_EXIT %PAUSE_ON_EXIT%
