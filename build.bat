@echo off
setlocal enabledelayedexpansion

echo ==============================================
echo       License System - Build Script
echo ==============================================
echo.

set "VS_PATH="
set "VS_TEMP=%TEMP%\vsdetect.txt"

echo Detecting Visual Studio...

if exist "C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Insiders"
if not defined VS_PATH if exist "C:\Program Files\Microsoft Visual Studio\18\Professional\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Professional"
if not defined VS_PATH if exist "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Community"
if not defined VS_PATH if exist "C:\Program Files\Microsoft Visual Studio\18\Enterprise\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
if not defined VS_PATH if exist "C:\Program Files\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\BuildTools"
if not defined VS_PATH if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional"
if not defined VS_PATH if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community"
if not defined VS_PATH if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
if not defined VS_PATH if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
if not defined VS_PATH if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools"
if not defined VS_PATH if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional"
if not defined VS_PATH if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat" set "VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community"

if defined VS_PATH (
    echo Found Visual Studio at: !VS_PATH!
    goto :VS_FOUND
)

echo Checking with vswhere...

if exist "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" (
    "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath > "%VS_TEMP%" 2>nul
    for /f "usebackq delims=" %%a in ("%VS_TEMP%") do set "VS_PATH=%%a"
    del "%VS_TEMP%" >nul 2>&1
    if defined VS_PATH (
        echo Found via vswhere: !VS_PATH!
        goto :VS_FOUND
    )
)

echo.
echo ERROR: Visual Studio not found.
echo Please install Visual Studio with C++ tools.
echo Download: https://visualstudio.microsoft.com/downloads/
echo.
pause
exit /b 1

:VS_FOUND

if not exist "!VS_PATH!\Common7\Tools\VsDevCmd.bat" (
    echo.
    echo ERROR: VsDevCmd.bat not found at !VS_PATH!
    echo.
    pause
    exit /b 1
)

echo Loading VS environment...
call "!VS_PATH!\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul 2>&1

where cl >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: cl.exe not found after loading VS.
    echo Please install C++ tools in Visual Studio.
    echo.
    pause
    exit /b 1
)

echo cl.exe is ready.
echo.
echo ==============================================
echo       License System - Build Script
echo ==============================================

set "OUTPUT_DIR=bin"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

del *.obj *.res >nul 2>&1
del "%OUTPUT_DIR%\*.dll" "%OUTPUT_DIR%\*.lib" "%OUTPUT_DIR%\*.exp" "%OUTPUT_DIR%\*.exe" >nul 2>&1

set "SIGN_CFG=%~dp0sign\sign.config"
if not exist "%~dp0sign" mkdir "%~dp0sign"
set "PFX_FILE="
set "PFX_PASS="
set "SIGN_OK="
if not exist "%SIGN_CFG%" goto :sign_pick
echo Using saved certificate settings from sign\sign.config...
for /f "usebackq eol=@ tokens=* delims=" %%L in ("%SIGN_CFG%") do %%L

:sign_pick
if defined PFX_FILE if exist "%PFX_FILE%" goto :sign_tool
if defined PFX_FILE echo Saved certificate no longer exists: %PFX_FILE%
echo.
echo ==============================================
echo [Signing] Select certificate...
echo ==============================================
echo Please select PFX certificate file in the dialog...
for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Title = 'Select PFX certificate'; $d.Filter = 'PFX files (*.pfx)|*.pfx|All files (*.*)|*.*'; $d.InitialDirectory = '%~dp0sign'; if ($d.ShowDialog() -eq 'OK') { Write-Output $d.FileName }"`) do set "PFX_FILE=%%P"
if not defined PFX_FILE (
    echo Skipped: no certificate selected, outputs will NOT be signed.
    goto :sign_setup_done
)
set /p "PFX_PASS=Enter PFX password (press Enter if no password): "
setlocal disabledelayedexpansion
(
echo @echo off
echo set "PFX_FILE=%PFX_FILE%"
echo set "PFX_PASS=%PFX_PASS%"
) > "%SIGN_CFG%"
endlocal
echo Certificate saved to sign\sign.config ^(delete this file to choose again^)

:sign_tool
set "SIGNTOOL_PATH="
set "SDK_SIGN=%ProgramFiles(x86)%\Windows Kits\10\bin"
for /f "delims=" %%D in ('dir /b /ad /on "%SDK_SIGN%" 2^>nul') do (
    if exist "%SDK_SIGN%\%%D\x64\signtool.exe" (
        set "SIGNTOOL_PATH=%SDK_SIGN%\%%D\x64\signtool.exe"
        goto :sign_tool_found
    )
)
:sign_tool_found
if defined SIGNTOOL_PATH goto :sign_tool_ok
for /f "delims=" %%W in ('where signtool.exe 2^>nul') do (
    set "SIGNTOOL_PATH=%%W"
    goto :sign_tool_ok
)
:sign_tool_ok
if defined SIGNTOOL_PATH goto :sign_ready
echo Warning: signtool.exe not found, outputs will NOT be signed.
echo Install the Windows 10 SDK, or sign manually with:
echo   signtool sign /f certificate.pfx /fd sha256 ^/tr http://timestamp.digicert.com ^/td sha256 bin\generator.exe
goto :sign_setup_done

:sign_ready
set "PASS_ARG="
if defined PFX_PASS set "PASS_ARG=/p "%PFX_PASS%""
set "SIGN_OK=1"
echo Using certificate: %PFX_FILE%
echo Using signtool:    %SIGNTOOL_PATH%
set "TS_URL1=http://timestamp.digicert.com"
set "TS_URL2=http://timestamp.sectigo.com"
:sign_setup_done

echo.
echo [0/8] Generating embedded key headers...
if not exist "key\sky_share.bin" (
    echo ERROR: key\sky_share.bin not found! Run keygen.exe first.
    pause
    exit /b 1
)
if not exist "key\sky.bin" (
    echo ERROR: key\sky.bin not found! Run keygen.exe first.
    pause
    exit /b 1
)
cl /nologo /Fe:embed_key.exe src\embed_key.c
if !errorlevel! neq 0 (
    echo Compile embed_key failed!
    pause
    exit /b 1
)
embed_key.exe "key\sky_share.bin" "include\embedded_pubkey.h" EMBEDDED_PUBLIC_KEY EMBEDDED_PUBKEY_H
if !errorlevel! neq 0 (
    echo Generate embedded_pubkey.h failed!
    pause
    exit /b 1
)
embed_key.exe "key\sky.bin" "include\embedded_privkey.h" EMBEDDED_PRIVATE_KEY EMBEDDED_PRIVKEY_H
if !errorlevel! neq 0 (
    echo Generate embedded_privkey.h failed!
    pause
    exit /b 1
)
del embed_key.exe >nul 2>&1
echo Key headers generated successfully!

echo.
echo [1/8] Building hashgen.exe (DLL hash generator)...
cl /c /Iinclude src\sha256.c src\pe_digest.c src\hashgen.c /DWIN32 /D_CONSOLE /utf-8
if !errorlevel! neq 0 (
    echo Compile hashgen failed!
    pause
    exit /b 1
)
link /OUT:"hashgen.exe" sha256.obj pe_digest.obj hashgen.obj
if !errorlevel! neq 0 (
    echo Link hashgen failed!
    pause
    exit /b 1
)
echo hashgen.exe built successfully!
del *.obj >nul 2>&1

echo.
echo [2/8] First pass: Building license.dll (placeholder hash)...
cl /c /Iinclude src\sha256.c src\hardware.c src\license.c src\ntp_client.c src\time_anchor.c src\anti_debug.c src\license_dll.c src\key.c src\ecdsa.c /DWIN32 /D_WINDOWS /DLICENSE_DLL_EXPORTS /utf-8
if !errorlevel! neq 0 (
    echo Compile failed!
    pause
    exit /b 1
)

link /DLL /OUT:"%OUTPUT_DIR%\license.dll" sha256.obj hardware.obj license.obj ntp_client.obj time_anchor.obj anti_debug.obj license_dll.obj key.obj ecdsa.obj /EXPORT:License_Init /EXPORT:License_Shutdown /EXPORT:License_IsActivated /EXPORT:License_GetInfo /EXPORT:License_GetMachineCode /EXPORT:License_GetObfuscatedMachineCode /EXPORT:License_NormalizeMachineCode /EXPORT:License_Verify /EXPORT:License_ShowActivationDialog /EXPORT:License_Activate /EXPORT:License_Clear /EXPORT:License_GenerateCode user32.lib gdi32.lib advapi32.lib iphlpapi.lib ws2_32.lib psapi.lib bcrypt.lib shell32.lib
if !errorlevel! neq 0 (
    echo Link failed!
    pause
    exit /b 1
)
echo license.dll (pass 1) built successfully!
del *.obj >nul 2>&1

echo.
echo [3/8] Calculating .text section hash...
hashgen.exe "%OUTPUT_DIR%\license.dll" "include\dll_hash.h"
if !errorlevel! neq 0 (
    echo Hash generation failed!
    pause
    exit /b 1
)

echo.
echo [4/8] Second pass: Rebuilding license.dll (with correct hash)...
cl /c /Iinclude src\sha256.c src\hardware.c src\license.c src\ntp_client.c src\time_anchor.c src\anti_debug.c src\license_dll.c src\key.c src\ecdsa.c /DWIN32 /D_WINDOWS /DLICENSE_DLL_EXPORTS /utf-8
if !errorlevel! neq 0 (
    echo Compile failed!
    pause
    exit /b 1
)

link /DLL /OUT:"%OUTPUT_DIR%\license.dll" sha256.obj hardware.obj license.obj ntp_client.obj time_anchor.obj anti_debug.obj license_dll.obj key.obj ecdsa.obj /EXPORT:License_Init /EXPORT:License_Shutdown /EXPORT:License_IsActivated /EXPORT:License_GetInfo /EXPORT:License_GetMachineCode /EXPORT:License_GetObfuscatedMachineCode /EXPORT:License_NormalizeMachineCode /EXPORT:License_Verify /EXPORT:License_ShowActivationDialog /EXPORT:License_Activate /EXPORT:License_Clear /EXPORT:License_GenerateCode user32.lib gdi32.lib advapi32.lib iphlpapi.lib ws2_32.lib psapi.lib bcrypt.lib shell32.lib
if !errorlevel! neq 0 (
    echo Link failed!
    pause
    exit /b 1
)
echo license.dll (pass 2) built successfully!
del *.obj >nul 2>&1

echo.
echo [5/8] Building dll_test.exe...
cl /c /Iinclude src\dll_test.c /DWIN32 /D_CONSOLE /utf-8
if !errorlevel! neq 0 (
    echo Compile failed!
    pause
    exit /b 1
)

link /OUT:"%OUTPUT_DIR%\dll_test.exe" dll_test.obj "%OUTPUT_DIR%\license.lib" user32.lib
if !errorlevel! neq 0 (
    echo Link failed!
    pause
    exit /b 1
)
echo dll_test.exe built successfully!
del *.obj *.res >nul 2>&1

echo.
echo [6/8] Building license_system.exe...
rc /c 65001 /I include /I src /fo license_system.res src\main.rc
if !errorlevel! neq 0 (
    echo Resource compile failed!
    pause
    exit /b 1
)
cl /c /Iinclude src\sha256.c src\hardware.c src\license.c src\ntp_client.c src\time_anchor.c src\anti_debug.c src\key.c src\ecdsa.c src\main.c /DWIN32 /D_WINDOWS /utf-8
if !errorlevel! neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

link /OUT:"%OUTPUT_DIR%\license_system.exe" sha256.obj hardware.obj license.obj ntp_client.obj time_anchor.obj anti_debug.obj key.obj ecdsa.obj main.obj license_system.res user32.lib gdi32.lib advapi32.lib iphlpapi.lib ws2_32.lib psapi.lib bcrypt.lib shell32.lib
if !errorlevel! neq 0 (
    echo Link failed!
    pause
    exit /b 1
)
echo license_system.exe built successfully!

del *.obj *.res >nul 2>&1

echo.
echo [7/8] Building generator.exe...
rc /c 65001 /I include /I src /fo generator.res src\generator.rc
if !errorlevel! neq 0 (
    echo Resource compile failed!
    pause
    exit /b 1
)
cl /c /Iinclude /Isrc src\sha256.c src\hardware.c src\license.c src\ntp_client.c src\time_anchor.c src\anti_debug.c src\key.c src\ecdsa.c src\ecdsa_sign.c src\generator-core.c src\generator-version.c src\generator.c /DWIN32 /DECDSA_SIGN_ENABLED /utf-8
if !errorlevel! neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

link /OUT:"%OUTPUT_DIR%\generator.exe" sha256.obj hardware.obj license.obj ntp_client.obj time_anchor.obj anti_debug.obj key.obj ecdsa.obj ecdsa_sign.obj generator-core.obj generator-version.obj generator.obj generator.res user32.lib gdi32.lib advapi32.lib iphlpapi.lib ws2_32.lib psapi.lib bcrypt.lib shell32.lib
if !errorlevel! neq 0 (
    echo Link failed!
    pause
    exit /b 1
)
echo generator.exe built successfully!

del *.obj *.res >nul 2>&1

echo.
echo [8/8] Building keygen.exe and dat_viewer.exe...
rc /c 65001 /I include /I src /fo keygen.res src\keygen.rc
if !errorlevel! neq 0 (
    echo Resource compile failed!
    pause
    exit /b 1
)
cl /c /Iinclude src\keygen.c src\ecdsa.c src\sha256.c src\key.c /DWIN32 /utf-8
if !errorlevel! neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

link /OUT:"%OUTPUT_DIR%\keygen.exe" keygen.obj ecdsa.obj sha256.obj key.obj keygen.res user32.lib gdi32.lib advapi32.lib comdlg32.lib bcrypt.lib shell32.lib ole32.lib
if !errorlevel! neq 0 (
    echo Link failed!
    pause
    exit /b 1
)
echo keygen.exe built successfully!

del *.obj *.res >nul 2>&1

rc /c 65001 /fo dat_viewer.res src\dat_viewer.rc
if !errorlevel! neq 0 (
    echo Resource compile failed!
    pause
    exit /b 1
)
cl /c /Iinclude src\dat_viewer.c /DWIN32 /D_WINDOWS /utf-8
if !errorlevel! neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

link /OUT:"%OUTPUT_DIR%\dat_viewer.exe" dat_viewer.obj dat_viewer.res user32.lib gdi32.lib comdlg32.lib advapi32.lib
if !errorlevel! neq 0 (
    echo Link failed!
    pause
    exit /b 1
)
echo dat_viewer.exe built successfully!

del *.obj *.res >nul 2>&1

echo.
echo Cleaning up temporary files...
del "%OUTPUT_DIR%\license.lib" "%OUTPUT_DIR%\license.exp" >nul 2>&1
del hashgen.exe >nul 2>&1

echo.
echo ==============================================
echo [Signing] Signing build outputs...
echo ==============================================
if not defined SIGN_OK (
    echo No certificate configured, so nothing was signed. Delete nothing
    echo and re-run: pick the PFX when the dialog appears.
    goto :sign_all_done
)
for %%F in ("%OUTPUT_DIR%\license.dll" "%OUTPUT_DIR%\dll_test.exe" "%OUTPUT_DIR%\license_system.exe" "%OUTPUT_DIR%\generator.exe" "%OUTPUT_DIR%\keygen.exe" "%OUTPUT_DIR%\dat_viewer.exe") do call :sign_one "%%~F" "%%~nxF"
:sign_all_done

echo.
echo ==============================================
echo              Build Complete!
echo ==============================================
echo All files are in "%OUTPUT_DIR%\" directory:
echo   - license.dll (License DLL, integrity-protected)
echo   - dll_test.exe (DLL Test Program)
echo   - license_system.exe (GUI License Tool)
echo   - generator.exe (Activation Code Generator)
echo   - keygen.exe (Key Generator)
echo   - dat_viewer.exe (DAT File Viewer)
echo ==============================================
echo DLL Anti-Tamper: .text section SHA256 verified by loader + DLL self
echo ==============================================
if defined SIGN_OK goto :sign_report_yes
echo Outputs are NOT signed - no certificate was configured.
goto :sign_report_done

:sign_report_yes
echo Signed with: %PFX_FILE%
:sign_report_done
echo ==============================================
pause
exit /b 0

:sign_one
if exist %1 goto :sign_one_sha1
echo   skipped ^(not found^): %~1
goto :eof

:sign_one_sha1
echo Signing %~2 (SHA1)...
"%SIGNTOOL_PATH%" sign /f "%PFX_FILE%" %PASS_ARG% /fd sha1 /t %TS_URL1% %1
if not errorlevel 1 goto :sign_one_sha256
echo   Timestamp via %TS_URL1% failed, retrying with the backup server...
"%SIGNTOOL_PATH%" sign /f "%PFX_FILE%" %PASS_ARG% /fd sha1 /t %TS_URL2% %1
if not errorlevel 1 goto :sign_one_sha256
echo   Backup timestamp failed too, signing WITHOUT timestamp...
"%SIGNTOOL_PATH%" sign /f "%PFX_FILE%" %PASS_ARG% /fd sha1 %1
if not errorlevel 1 echo   WARNING: %~2 SHA1 signature has no timestamp, it expires with the certificate.

:sign_one_sha256
echo Signing %~2 (SHA256)...
"%SIGNTOOL_PATH%" sign /f "%PFX_FILE%" %PASS_ARG% /fd sha256 /tr %TS_URL1% /td sha256 /as %1
if not errorlevel 1 goto :eof
echo   Timestamp via %TS_URL1% failed, retrying with the backup server...
"%SIGNTOOL_PATH%" sign /f "%PFX_FILE%" %PASS_ARG% /fd sha256 /tr %TS_URL2% /td sha256 /as %1
if not errorlevel 1 goto :eof
echo   Backup timestamp failed too, signing WITHOUT timestamp...
"%SIGNTOOL_PATH%" sign /f "%PFX_FILE%" %PASS_ARG% /fd sha256 /as %1
if not errorlevel 1 echo   WARNING: %~2 SHA256 signature has no timestamp, it expires with the certificate.
goto :eof
