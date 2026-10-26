@echo off
setlocal
echo =========================================
echo  Building PurgeX
echo =========================================
echo.

REM Default toolchain location (MSYS2 UCRT64). If qmake is already on PATH it is used as is.
if exist "C:\msys64\ucrt64\bin\qmake.exe" set "PATH=C:\msys64\ucrt64\bin;%PATH%"

where qmake >nul 2>nul
if errorlevel 1 (
    echo Error: qmake not found.
    echo.
    echo Install the toolchain with MSYS2 ^(UCRT64 shell^):
    echo   pacman -S mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-qt5-base ^
    echo             mingw-w64-ucrt-x86_64-qt5-tools mingw-w64-ucrt-x86_64-openssl
    echo or use the Qt online installer and run this script from a Qt MinGW prompt.
    if not defined CI pause
    exit /b 1
)

for /f "delims=" %%i in ('where qmake') do (
    set "TOOL_BIN=%%~dpi"
    goto :found
)
:found
echo Using qmake from %TOOL_BIN%
qmake -v
echo.

echo Generating Makefile...
qmake PurgeX.pro
if errorlevel 1 (
    echo qmake failed.
    if not defined CI pause
    exit /b 1
)

echo.
echo Compiling...
mingw32-make -f Makefile.Release -j %NUMBER_OF_PROCESSORS%
if errorlevel 1 (
    echo.
    echo Build failed!
    if not defined CI pause
    exit /b 1
)

echo.
echo =========================================
echo  Deploying dependencies
echo =========================================
echo.
cd /d "%~dp0release"

windeployqt.exe --compiler-runtime PurgeX.exe
if errorlevel 1 (
    echo.
    echo windeployqt failed. Copying the MSYS2 runtime manually...
    for %%D in (Qt5Core Qt5Gui Qt5Widgets Qt5PrintSupport libgcc_s_seh-1 libstdc++-6 libwinpthread-1 ^
                libdouble-conversion libfreetype-6 libicuin77 libicuuc77 libicudt77 libpcre2-16-0 libpcre2-8-0 ^
                zlib1 libzstd libharfbuzz-0 libmd4c libpng16-16 libbrotlidec libbrotlicommon libbz2-1 ^
                libglib-2.0-0 libgraphite2 libintl-8 libiconv-2) do (
        if exist "%TOOL_BIN%%%D.dll" copy /y "%TOOL_BIN%%%D.dll" . >nul
    )
    if not exist platforms mkdir platforms
    copy /y "%TOOL_BIN%..\share\qt5\plugins\platforms\qwindows.dll" platforms\ >nul
    if not exist imageformats mkdir imageformats
    copy /y "%TOOL_BIN%..\share\qt5\plugins\imageformats\qjpeg.dll" imageformats\ >nul
)

REM libcrypto signs and verifies certificates; windeployqt does not know about it.
for %%F in ("%TOOL_BIN%libcrypto-*.dll") do copy /y "%%F" . >nul

echo.
echo Build and deployment completed successfully.
echo The standalone application is in the 'release' folder.
if not defined CI pause
endlocal
