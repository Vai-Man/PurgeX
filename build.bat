@echo off
echo =========================================
echo  Building PurgeX - Secure Data Wiping Tool
echo =========================================
echo.

REM Set the path to include Qt binaries (MSYS2)
set "PATH=C:\msys64\ucrt64\bin;%PATH%"

REM Check if qmake is available
where qmake >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: qmake not found. Please install Qt5 or Qt6.
    echo.
    echo Windows: Download from https://www.qt.io/download
    echo Or use MSYS2: pacman -S mingw-w64-x86_64-qt5
    pause
    exit /b 1
)

echo Using qmake:
qmake -v

echo.
echo Generating Makefile...
qmake PurgeX.pro

echo.
echo Compiling...
mingw32-make -f Makefile.Release

if %errorlevel% neq 0 (
    echo.
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo =========================================
echo  Deploying Dependencies
echo =========================================
echo.
cd /d "%~dp0\release"

windeployqt.exe --compiler-runtime PurgeX.exe

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo windeployqt failed. Proceeding with manual MSYS2 fallback deployment...
    set MINGW_BIN=C:\msys64\ucrt64\bin
    set PLUGINS_DIR=C:\msys64\ucrt64\share\qt5\plugins
    
    copy /y "%MINGW_BIN%\Qt5Core.dll" . >nul
    copy /y "%MINGW_BIN%\Qt5Gui.dll" . >nul
    copy /y "%MINGW_BIN%\Qt5Widgets.dll" . >nul
    copy /y "%MINGW_BIN%\Qt5PrintSupport.dll" . >nul
    copy /y "%MINGW_BIN%\libgcc_s_seh-1.dll" . >nul
    copy /y "%MINGW_BIN%\libstdc++-6.dll" . >nul
    copy /y "%MINGW_BIN%\libwinpthread-1.dll" . >nul
    
    REM Transitive dependencies
    copy /y "%MINGW_BIN%\libdouble-conversion.dll" . >nul
    copy /y "%MINGW_BIN%\libfreetype-6.dll" . >nul
    copy /y "%MINGW_BIN%\libicuin77.dll" . >nul
    copy /y "%MINGW_BIN%\libicuuc77.dll" . >nul
    copy /y "%MINGW_BIN%\libicudt77.dll" . >nul
    copy /y "%MINGW_BIN%\libpcre2-16-0.dll" . >nul
    copy /y "%MINGW_BIN%\libpcre2-8-0.dll" . >nul
    copy /y "%MINGW_BIN%\zlib1.dll" . >nul
    copy /y "%MINGW_BIN%\libzstd.dll" . >nul
    copy /y "%MINGW_BIN%\libharfbuzz-0.dll" . >nul
    copy /y "%MINGW_BIN%\libmd4c.dll" . >nul
    copy /y "%MINGW_BIN%\libpng16-16.dll" . >nul
    copy /y "%MINGW_BIN%\libbrotlidec.dll" . >nul
    copy /y "%MINGW_BIN%\libbrotlicommon.dll" . >nul
    copy /y "%MINGW_BIN%\libbz2-1.dll" . >nul
    copy /y "%MINGW_BIN%\libglib-2.0-0.dll" . >nul
    copy /y "%MINGW_BIN%\libgraphite2.dll" . >nul
    copy /y "%MINGW_BIN%\libintl-8.dll" . >nul
    copy /y "%MINGW_BIN%\libiconv-2.dll" . >nul

    if not exist platforms mkdir platforms
    copy /y "%PLUGINS_DIR%\platforms\qwindows.dll" platforms\ >nul

    if not exist imageformats mkdir imageformats
    copy /y "%PLUGINS_DIR%\imageformats\qjpeg.dll" imageformats\ >nul
)

echo.
echo Build and deployment completed successfully!
echo You can find the standalone application in the 'release' folder.
pause
