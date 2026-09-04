#!/bin/bash

echo "Building PurgeX - Secure Data Wiping Tool"
echo "Building PurgeX"
echo

# Check if qmake is available
if ! command -v qmake &> /dev/null; then
    echo "Error: qmake not found. Please install Qt5 or Qt6."
    echo
    echo "Ubuntu/Debian: sudo apt install qt5-default qtbase5-dev"
    echo "Fedora/RHEL: sudo dnf install qt5-qtbase-devel"
    echo "Arch/Manjaro: sudo pacman -S qt5-base qt5-tools"
    echo "macOS: brew install qt@5"
    exit 1
fi

echo "Using qmake:"
qmake --version
echo

# Clean previous build
echo "Cleaning previous build..."
rm -f Makefile Makefile.Debug Makefile.Release
rm -rf debug release

echo "Generating Makefile..."
qmake PurgeX.pro
if [ $? -ne 0 ]; then
    echo "Error: qmake failed"
    exit 1
fi

echo
echo "Compiling..."
make -j$(nproc)
if [ $? -ne 0 ]; then
    echo "Error: Compilation failed"
    exit 1
fi

echo
echo "Build completed successfully!"
echo
echo "Executable: ./PurgeX"
echo
echo "Usage:"
echo "  GUI Mode: ./PurgeX"
echo "  CLI Mode: ./PurgeX --cli --help"
echo
