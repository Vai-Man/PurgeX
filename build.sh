#!/bin/bash
# Builds PurgeX with qmake. Tested with Qt 5.15 on Windows (MSYS2); the Linux build uses the same sources.
set -e

if ! command -v qmake &> /dev/null; then
    echo "Error: qmake not found. Install Qt 5.15+ (widgets + printsupport) and OpenSSL headers:"
    echo
    echo "  Ubuntu/Debian: sudo apt install build-essential qtbase5-dev qt5-qmake libssl-dev"
    echo "  Fedora/RHEL:   sudo dnf install gcc-c++ qt5-qtbase-devel openssl-devel"
    echo "  Arch/Manjaro:  sudo pacman -S base-devel qt5-base openssl"
    exit 1
fi

echo "Using $(qmake --version | tail -1)"

echo "Generating Makefile..."
qmake PurgeX.pro

echo "Compiling..."
if command -v nproc &> /dev/null; then JOBS=$(nproc); else JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 2); fi
make -j"$JOBS"

echo
echo "Build completed successfully: ./PurgeX"
echo
echo "  GUI:  ./PurgeX"
echo "  CLI:  ./PurgeX --help"
echo
echo "Raw disk access (full-drive wipe, hardware secure erase, device recovery) needs root: run with sudo."
