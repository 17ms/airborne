#!/usr/bin/env bash

CORES=$(nproc)
USED=$(($CORES / 2))

case $(uname -a) in
    Linux*)
        echo "[+] Using Linux toolchain"
        TOOLCHAIN="linux-mingw-w64-x86_64.cmake"
        ;;
    Darwin*)
        echo "[+] Using MacOS toolchain"
        TOOLCHAIN="macos-mingw-w64-x86_64.cmake"
        ;;
esac

echo "Running CMake"
cmake -DCMAKE_TOOLCHAIN_FILE=toolchains/$TOOLCHAIN -B build

echo "Running Make with $USED threads"
make -j$USED -C build
