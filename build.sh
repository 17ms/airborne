#!/usr/bin/env bash

CORES=$(nproc)
USED=$(($CORES / 2))

case $(uname -a) in
    Linux*)
        echo "[+] Using Linux toolchain"
        TOOLCHAIN="linux-mingw-w64-x86_64.cmake"
        ;;
    Darwin*)
        echo "[+] Using Darwin toolchain"
        TOOLCHAIN="darwin-mingw-w64-x86_64.cmake"
        ;;
esac

echo "[+] Running CMake with specified toolchain, outputting to build/"
if ! cmake -DCMAKE_TOOLCHAIN_FILE=toolchains/$TOOLCHAIN -B build
then
    echo "[!] CMake failed, aborting build"
    exit 1
fi

echo "[+] Running Make with $USED threads"
make -j$USED -C build
