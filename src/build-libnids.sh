#!/usr/bin/env bash
set -eux
gcc \
  -L/home/hypermoon/Qcloud/glibc/build/install/lib \
  -I/home/hypermoon/Qcloud/glibc/build/install/include \
  -o "$1.exe" \
  -g \
  -rdynamic \
  "$1.c" \
  -Wl,-rpath=/home/hypermoon/Qcloud/glibc/build/install/lib \
  -Wl,--dynamic-linker=/home/hypermoon/Qcloud/glibc/build/install/lib/ld-linux-x86-64.so.2 \
  -lnids
