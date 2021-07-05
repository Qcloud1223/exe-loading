#!/usr/bin/env bash
set -eux
gcc \
  -L/home/hypermoon/Qcloud/glibc/build/install/lib \
  -I/home/hypermoon/Qcloud/glibc/build/install/include \
  -Wl,-rpath=/home/hypermoon/Qcloud/glibc/build/install/lib \
  -Wl,--dynamic-linker=/home/hypermoon/Qcloud/glibc/build/install/lib/ld-linux-x86-64.so.2 \
  -std=c11 \
  -o "$1" \
  -g \
  "$1.c" \
  -ldl
# build Loader, nothing special
