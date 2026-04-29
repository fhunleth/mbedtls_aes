#!/usr/bin/env bash
# SPDX-FileCopyrightText: None
# SPDX-License-Identifier: CC0-1.0
#
# Cross-build and run aes_bench for one target architecture.
# Picks the first available toolchain prefix (Nerves, then Debian/Ubuntu)
# and the first available qemu-user binary on PATH.

set -euo pipefail

ARCH="${1:-}"

case "$ARCH" in
  aarch64)
    TRIPLES=(aarch64-nerves-linux-gnu aarch64-linux-gnu)
    QEMU_NAMES=(qemu-aarch64-static qemu-aarch64)
    MARCH="-march=armv8-a"
    APT_PKGS="gcc-aarch64-linux-gnu libc6-dev-arm64-cross"
    ;;
  armv7)
    TRIPLES=(armv7-nerves-linux-gnueabihf arm-linux-gnueabihf)
    QEMU_NAMES=(qemu-arm-static qemu-arm)
    MARCH="-march=armv7-a -mfpu=neon"
    APT_PKGS="gcc-arm-linux-gnueabihf libc6-dev-armhf-cross"
    ;;
  riscv64)
    TRIPLES=(riscv64-nerves-linux-gnu riscv64-linux-gnu)
    QEMU_NAMES=(qemu-riscv64-static qemu-riscv64)
    MARCH=""
    APT_PKGS="gcc-riscv64-linux-gnu libc6-dev-riscv64-cross"
    ;;
  ""|-h|--help)
    echo "usage: $0 <aarch64|armv7|riscv64>" >&2
    exit 2
    ;;
  *)
    echo "$0: unknown arch '$ARCH'" >&2
    echo "usage: $0 <aarch64|armv7|riscv64>" >&2
    exit 2
    ;;
esac

cd "$(dirname "$0")/.."

HOST="$(uname -s)"

print_install_hint() {
  echo "" >&2
  echo "Install options:" >&2
  echo "  Nerves toolchain (any host):  mise install   # or: asdf install" >&2
  if [ "$HOST" = "Linux" ]; then
    echo "  Debian/Ubuntu apt:            sudo apt-get install -y $APT_PKGS qemu-user-static" >&2
  fi
}

TRIPLE=""
for t in "${TRIPLES[@]}"; do
  if command -v "${t}-gcc" >/dev/null 2>&1; then
    TRIPLE="$t"
    break
  fi
done
if [ -z "$TRIPLE" ]; then
  echo "no cross compiler found for $ARCH (tried: ${TRIPLES[*]})" >&2
  print_install_hint
  exit 1
fi

# qemu-user is Linux-only. On other hosts we build-only.
QEMU=""
if [ "$HOST" = "Linux" ]; then
  for q in "${QEMU_NAMES[@]}"; do
    if command -v "$q" >/dev/null 2>&1; then
      QEMU="$q"
      break
    fi
  done
  if [ -z "$QEMU" ]; then
    echo "no qemu-user binary found for $ARCH (tried: ${QEMU_NAMES[*]})" >&2
    print_install_hint
    exit 1
  fi
fi

SYSROOT="$("${TRIPLE}-gcc" -print-sysroot 2>/dev/null || true)"
# Some Debian cross-gcc packages (e.g. arm-linux-gnueabihf) report sysroot="/",
# which is bogus for a cross toolchain — the host root doesn't contain the
# target loader. Treat empty, "/", or a non-existent path as missing and fall
# back to /usr/${TRIPLE} (Debian multiarch layout).
if [ -z "$SYSROOT" ] || [ "$SYSROOT" = "/" ] || [ ! -d "$SYSROOT" ]; then
  if [ -d "/usr/${TRIPLE}" ]; then
    SYSROOT="/usr/${TRIPLE}"
  else
    SYSROOT=""
  fi
fi

OBJDIR="build/cross-${ARCH}"
BIN="build/aes_bench-${ARCH}"
CFLAGS="-O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -std=c11 -D_GNU_SOURCE ${MARCH} -I."

echo "==> arch=${ARCH}  triple=${TRIPLE}  qemu=${QEMU:-<build-only on $HOST>}  sysroot=${SYSROOT:-<none>}"

make amalgamate
make CC="${TRIPLE}-gcc" CFLAGS="$CFLAGS" LDFLAGS="$MARCH" OBJDIR="$OBJDIR" BIN="$BIN"

if [ -n "$QEMU" ]; then
  QEMU_LD_PREFIX="$SYSROOT" AES_BENCH_MIN_SECONDS=0.2 "$QEMU" "./$BIN"
else
  echo "==> built ./$BIN (skipping run; qemu-user is Linux-only)"
fi
