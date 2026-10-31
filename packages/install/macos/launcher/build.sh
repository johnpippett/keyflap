#!/usr/bin/env bash
# Builds keyflap-launch for Apple silicon macOS, on Linux, as your own user.
#
#   build.sh OUT_DIR      writes OUT_DIR/keyflap-launch and prints its SHA-256
#
# Cross-compiled in a container pinned by digest, with clang and lld at exact versions from a
# dated Debian snapshot. It links against libSystem.tbd here (the symbols the program imports),
# not Apple's SDK, and lld signs it ad hoc (arm64 macOS runs no unsigned code). Nothing in the
# output depends on the time, the machine or the paths, so every build of a commit is
# byte-identical. Needs podman or docker and network access to snapshot.debian.org.
set -euo pipefail

IMAGE=docker.io/library/debian@sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d
SNAPSHOT=20261027T000000Z
LLVM_VERSION=1:19.1.7-3+b1

[[ $# -eq 1 ]] || { echo "usage: build.sh OUT_DIR" >&2; exit 2; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
runtime=$(command -v podman || command -v docker) || { echo "build.sh: needs podman or docker" >&2; exit 1; }
mkdir -p "$1"
out=$(cd "$1" && pwd)/keyflap-launch

tar -C "$here" -cf - keyflap-launch.c libSystem.tbd |
  "$runtime" run --rm -i "$IMAGE" sh -euc '
    sed -i -e "s|^URIs: http://deb.debian.org/debian\$|URIs: http://snapshot.debian.org/archive/debian/$1|" \
      -e "s|^URIs: http://deb.debian.org/debian-security\$|URIs: http://snapshot.debian.org/archive/debian-security/$1|" \
      /etc/apt/sources.list.d/debian.sources
    apt-get -o Acquire::Check-Valid-Until=false -qq update </dev/null >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      "clang-19=$2" "lld-19=$2" </dev/null >/dev/null
    mkdir /src /build && tar -xf - -C /src && cd /build
    clang-19 --target=arm64-apple-macos11 -O2 -g0 -nostdinc -ffreestanding -fno-builtin \
      -fstack-protector-strong -Wall -Wextra -Werror -c /src/keyflap-launch.c -o keyflap-launch.o
    ld64.lld-19 -arch arm64 -platform_version macos 11.0 11.0 -dead_strip -fixup_chains \
      -o keyflap-launch keyflap-launch.o /src/libSystem.tbd
    cat keyflap-launch
  ' sh "$SNAPSHOT" "$LLVM_VERSION" >"$out.tmp"
chmod 0755 "$out.tmp"
mv "$out.tmp" "$out"
sha256sum "$out"
