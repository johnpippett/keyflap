# The pinned service-mode runtime (docs/ISOLATION_PLAN.md D4), sourced by install.sh and
# build-bundle.sh (Linux) and by packages/install/macos/install.sh, so the release build and
# the installers check the same values. Plain variables, not an associative array: macOS
# ships bash 3.2, which has none.
# Bump NODE_* together (sha256 from https://nodejs.org/dist/vX/SHASUMS256.txt), and
# CHROMIUM_REVISION together with Playwright (CLAUDE.md: pinned to 1.64.1 / 1248);
# build-bundle.sh refuses a bundle whose Playwright expects another revision.
# shellcheck shell=bash disable=SC2034
NODE_VERSION=22.23.4
NODE_SHA256_linux_x64=1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce
NODE_SHA256_linux_arm64=6287aa46b6c375d816e63ae66d024fbbfd70404825aabdfdf898a970871d2f4b
NODE_SHA256_darwin_arm64=037650d0839f457747396f052073fb48333d31bf5abd3c98b74da20d89ebb1ad
CHROMIUM_REVISION=1248

# node_sha256 OS ARCH: the pinned SHA-256 of node-vNODE_VERSION-OS-ARCH.tar.xz, or nothing.
node_sha256() {
  eval "printf '%s' \"\${NODE_SHA256_$1_$2:-}\""
}
