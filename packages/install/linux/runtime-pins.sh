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
# The Chrome for Testing build put inside Playwright's revision directories: 156.0.8078.80
# fixes CVE-2026-118306, -118331, -118348 and -118344. Independent of CHROMIUM_REVISION, and
# it is the security patch level to bump.
CHROME_FOR_TESTING_VERSION=156.0.8078.80
CFT_SHA256_linux64_full=b711c720f774be355197f32edf37e0651418ba036d92446ee2da19ac017540a7
CFT_SHA256_linux64_shell=547dcd374e02961bf998f6046a267644f8502225c36bb78ca307dab32a0b3eb4
CFT_SHA256_linux_arm64_full=1f496a826c9ba4d6a5f5bf2de686145fe718528c2cc3dbeb96b5893b89653724
CFT_SHA256_linux_arm64_shell=5bb6a00a4285c13303d3f72c5afdb70f144ea7a93eed462365a52b69631c9607
CFT_SHA256_mac_arm64_full=8bc590d1b1acac042a000234c768f31830f25a3983a83ed5e067114c87c4cad1
CFT_SHA256_mac_arm64_shell=ea615baa2e9caf0d02d1898a6562b5f8fa9c35239707dae0f592178df5b986ac
CFT_SHA256_mac_x64_full=672b79dc79fdf28bb2ec9787b7fa33810c2b3cfd946a0fb4d3b72775f4e6fd9a
CFT_SHA256_mac_x64_shell=535d417d9034cbd11e7dacd1a71aa3d6e1b525e6d5dcd2671eb2532f01481228

# node_sha256 OS ARCH: the pinned SHA-256 of node-vNODE_VERSION-OS-ARCH.tar.xz, or nothing.
node_sha256() {
  eval "printf '%s' \"\${NODE_SHA256_$1_$2:-}\""
}

# cft_sha256 PLATFORM KIND: the pinned SHA-256 of the Chrome for Testing archive, or nothing.
cft_sha256() {
  local key
  key=$(printf '%s_%s' "$1" "$2" | tr '-' '_')
  eval "printf '%s' \"\${CFT_SHA256_$key:-}\""
}
