# The pinned service-mode runtime (docs/ISOLATION_PLAN.md D4), sourced by install.sh and
# build-bundle.sh (Linux) and by packages/install/macos/install.sh, so the release build and
# the installers check the same values. Plain variables, not an associative array: macOS
# ships bash 3.2, which has none.
# Bump NODE_* together (sha256 from https://nodejs.org/dist/vX/SHASUMS256.txt), and
# CHROMIUM_REVISION together with Playwright (CLAUDE.md: pinned to 1.65.1 / 1255);
# build-bundle.sh refuses a bundle whose Playwright expects another revision.
# shellcheck shell=bash disable=SC2034
NODE_VERSION=22.23.5
NODE_SHA256_linux_x64=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8
NODE_SHA256_linux_arm64=2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09
NODE_SHA256_darwin_arm64=d0c68c321161bb2c6483efea9a343010dea8e5e7f60d73c6a7eba140016d662f
CHROMIUM_REVISION=1255
# The Chrome for Testing build put inside Playwright's revision directories: 159.0.8154.33
# updates the 159.0.8154 branch ahead of Playwright 1.65.1's bundled 159.0.8154.6. Independent
# of CHROMIUM_REVISION, and it is the security patch level to bump.
CHROME_FOR_TESTING_VERSION=159.0.8154.33
CFT_SHA256_linux64_full=892ea184f6738de789b1e3fc18f66ac8d7a1f55b473f688cb27fe0b1b55f409e
CFT_SHA256_linux64_shell=50664258def7bad1793d527b30c900540b668462686e3cc5862e65036652a190
CFT_SHA256_linux_arm64_full=84e7ec54c9e3d7d03435fda89a2e71cef7e5117b2abd5e2fafa8d7f3521963b7
CFT_SHA256_linux_arm64_shell=6f08e46a33caa8940b6ac77c082d187b6e4cbf099997eea28dbed75dd1050432
CFT_SHA256_mac_arm64_full=00b33fd0c8dc9b5ef33301763df177a566424cce328be303c1736581c4a09ffe
CFT_SHA256_mac_arm64_shell=f3e5fa5eb5c4803024fd3e198175cddd6cbd40dfd9e2aef75c2d3bf924010457
CFT_SHA256_mac_x64_full=e8f2f419e9dbff7599def39acedffd5ef6897891c834f874c28fe436344f43f3
CFT_SHA256_mac_x64_shell=d251b6d9e535c6cf5413ec948e1ef55156f4473956f9f452ff4cad3ba1474c97

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
