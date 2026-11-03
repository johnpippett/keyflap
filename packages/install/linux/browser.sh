# Chrome for Testing, installed inside Playwright's Chromium revision directories: Playwright
# 1.64.1 pins revision 1248, whose Chrome 156.0.8078.4 has known vulnerabilities. Fetches
# CHROME_FOR_TESTING_VERSION (runtime-pins.sh) and keeps Playwright's layout unchanged, so the
# pinned Playwright still finds its browser. Bash 3.2 and BSD userland; functions only.
#
#   cft_platform OS ARCH              -> linux64, linux-arm64, mac-arm64 or mac-x64
#   cft_asset PLATFORM KIND           -> the zip's name (KIND: full or shell)
#   cft_inner PLATFORM KIND           -> the top-level directory inside that zip
#   cft_exe PLATFORM KIND DIR         -> the executable to ask for --version
#   browser_is_current DIR KIND       -> 0 when DIR holds our build (KIND: full, shell or both)
#   install_chrome_for_testing DIR OS ARCH KIND
#                                     -> download and swap in KIND's build (both, full or shell)

cft_tmp=''

cft_fail() {
  if [[ -n ${cft_tmp:-} ]]; then rm -rf "$cft_tmp"; fi
  if command -v die >/dev/null 2>&1; then die "$*"; fi
  echo "install: $*" >&2
  exit 1
}

cft_platform() {
  local os arch
  os=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  arch=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
  case $os-$arch in
    linux-x64 | linux-x86_64) printf '%s\n' linux64 ;;
    linux-arm64 | linux-aarch64) printf '%s\n' linux-arm64 ;;
    darwin-arm64 | darwin-aarch64) printf '%s\n' mac-arm64 ;;
    darwin-x64 | darwin-x86_64) printf '%s\n' mac-x64 ;;
    *) return 1 ;;
  esac
}

cft_asset() {
  case $1-$2 in
    linux64-full) printf '%s\n' chrome-linux64.zip ;;
    linux64-shell) printf '%s\n' chrome-headless-shell-linux64.zip ;;
    linux-arm64-full) printf '%s\n' chrome-linux-arm64.zip ;;
    linux-arm64-shell) printf '%s\n' chrome-headless-shell-linux-arm64.zip ;;
    mac-arm64-full) printf '%s\n' chrome-mac-arm64.zip ;;
    mac-arm64-shell) printf '%s\n' chrome-headless-shell-mac-arm64.zip ;;
    mac-x64-full) printf '%s\n' chrome-mac-x64.zip ;;
    mac-x64-shell) printf '%s\n' chrome-headless-shell-mac-x64.zip ;;
    *) return 1 ;;
  esac
}

cft_inner() {
  case $1-$2 in
    linux64-full) printf '%s\n' chrome-linux64 ;;
    linux64-shell) printf '%s\n' chrome-headless-shell-linux64 ;;
    linux-arm64-full) printf '%s\n' chrome-linux-arm64 ;;
    linux-arm64-shell) printf '%s\n' chrome-headless-shell-linux-arm64 ;;
    mac-arm64-full) printf '%s\n' chrome-mac-arm64 ;;
    mac-arm64-shell) printf '%s\n' chrome-headless-shell-mac-arm64 ;;
    mac-x64-full) printf '%s\n' chrome-mac-x64 ;;
    mac-x64-shell) printf '%s\n' chrome-headless-shell-mac-x64 ;;
    *) return 1 ;;
  esac
}

cft_exe() {
  case $1-$2 in
    linux64-full | linux-arm64-full) printf '%s\n' "$3/chrome" ;;
    linux64-shell | linux-arm64-shell | mac-arm64-shell | mac-x64-shell) printf '%s\n' "$3/chrome-headless-shell" ;;
    mac-arm64-full | mac-x64-full) printf '%s\n' "$3/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing" ;;
    *) return 1 ;;
  esac
}

cft_revision() {
  case $1 in
    full) printf '%s\n' "chromium-$CHROMIUM_REVISION" ;;
    shell) printf '%s\n' "chromium_headless_shell-$CHROMIUM_REVISION" ;;
    *) return 1 ;;
  esac
}

browser_is_current() {
  local browsers=$1 kinds=$2 platform kind inner revision
  [[ -f $browsers/.chrome-for-testing-version ]] || return 1
  [[ $(cat "$browsers/.chrome-for-testing-version" 2>/dev/null) == "$CHROME_FOR_TESTING_VERSION" ]] || return 1
  platform=$(cft_platform "$(uname -s)" "$(uname -m)") || return 1
  case $kinds in
    both) kinds='full shell' ;;
    full | shell) ;;
    *) return 1 ;;
  esac
  for kind in $kinds; do
    revision=$(cft_revision "$kind") || return 1
    inner=$(cft_inner "$platform" "$kind") || return 1
    [[ -d $browsers/$revision/$inner ]] || return 1
  done
}

install_chrome_for_testing() {
  local browsers=$1 os=$2 arch=$3 kinds=$4
  local platform kind asset inner revision expected url exe version
  platform=$(cft_platform "$os" "$arch") || cft_fail "no Chrome for Testing build for $os-$arch"
  case $kinds in
    both) kinds='full shell' ;;
    full | shell) ;;
    *) cft_fail "unknown browser kind $kinds" ;;
  esac
  for kind in $kinds; do
    asset=$(cft_asset "$platform" "$kind") || cft_fail "no $kind Chrome for Testing asset for $platform"
    inner=$(cft_inner "$platform" "$kind") || cft_fail "no $kind Chrome for Testing directory for $platform"
    revision=$(cft_revision "$kind") || cft_fail "unknown browser kind $kind"
    cft_tmp=$(mktemp -d "${TMPDIR:-/tmp}/keyflap-cft.XXXXXX")
    url=https://storage.googleapis.com/chrome-for-testing-public/$CHROME_FOR_TESTING_VERSION/$platform/$asset
    curl -fSL --proto '=https' --tlsv1.2 -o "$cft_tmp/$asset" "$url" ||
      cft_fail "the Chrome for Testing download failed: $url"
    expected=$(cft_sha256 "$platform" "$kind") || cft_fail "no pinned SHA-256 for $platform $kind"
    [[ -n $expected ]] || cft_fail "no pinned SHA-256 for $platform $kind"
    cft_hash_check "$cft_tmp/$asset" "$expected" ||
      cft_fail "Chrome for Testing checksum mismatch: $asset"
    unzip -q "$cft_tmp/$asset" -d "$cft_tmp" || cft_fail "cannot unpack Chrome for Testing: $asset"
    [[ -d $cft_tmp/$inner ]] || cft_fail "$asset has no $inner directory"
    rm -rf "${browsers:?}/$revision/$inner"
    mkdir -p "$browsers/$revision"
    mv "$cft_tmp/$inner" "$browsers/$revision/$inner"
    : >"$browsers/$revision/INSTALLATION_COMPLETE"
    : >"$browsers/$revision/DEPENDENCIES_VALIDATED"
    exe=$(cft_exe "$platform" "$kind" "$browsers/$revision/$inner") ||
      cft_fail "no $kind Chrome for Testing executable for $platform"
    version=$("$exe" --version 2>/dev/null) || cft_fail "cannot run $exe --version"
    case $version in
      *"$CHROME_FOR_TESTING_VERSION"*) ;;
      *) cft_fail "$exe runs $version, which is not $CHROME_FOR_TESTING_VERSION" ;;
    esac
    if command -v dequarantine >/dev/null 2>&1; then dequarantine "$browsers/$revision/$inner"; fi
    rm -rf "$cft_tmp"
    cft_tmp=''
  done
  printf '%s\n' "$CHROME_FOR_TESTING_VERSION" >"$browsers/.chrome-for-testing-version"
}
