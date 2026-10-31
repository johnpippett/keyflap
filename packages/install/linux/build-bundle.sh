#!/usr/bin/env bash
# Stages the broker's code for install.sh, as your own user (no root).
#
#   build-bundle.sh OUT_DIR
#     OUT_DIR/app/  package.json, lockfile, packages/*/{package.json,src}, docs, and production
#                   node_modules (pnpm --prod --offline from your store; no install scripts run).
#     For a source install: sudo packages/install/linux/install.sh --bundle OUT_DIR …
#
#   build-bundle.sh --release OUT_DIR [--version V] [--os linux|darwin|all] [--arch x64|arm64|all]
#                   [--node-cache DIR] [--launcher FILE]
#     OUT_DIR/keyflap-V-linux-ARCH.tar.xz (one per arch), OUT_DIR/keyflap-V-darwin-arm64.tar.xz
#     with --os darwin or all, and OUT_DIR/SHA256SUMS. Each tarball holds keyflap-V-OS-ARCH/ with
#     install.sh, uninstall.sh, that OS's service files (units and configs; launchd plists and
#     keyflap-launch, built by packages/install/macos/launcher/build.sh unless --launcher names
#     a build), the bundle (bundle/app as above) and the pinned Node tarball for that OS and arch
#     (checked against runtime-pins.sh here and again by install.sh). Chromium is not included:
#     install.sh fetches Playwright's build for the machine. V defaults to the exact git tag
#     (vX.Y.Z -> X.Y.Z), else 0.0.0-dev.<commit>. Node tarballs are cached in DIR (default
#     ~/.cache/keyflap/node) and downloaded from nodejs.org when missing. --arch applies to
#     Linux; macOS is Apple silicon only.
#
# Reproducible where reasonably possible: files sorted, owner 0:0, modes normalised, every
# mtime set to SOURCE_DATE_EPOCH (default: the commit time), no build paths or timestamps in
# the content (pnpm's .modules.yaml, workspace state and .bin shims are dropped; nothing in
# /opt/keyflap runs them). The tar stream is byte-identical for the same commit, lockfile and
# pnpm version; the .xz also needs the same xz version (single-threaded, preset 6).
#
# install.sh copies the bundle into the root-owned /opt/keyflap/app (fresh inodes, owned by
# root), so nothing in /opt/keyflap stays linked to your checkout or your pnpm store.
set -euo pipefail
umask 022
export LC_ALL=C

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
die() { echo "build-bundle: $*" >&2; exit 1; }
# shellcheck source=runtime-pins.sh
source "$here/runtime-pins.sh"

release=0 out='' version='' arch_opt='' os_opt='' node_cache='' launcher=''
while [[ $# -gt 0 ]]; do
  case $1 in
    --release) release=1; shift ;;
    --version) version=${2:?}; shift 2 ;;
    --arch) arch_opt=${2:?}; shift 2 ;;
    --os) os_opt=${2:?}; shift 2 ;;
    --node-cache) node_cache=${2:?}; shift 2 ;;
    --launcher) launcher=${2:?}; shift 2 ;;
    -h|--help) sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) [[ -z $out ]] || die "one OUT_DIR only"; out=$1; shift ;;
  esac
done
[[ -n $out ]] || die "usage: build-bundle.sh [--release] OUT_DIR (--help)"
if [[ $release -eq 0 && ( -n $version || -n $arch_opt || -n $os_opt || -n $node_cache || -n $launcher ) ]]; then
  die "--version, --os, --arch, --node-cache and --launcher need --release"
fi
command -v pnpm >/dev/null || die "pnpm not on PATH (corepack enable)"

revision=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)
dirty=0
[[ -z "$(git -C "$repo" status --porcelain 2>/dev/null)" ]] || { dirty=1; revision=$revision-dirty; }
if [[ -z ${SOURCE_DATE_EPOCH:-} ]]; then
  SOURCE_DATE_EPOCH=$(git -C "$repo" log -1 --format=%ct 2>/dev/null || echo 0)
fi
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be seconds since the epoch"
export SOURCE_DATE_EPOCH

# ---- the bundle: app/ ----------------------------------------------------------------
build_bundle() { # build_bundle DIR (DIR must not exist)
  local dir=$1
  mkdir -p "$dir/app/packages"
  touch "$dir/.keyflap-bundle"
  cp "$repo/package.json" "$repo/pnpm-lock.yaml" "$repo/pnpm-workspace.yaml" "$repo/.node-version" "$dir/app/"
  mkdir -p "$dir/app/docs"
  cp -r "$repo/docs/." "$dir/app/docs/"
  local pkg name
  for pkg in "$repo"/packages/*/; do
    name=$(basename "$pkg")
    mkdir -p "$dir/app/packages/$name"
    cp "$pkg/package.json" "$dir/app/packages/$name/"
    # Runtime code only: never tests, fixtures or the fake pass-cli.
    if [[ -d "$pkg/src" ]]; then cp -r "$pkg/src" "$dir/app/packages/$name/"; fi
  done

  # Your checkout's store (pnpm picks a per-filesystem store otherwise, and OUT may be on
  # another filesystem). Files are copied or hard-linked from it; install.sh copies again.
  local store
  store=$(cd "$repo" && pnpm store path)
  (
    cd "$dir/app"
    pnpm install --prod --frozen-lockfile --offline --ignore-scripts --store-dir "$store" \
      --config.confirmModulesPurge=false >/dev/null
  )
  # pnpm's bookkeeping holds build paths and times; the service never runs pnpm or .bin shims.
  rm -f "$dir/app/node_modules/.modules.yaml" "$dir/app/node_modules/.pnpm-workspace-state-v1.json"
  find "$dir/app" -type d -name .bin -path '*/node_modules/*' -prune -exec rm -rf {} +

  # The browser install.sh fetches must be the one this Playwright drives.
  local browsers
  browsers=$(find "$dir/app/node_modules/.pnpm" -path '*/playwright-core/browsers.json' | head -1)
  [[ -n $browsers ]] || die "no playwright-core in the bundle"
  grep -A2 '"name": "chromium",' "$browsers" | grep -q "\"revision\": \"$CHROMIUM_REVISION\"" ||
    die "the bundled Playwright expects another Chromium than $CHROMIUM_REVISION (runtime-pins.sh)"

  echo "$revision" >"$dir/app/REVISION"
  if [[ -n $version ]]; then echo "$version" >"$dir/app/VERSION"; fi
}

if [[ $release -eq 0 ]]; then
  if [[ -e "$out" ]]; then
    [[ -f "$out/.keyflap-bundle" ]] || die "$out exists and is not a bundle"
    rm -rf "$out"
  fi
  build_bundle "$out"
  [[ $dirty -eq 0 ]] || echo "build-bundle: note: the checkout has uncommitted changes; they are in the bundle" >&2
  echo "bundle ready: $out ($(du -sh "$out" | cut -f1))"
  exit 0
fi

# ---- release tarballs -----------------------------------------------------------------
for tool in tar xz sha256sum curl; do
  command -v "$tool" >/dev/null || die "$tool not on PATH"
done
tar --version 2>/dev/null | grep -q 'GNU tar' || die "needs GNU tar (--sort, --mtime)"
if [[ -z $version ]]; then
  tag=$(git -C "$repo" describe --tags --exact-match 2>/dev/null || true)
  if [[ $tag == v* ]]; then version=${tag#v}; else version=0.0.0-dev.${revision:0:12}; fi
fi
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "bad version $version (X.Y.Z[-pre])"
case ${arch_opt:-all} in
  all) archs=(x64 arm64) ;;
  x64|arm64) archs=("$arch_opt") ;;
  *) die "--arch must be x64, arm64 or all" ;;
esac
case ${os_opt:-linux} in
  linux) targets=("${archs[@]/#/linux-}") ;;
  darwin) targets=(darwin-arm64) ;;
  all) targets=("${archs[@]/#/linux-}" darwin-arm64) ;;
  *) die "--os must be linux, darwin or all" ;;
esac
macos=$here/../macos
node_cache=${node_cache:-${XDG_CACHE_HOME:-$HOME/.cache}/keyflap/node}

node_tarball() { # node_tarball OS ARCH -> path of the verified tarball in the cache
  local os=$1 arch=$2 file f
  file=node-v$NODE_VERSION-$os-$arch.tar.xz
  f=$node_cache/$file
  if [[ ! -f $f ]]; then
    mkdir -p "$node_cache"
    echo "downloading $file" >&2
    curl -fsSL --proto '=https' --tlsv1.2 -o "$f.part" "https://nodejs.org/dist/v$NODE_VERSION/$file"
    mv "$f.part" "$f"
  fi
  if ! echo "$(node_sha256 "$os" "$arch")  $f" | sha256sum -c --quiet - >/dev/null 2>&1; then
    rm -f "$f"
    die "$file does not match the pinned SHA-256 (runtime-pins.sh); removed it from the cache"
  fi
  echo "$f"
}

if [[ -e "$out" ]]; then
  [[ -d "$out" ]] || die "$out is not a directory"
  # Only ever replace our own outputs.
  for f in "$out"/* "$out"/.[!.]*; do
    [[ -e $f ]] || continue
    case $(basename "$f") in
      keyflap-*-linux-*.tar.xz|keyflap-*-darwin-*.tar.xz|SHA256SUMS) rm -f "$f" ;;
      *) die "$out holds other files ($(basename "$f")); use an empty or new directory" ;;
    esac
  done
fi
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/keyflap-release.XXXXXX")
trap 'rm -rf "$work"' EXIT

# keyflap-launch for the darwin tarball: --launcher, else a reproducible build from source
# (packages/install/macos/launcher/build.sh, podman or docker).
case " ${targets[*]} " in
  *" darwin-"*)
    if [[ -z $launcher ]]; then
      [[ -x $macos/launcher/build.sh ]] || die "no keyflap-launch: packages/install/macos/launcher/build.sh is missing (pass --launcher FILE)"
      command -v podman >/dev/null || command -v docker >/dev/null ||
        die "building keyflap-launch needs podman or docker (or pass --launcher FILE from a machine that has one)"
    fi
    ;;
esac

build_bundle "$work/bundle"
if [[ -z $launcher ]]; then
  case " ${targets[*]} " in
    *" darwin-"*) "$macos/launcher/build.sh" "$work/launcher" >&2; launcher=$work/launcher/keyflap-launch ;;
  esac
fi
if [[ -n $launcher ]]; then
  [[ $(head -c 4 "$launcher" | od -An -tx1 | tr -d ' \n') == cffaedfe ]] || die "$launcher is not a Mach-O 64-bit program"
fi
files=()
for target in "${targets[@]}"; do
  os=${target%-*}
  arch=${target#*-}
  name=keyflap-$version-$target
  d=$work/$name
  mkdir -p "$d"
  if [[ $os == linux ]]; then
    cp "$here/install.sh" "$here/uninstall.sh" "$here/keyflap-wrapper.sh" "$here/runtime-pins.sh" \
      "$here/progress.sh" "$here/sysusers.conf" "$here/tmpfiles.conf" "$d/"
    cp -r "$here/units" "$d/units"
  else
    cp "$macos/install.sh" "$macos/uninstall.sh" "$macos/keyflap-wrapper.sh" "$here/runtime-pins.sh" \
      "$here/progress.sh" "$macos/install-simple.sh" "$macos/uninstall-simple.sh" "$d/"
    chmod 0755 "$d/install-simple.sh" "$d/uninstall-simple.sh"
    cp -r "$macos/launchd" "$d/launchd"
    cp "$launcher" "$d/keyflap-launch"
    chmod 0755 "$d/keyflap-launch"
  fi
  chmod 0755 "$d/install.sh" "$d/uninstall.sh"
  cp -a "$work/bundle" "$d/bundle"
  cp "$(node_tarball "$os" "$arch")" "$d/"
  cat >"$d/RELEASE" <<EOF
name=keyflap
version=$version
os=$os
arch=$arch
revision=$revision
node=$NODE_VERSION
chromium=$CHROMIUM_REVISION
EOF
  tar --create --file=- --directory="$work" --sort=name --format=gnu \
    --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
    --mode='u+rwX,go+rX,go-w' --hard-dereference "$name" |
    xz -T1 -6 -c >"$out/$name.tar.xz.part"
  mv "$out/$name.tar.xz.part" "$out/$name.tar.xz"
  files+=("$name.tar.xz")
done
(cd "$out" && sha256sum "${files[@]}" >SHA256SUMS)

[[ $dirty -eq 0 ]] || echo "build-bundle: note: the checkout has uncommitted changes; they are in the release" >&2
echo "release $version ready in $out:"
for f in "${files[@]}" SHA256SUMS; do echo "  $(stat -c %s "$out/$f")  $f"; done
