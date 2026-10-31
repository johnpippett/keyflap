#!/usr/bin/env bash
# Writes the one-command installer for a release: DIST_DIR/install-keyflap.sh, from
# install-keyflap.sh.in, with the SHA-256 of each of the release's tarballs pinned inside and
# ../linux/progress.sh (the progress view install.sh shares) copied in.
#
#   packages/install/bootstrap/make-bootstrap.sh DIST_DIR VERSION
#
# DIST_DIR holds the release (build-bundle.sh --release output): keyflap-VERSION-OS-ARCH.tar.xz
# and SHA256SUMS. Each tarball SHA256SUMS lists must be in DIST_DIR with that hash. It then adds
# install-keyflap.sh's own line to SHA256SUMS, so the release attestation (subject-checksums:
# SHA256SUMS) covers the installer too: run it after the last tarball and before attesting.
# Running it again gives the same file. Bash 3.2 and BSD tools are enough.
set -euo pipefail

die() { echo "make-bootstrap: $*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: make-bootstrap.sh DIST_DIR VERSION"
dist=$1 version=$2
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
template=$here/install-keyflap.sh.in
progress=$here/../linux/progress.sh
semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
[[ $version =~ $semver ]] || die "bad version $version (X.Y.Z[-pre])"
[ -d "$dist" ] || die "$dist is not a directory"
sums=$dist/SHA256SUMS
[ -f "$sums" ] || die "no SHA256SUMS in $dist"

sha256_of() {
  local out
  if command -v sha256sum >/dev/null 2>&1; then out=$(sha256sum "$1"); else out=$(shasum -a 256 "$1"); fi
  printf '%s' "${out%% *}"
}

line_re='^([0-9a-f]{64}) [ *](.+)$'
pins='' count=0
while IFS= read -r line || [ -n "$line" ]; do
  [ -n "$line" ] || continue
  [[ $line =~ $line_re ]] || die "SHA256SUMS: not a checksum line: $line"
  hash=${BASH_REMATCH[1]} file=${BASH_REMATCH[2]}
  case $file in
    install-keyflap.sh) continue ;;
    keyflap-"$version"-darwin-arm64.tar.xz) key=darwin-arm64 ;;
    keyflap-"$version"-linux-x64.tar.xz) key=linux-x64 ;;
    keyflap-"$version"-linux-arm64.tar.xz) key=linux-arm64 ;;
    keyflap-*.tar.xz) die "SHA256SUMS lists $file, which is not a $version tarball this installer knows" ;;
    *) continue ;;
  esac
  [ -f "$dist/$file" ] || die "SHA256SUMS lists $file, but it is not in $dist"
  [ "$(sha256_of "$dist/$file")" = "$hash" ] || die "$dist/$file does not match its SHA256SUMS line"
  case $pins in *"    $key)"*) die "SHA256SUMS lists $file twice" ;; esac
  pins="$pins    $key) echo $hash ;;
"
  count=$((count + 1))
done <"$sums"
[ $count -gt 0 ] || die "SHA256SUMS lists no keyflap-$version-*.tar.xz"

out=$dist/install-keyflap.sh
tmp=$out.tmp.$$
trap 'rm -f "$tmp" "$sums.tmp.$$"' EXIT
pins_file=$tmp.pins
printf '%s' "$pins" >"$pins_file"
sed "s/@KEYFLAP_VERSION@/$version/g" "$template" |
  awk -v pins="$pins_file" -v progress="$progress" '
    $0 == "@KEYFLAP_PINS@" { while ((getline l < pins) > 0) print l; next }
    $0 == "@KEYFLAP_PROGRESS@" { while ((getline l < progress) > 0) print l; next }
    { print }
  ' >"$tmp"
rm -f "$pins_file"
if grep -q '@KEYFLAP_' "$tmp"; then die "a placeholder is left in the output"; fi
bash -n "$tmp" || die "the generated installer does not parse"
chmod 0644 "$tmp"
mv "$tmp" "$out"

{
  grep -v '[ *]install-keyflap\.sh$' "$sums" || true
  printf '%s  install-keyflap.sh\n' "$(sha256_of "$out")"
} >"$sums.tmp.$$"
mv "$sums.tmp.$$" "$sums"
echo "wrote $out (Keyflap $version, $count tarball(s) pinned) and added it to $sums"
