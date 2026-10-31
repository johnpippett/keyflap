#!/usr/bin/env bash
# Runs the isolation suite on a Mac, from Linux. The Mac side needs an admin account with
# passwordless sudo (sudo -n), Node 22 and network access for pnpm; it installs Keyflap for real
# (as root, from the darwin release built here), probes it as a hidden third uid, and purges it
# at the end. Never point this at a Mac whose Keyflap install you want to keep.
#
#   KEYFLAP_MAC=user@host packages/isolation/darwin/run-on-mac.sh [vitest args…]
#
#   KEYFLAP_MAC_SSH_OPTS   extra ssh options, e.g. "-i ~/.ssh/key -o IdentitiesOnly=yes"
#   KEYFLAP_MAC_PATH       prepended to PATH on the Mac (default: $HOME/.local/node/bin there)
#   KEYFLAP_MAC_DIR        where the checkout goes on the Mac (default /Users/Shared/keyflap-isolation:
#                          the probe uid must be able to read the probe scripts, and home
#                          directories are closed to other users on macOS)
#   KEYFLAP_MAC_CLEAN=1    remove that directory on the Mac afterwards
#
# Why build here: build-bundle.sh --release needs GNU tar and podman or docker (keyflap-launch is
# cross-built in a pinned container), which a stock Mac doesn't have.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
mac=${KEYFLAP_MAC:?set KEYFLAP_MAC=user@host}
read -r -a ssh_opts <<<"${KEYFLAP_MAC_SSH_OPTS:-}"
remote=${KEYFLAP_MAC_DIR:-/Users/Shared/keyflap-isolation}
remote_path=${KEYFLAP_MAC_PATH:-\$HOME/.local/node/bin}
pnpm_version=$(sed -n 's/.*"packageManager": "pnpm@\([^"]*\)".*/\1/p' "$repo/package.json")
[[ -n $pnpm_version ]] || { echo "run-on-mac: no packageManager pnpm version in package.json" >&2; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/keyflap-mac-isolation.XXXXXX")
trap 'rm -rf "$work"' EXIT
"$repo/packages/install/linux/build-bundle.sh" --release "$work/artifacts/release" --os darwin \
  --version 0.0.0-isolation >&2
"$repo/packages/install/linux/build-bundle.sh" "$work/artifacts/bundle" >&2

ssh_cmd=(ssh "${ssh_opts[@]}" "$mac")
rsh="ssh ${ssh_opts[*]}"
"${ssh_cmd[@]}" "mkdir -p '$remote/repo' '$remote/artifacts' && chmod 0755 '$remote' '$remote/repo' '$remote/artifacts'"
rsync -a --delete --exclude node_modules --exclude .git --filter=':- .gitignore' -e "$rsh" \
  "$repo/" "$mac:$remote/repo/"
rsync -a --delete -e "$rsh" "$work/artifacts/" "$mac:$remote/artifacts/"

args=$(printf '%q ' "$@")
status=0
"${ssh_cmd[@]}" "set -e; export PATH=$remote_path:\$PATH; cd '$remote/repo'
  npx --yes pnpm@$pnpm_version install --frozen-lockfile --reporter=silent
  npx --yes pnpm@$pnpm_version --filter @aab/shim exec playwright install chromium chromium-headless-shell
  KEYFLAP_ISOLATION_ARTIFACTS='$remote/artifacts' KEYFLAP_ISOLATION_REQUIRED=1 KEYFLAP_ISOLATION_KEEP=${KEYFLAP_ISOLATION_KEEP:-0} \
    npx --yes pnpm@$pnpm_version exec vitest run --config packages/isolation/vitest.config.ts $args" || status=$?
if [[ ${KEYFLAP_MAC_CLEAN:-0} == 1 ]]; then "${ssh_cmd[@]}" "rm -rf '$remote'"; fi
exit $status
