#!/bin/bash
# The simple Mac install: Keyflap for your own account, no admin password (docs/MAC_PLAN.md,
# "Simple Mac install"; docs/integrations/simple-mac-install.md). bash 3.2 and BSD tools.
#
#   ./install-simple.sh            # from an extracted keyflap-V-darwin-arm64 release, as you
#
# It protects less than the full install (./install.sh with sudo), and says so before it
# installs anything. As you, it puts the code, a pinned Node 22 and Playwright's headless
# Chromium in ~/Library/Application Support/Keyflap, with the keyflap command in its bin/.
# Run that command's `setup` next (the one-command install does): it pairs your phone, adds
# your agent, and starts the broker as the LaunchAgent com.keyflap.simple. The key store lives
# in ~/.keyflap and unlocks from the key file ~/.keyflap/unlock.key (0600), so the broker
# starts at login without a passphrase. Re-running it upgrades the code and keeps the data.
#
# --confirmed: the person already read the "protects less" notice and said yes (the
# one-command install asks before it downloads anything).
set -euo pipefail
umask 022

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
die() { echo "install-simple: $*" >&2; exit 1; }
step() { echo "==> $*"; }

full_install='curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | sudo bash'

[[ $(id -u) -ne 0 ]] || die "the simple install runs as you, without sudo: run it again without sudo.
For the full install, which does need sudo: $full_install"

# shellcheck source=../linux/runtime-pins.sh
source "$here/runtime-pins.sh"

confirmed=0 bundle='' browsers_dir=''
while [[ $# -gt 0 ]]; do
  case $1 in
    --confirmed) confirmed=1; shift ;;
    --bundle) bundle=${2:?}; shift 2 ;;
    --browsers-dir) browsers_dir=${2:?}; shift 2 ;;
    -h|--help) sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

label=com.keyflap.simple
app="$HOME/Library/Application Support/Keyflap"
data="$HOME/.keyflap"
plist="$HOME/Library/LaunchAgents/$label.plist"
uid=$(id -u)

problems=()
problem() { problems[${#problems[@]}]=$*; }

[[ $(uname -s) == Darwin ]] || die "the simple install is for macOS; on Linux use the full install: $full_install"
arch=$(uname -m)
[[ $arch == arm64 ]] || problem "this Mac is $arch: Keyflap supports Apple silicon (arm64) only; Intel Macs are not supported yet"
if [[ -f $here/RELEASE ]]; then
  release_os=$(sed -n 's/^os=//p' "$here/RELEASE")
  release_arch=$(sed -n 's/^arch=//p' "$here/RELEASE")
  release_version=$(sed -n 's/^version=//p' "$here/RELEASE")
  if [[ ${release_os:-} != darwin || $release_arch != arm64 ]]; then
    problem "this release is for ${release_os:-linux}-$release_arch, not macOS on Apple silicon: download keyflap-$release_version-darwin-arm64.tar.xz"
  fi
fi
macos=$(sw_vers -productVersion 2>/dev/null || echo 0)
[[ ${macos%%.*} -ge 14 ]] || problem "macOS $macos is too old: Keyflap needs macOS 14 or later (tested on 26)"
for tool in launchctl plutil shasum xattr tar; do
  command -v "$tool" >/dev/null || problem "$tool not found (part of macOS)"
done
if [[ -f /Library/LaunchDaemons/com.keyflap.core.plist ]]; then
  problem "the full install is already on this Mac (/Library/LaunchDaemons/com.keyflap.core.plist); the simple one would run a second broker next to it. Use the full install: sudo keyflap status"
fi
[[ -z $bundle && -f $here/bundle/.keyflap-bundle ]] && bundle=$here/bundle
if [[ -z $bundle || ! -f $bundle/.keyflap-bundle || ! -f $bundle/app/packages/cli/src/main.ts ]]; then
  problem "no bundle: run this from an extracted release tarball, or pass --bundle DIR (build-bundle.sh output)"
fi
node_file=node-v$NODE_VERSION-darwin-arm64.tar.xz
[[ -f $here/$node_file ]] || command -v curl >/dev/null ||
  problem "curl not found: needed to download Node $NODE_VERSION"
if [[ -n $browsers_dir && ! -d $browsers_dir/chromium_headless_shell-$CHROMIUM_REVISION ]]; then
  problem "--browsers-dir $browsers_dir has no chromium_headless_shell-$CHROMIUM_REVISION"
fi
if [[ -f $data/signer/keys.enc.json && ! -e $data/unlock.key ]]; then
  problem "$data already holds a key store that a passphrase unlocks (from keyflap daemon --unprotected). The simple install unlocks with a key file instead. Move it away first (mv ~/.keyflap ~/.keyflap.dev) and run this again"
fi
if [[ ${#problems[@]} -gt 0 ]]; then
  for p in "${problems[@]}"; do echo "install-simple: $p" >&2; done
  exit 1
fi

if [[ $confirmed -eq 0 ]]; then
  { : </dev/tty; } 2>/dev/null || die "it needs a terminal to ask you first"
  cat >/dev/tty <<EOF

Keyflap, the simple install (no admin password).

The simple install protects less: an agent that can run commands as you can read Keyflap's files and change its code. The full install stops that.

It runs as you, from ~/Library/Application Support/Keyflap, and keeps its keys in ~/.keyflap,
unlocked by a key file there. The full install needs your admin password once:
  $full_install

EOF
  printf 'Install the simple version anyway? [y/N]: ' >/dev/tty
  IFS= read -r answer </dev/tty || answer=''
  case $answer in
    y|Y|yes) ;;
    *) echo "Stopped. Nothing was installed."; exit 1 ;;
  esac
fi

filevault=$(fdesetup status 2>/dev/null || echo unknown)

q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
dequarantine() { xattr -r -d com.apple.quarantine "$1" 2>/dev/null || true; }

step "installing into $app"
install -d -m 0700 "$app"
stage=$(mktemp -d "$app/.stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

cp -R "$bundle/app" "$stage/app"
dequarantine "$stage/app"
while IFS= read -r link; do
  [[ -n $link ]] || continue
  target=$(readlink -f "$link" || true)
  [[ $target == "$stage/app/"* ]] || die "bundle symlink points outside the app: ${link#"$stage/"}"
done < <(find "$stage/app" -type l)

if [[ -f $here/$node_file ]]; then
  cp "$here/$node_file" "$stage/node.tar.xz"
else
  step "downloading Node $NODE_VERSION (darwin-arm64)"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$stage/node.tar.xz" "https://nodejs.org/dist/v$NODE_VERSION/$node_file"
fi
dequarantine "$stage/node.tar.xz"
sum=$(shasum -a 256 "$stage/node.tar.xz" | cut -d' ' -f1)
[[ $sum == "$(node_sha256 darwin arm64)" ]] || die "Node tarball checksum mismatch (expected $node_file)"
mkdir "$stage/node"
tar -xJf "$stage/node.tar.xz" -C "$stage/node" --strip-components=1
rm -f "$stage/node.tar.xz"
dequarantine "$stage/node"
"$stage/node/bin/node" --version | grep -q '^v22\.' || die "the runtime is not Node 22"

shell_dir=chromium_headless_shell-$CHROMIUM_REVISION
new_browsers=0
if [[ ! -d $app/browsers/$shell_dir ]]; then
  new_browsers=1
  if [[ -n $browsers_dir ]]; then
    mkdir "$stage/browsers"
    cp -R "$browsers_dir/$shell_dir" "$stage/browsers/"
  else
    step "downloading Chromium $CHROMIUM_REVISION (Playwright's headless shell)"
    PLAYWRIGHT_BROWSERS_PATH=$stage/browsers "$stage/node/bin/node" \
      "$stage/app/packages/shim/node_modules/playwright/cli.js" install --only-shell chromium >/dev/null
  fi
  dequarantine "$stage/browsers"
fi

mkdir "$stage/bin"
cat >"$stage/bin/keyflap" <<EOF
#!/bin/sh
KEYFLAP_MODE=simple
PLAYWRIGHT_BROWSERS_PATH=$(q "$app/browsers")
export KEYFLAP_MODE PLAYWRIGHT_BROWSERS_PATH
exec $(q "$app/node/bin/node") --disable-warning=ExperimentalWarning $(q "$app/app/packages/cli/src/main.ts") "\$@"
EOF
chmod 0755 "$stage/bin/keyflap"
install -m 0755 "$here/uninstall-simple.sh" "$stage/uninstall.sh"
chmod -R go-w "$stage"

was_loaded=0
if launchctl print "gui/$uid/$label" >/dev/null 2>&1; then
  was_loaded=1
  step "stopping the running broker"
  launchctl bootout "gui/$uid/$label" 2>/dev/null || true
  for ((i = 0; i < 80; i++)); do
    launchctl print "gui/$uid/$label" >/dev/null 2>&1 || break
    sleep 0.5
  done
fi

parts=(app node bin)
[[ $new_browsers -eq 0 ]] || parts[${#parts[@]}]=browsers
for part in "${parts[@]}"; do
  rm -rf "${app:?}/$part.old"
  [[ ! -e $app/$part ]] || mv "$app/$part" "$app/$part.old"
  mv "$stage/$part" "$app/$part"
done
mv "$stage/uninstall.sh" "$app/uninstall.sh"
for part in "${parts[@]}"; do rm -rf "${app:?}/$part.old"; done

if [[ $was_loaded -eq 1 && -f $plist ]]; then
  step "starting it again"
  launchctl bootstrap "gui/$uid" "$plist" || die "launchctl bootstrap gui/$uid $plist failed: see ~/Library/Logs/Keyflap/daemon.log"
fi

if [[ $filevault != *On* ]]; then
  cat <<EOF

note: FileVault is off ($filevault). Keyflap's key file and key store are files in your home
folder; whoever has the disk can read them. Turn FileVault on: System Settings > Privacy &
Security > FileVault.
EOF
fi
if [[ $confirmed -eq 1 ]]; then
  echo "Installed Keyflap ${release_version:-} (simple install) in $app."
  exit 0
fi
cat <<EOF

Installed Keyflap ${release_version:-} (simple install) in $app.

The simple install protects less: an agent that can run commands as you can read Keyflap's files and change its code. The full install stops that.

Next, the guided setup (pair your phone, add your agent, start Keyflap in the background):
  $(q "$app/bin/keyflap") setup
To remove it: $(q "$app/uninstall.sh") [--purge]
EOF
