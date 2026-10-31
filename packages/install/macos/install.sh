#!/bin/bash
# Installs (or upgrades) the Keyflap broker in service mode on an Apple silicon Mac.
# docs/MAC_PLAN.md (design), docs/ISOLATION_PLAN.md (D1-D6) and
# docs/integrations/service-mode.md (how to). bash 3.2 and BSD tools: nothing beyond macOS.
#
#   sudo ./install.sh --approver-origin https://HOST:8766 [options]      # from a release tarball
#   sudo packages/install/macos/install.sh --bundle DIR --launcher FILE --approver-origin … [options]
#
# What it does, all as root:
#   - checks the machine first (Apple silicon, macOS 14+, tools, inputs) and changes nothing
#     if a check fails; reports FileVault off but does not refuse;
#   - hidden system users _keyflap-core, _keyflap-signer and _keyflap-web (dscl; uid < 500, no
#     shell, no password; `keyflap-core` etc. as a second name), set up idempotently: on a
#     re-run only missing attributes are added and a mismatch is an error (TCC forbids
#     re-setting them);
#   - root-owned code and runtime in /opt/keyflap: the bundle copied with fresh root-owned
#     inodes, a pinned Node 22 (checksum-verified), Playwright's Chromium 1248 (the full
#     browser; it runs headless with its own sandbox on), and keyflap-launch, the small program
#     that hands launchd's sockets to each service the way systemd does. The quarantine
#     attribute is stripped from every copy before anything in it runs: Gatekeeper blocks a
#     quarantined binary for good once it tried to exec;
#   - secrets as 0400 files owned by the service that reads them, under
#     /Library/Keyflap/credentials/<service>/ (CREDENTIALS_DIRECTORY in each plist): the
#     key-store KEK (D1), the signer channel key (one copy each for the signer and the core)
#     and the host token. A plain copy of the host token goes to /Library/Keyflap/hook for the
#     owner's Claude Code hook. At rest they are protected by FileVault;
#   - /Library/Keyflap/etc/{core,signer,approver}.json, the three LaunchDaemons
#     (com.keyflap.{signer,core,approver}), their sockets (owners and modes as on Linux),
#     per-service log and tmp directories, /usr/local/bin/keyflap (a wrapper that runs node
#     with a clean environment: macOS sudo keeps HOME and has no secure_path).
# On a terminal it shows progress (progress.sh) and a short summary, and writes the detail to
# /Library/Keyflap/log/install.log (root, 0600); elsewhere it prints the plain `==>` lines.
# Nothing secret is printed or logged. Re-running upgrades the code and keeps the key store, its KEK,
# the channel key and the database, then restarts the services.
#
# Everything root runs or installs from must be root-only: this script's directory (and the
# bundle, Node tarball or browsers directory it is pointed at) is refused if anyone but root
# could change it, because a copy under your home (or an agent running as you) could be
# edited between your check and this run.
set -euo pipefail
umask 022

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
die() {
  if [[ ${pg_active:-0} -eq 1 ]]; then progress_fail "install: $*"; else echo "install: $*" >&2; fi
  exit 1
}
[[ $(id -u) -eq 0 ]] || die "run as root (sudo)"

prefix=/opt/keyflap
etc=/Library/Keyflap/etc
creds=/Library/Keyflap/credentials
data=/Library/Keyflap/data
hook=/Library/Keyflap/hook
run=/Library/Keyflap/run
logs=/Library/Keyflap/log
daemons=/Library/LaunchDaemons
wrapper=/usr/local/bin/keyflap

# chain_problem PATH: the first thing on the way to PATH (a parent directory, or PATH itself)
# that someone other than root could change, or nothing.
chain_problem() {
  local real d uid mode
  real=$(readlink -f "$1" 2>/dev/null) || { echo "$1 (cannot be resolved)"; return 0; }
  [[ -e $real ]] || { echo "$1 (does not exist)"; return 0; }
  d=$real
  while :; do
    uid=$(stat -f %u "$d")
    mode=$(stat -f %Lp "$d")
    if [[ $uid != 0 ]]; then echo "$d (owned by uid $uid)"; return 0; fi
    if (( (8#$mode & 8#022) != 0 )); then echo "$d (mode $mode: writable by group or others)"; return 0; fi
    [[ $d == / ]] && break
    d=$(dirname "$d")
  done
}

# not_root_only PATH: chain_problem, and for a directory anything inside it.
not_root_only() {
  local real bad
  bad=$(chain_problem "$1")
  if [[ -n $bad ]]; then echo "$bad"; return 0; fi
  real=$(readlink -f "$1")
  if [[ -d $real ]]; then
    bad=$(find "$real" ! -type l \( ! -user 0 -o -perm -g+w -o -perm -o+w \) -print 2>/dev/null | head -1)
    if [[ -n $bad ]]; then echo "$bad (not root-owned, or writable by group or others)"; return 0; fi
  fi
}

quarantined() { xattr -p com.apple.quarantine "$1" >/dev/null 2>&1; }

# tool_problem PATH COMMAND: why the signer would refuse to run PATH as COMMAND, or nothing.
# The same rules as @aab/sources tool.ts, which install-config.ts and the signer apply too.
tool_problem() {
  local p=$1 cmd=$2 real bad
  [[ $p == /* ]] || { echo "$p is not an absolute path"; return 0; }
  [[ -f $p ]] || { echo "$p does not exist"; return 0; }
  real=$(readlink -f "$p")
  [[ $real == "$p" ]] || { echo "$p is a symbolic link (or has one on the way) to $real"; return 0; }
  case $(dirname "$p") in
    /usr/bin|/usr/local/bin|/usr/sbin|/usr/local/sbin|/bin|/sbin) ;;
    "$prefix/tools/$cmd"|"$prefix/tools/$cmd"/*) ;;
    *) echo "$p is not in a system bin directory or $prefix/tools/$cmd/"; return 0 ;;
  esac
  bad=$(not_root_only "$p")
  [[ -z $bad ]] || { echo "$bad: someone other than root could replace $cmd"; return 0; }
  (( (8#$(stat -f %p "$p") & 8#6000) == 0 )) || { echo "$p has a setuid/setgid bit"; return 0; }
  [[ -x $p ]] || { echo "$p is not executable"; return 0; }
  if quarantined "$p"; then
    echo "$p carries com.apple.quarantine (a browser download); Gatekeeper would block the signer running it: sudo xattr -d com.apple.quarantine $p"
  fi
}

# pick_tool COMMAND PATH...: sets picked to the first existing PATH the signer would run as
# COMMAND (tool_problem prints nothing), or to nothing, and refusals to why each one before it
# was refused.
pick_tool() {
  local cmd=$1 c bad
  shift
  picked='' refusals=''
  for c in "$@"; do
    [[ -e $c ]] || continue
    bad=$(tool_problem "$c" "$cmd")
    if [[ -z $bad ]]; then picked=$c; return 0; fi
    refusals="$refusals
      refused: $bad"
  done
}

# The standalone Tailscale app's CLI reaches tailscaled through the app over XPC, and a
# LaunchDaemon has no app to go through: every read as _keyflap-signer timed out. Its tailscaled
# also answers on loopback at the port in $tailscale_dir/ipnport, to whoever sends the token in
# sameuserproof-PORT next to it. The signer reads the serve setting there instead, and this script
# lets _keyflap-signer read the token (an ACL entry) without changing anything else of Tailscale's.
tailscale_dir=/Library/Tailscale
tailscale_candidates=(/usr/bin/tailscale /usr/sbin/tailscale /usr/local/bin/tailscale)
signer_token_ace='user:_keyflap-signer allow read'

# localapi_problem DIR: why the signer would refuse to read tailscaled's port and token from DIR,
# or nothing. The same rules as the signer's tailscale-localapi.ts.
localapi_problem() {
  local d=$1 bad port
  [[ $(readlink -f "$d" 2>/dev/null) == "$d" ]] ||
    { echo "$d is a symbolic link (or has one on the way)"; return 0; }
  bad=$(chain_problem "$d")
  [[ -z $bad ]] || { echo "$bad: someone other than root could change it"; return 0; }
  [[ $(stat -f %u "$d/ipnport") == 0 ]] || { echo "$d/ipnport is not owned by root"; return 0; }
  port=$(readlink "$d/ipnport")
  [[ $port =~ ^[1-9][0-9]{0,4}$ ]] || echo "$d/ipnport does not name a port"
}

# choose_tailscale: sets tailscale_localapi to the directory the signer reads tailscaled's port
# and token from, or tailscale_bin to the tailscale it runs; reports what stands in the way
# through problem.
choose_tailscale() {
  tailscale_localapi=''
  [[ -n $tailscale_bin || $origin_host == *.ts.net ]] || return 0
  local bad
  if [[ -z $tailscale_bin && -L $tailscale_dir/ipnport ]]; then
    tailscale_localapi=$tailscale_dir
    bad=$(localapi_problem "$tailscale_dir")
    [[ -z $bad ]] || problem "the signer would refuse to read Tailscale's setting: $bad.
    Reinstall the standalone Tailscale app (tailscale.com/download), or pass --tailscale-bin PATH"
    return 0
  fi
  if [[ -z $tailscale_bin ]]; then
    pick_tool tailscale "${tailscale_candidates[@]}"
    tailscale_bin=$picked
    if [[ -z $tailscale_bin ]]; then
      problem "the signer can't read Tailscale's serve setting: no $tailscale_dir/ipnport, and no
    tailscale it can run in /usr/bin, /usr/sbin or /usr/local/bin.$refusals
    The signer checks that $origin still points at the approver. The App Store Tailscale app keeps
    that setting where a background service can't read it. Install the standalone Tailscale app
    (tailscale.com/download) or open-source tailscaled, start it and connect, then run this again;
    or pass --tailscale-bin PATH"
      return 0
    fi
  fi
  bad=$(tool_problem "$tailscale_bin" tailscale)
  [[ -z $bad ]] || problem "the signer would refuse tailscale: $bad.
    Install Tailscale as root (tailscale.com/download, never a copy from your home or Homebrew) and pass
    --tailscale-bin /usr/local/bin/tailscale"
}

# drop_signer_aces PATH: removes every ACL entry for _keyflap-signer on PATH, set directly or
# inherited, and no other entry.
drop_signer_aces() {
  local i
  for i in $(ls -led "$1" 2>/dev/null | sed -n 's/^ *\([0-9][0-9]*\): user:_keyflap-signer .*/\1/p' | sort -rn); do
    chmod -a# "$i" "$1"
  done
}

# grant_tailscale_token DIR: lets _keyflap-signer read tailscaled's current token in DIR, and each
# one tailscaled writes there later (it writes a new one when it restarts).
grant_tailscale_token() {
  local d=$1 proof
  proof=$d/sameuserproof-$(readlink "$d/ipnport")
  drop_signer_aces "$d"
  chmod +a "$signer_token_ace,file_inherit,only_inherit" "$d"
  if [[ -f $proof ]]; then
    drop_signer_aces "$proof"
    chmod +a "$signer_token_ace" "$proof"
  fi
  if ! sudo -u _keyflap-signer /bin/test -r "$proof"; then
    echo "note: _keyflap-signer can't read $proof yet, so approvals stay paused until it can. Start
Tailscale and run this again, or check: sudo keyflap doctor" >&2
    progress_warn "Approvals stay paused until Keyflap can read Tailscale's token: start Tailscale and run this again."
  fi
}

# The installer itself first: a copy your user can change is not one to run as root (M4).
bad=$(not_root_only "$here")
if [[ -n $bad ]]; then
  die "refusing to run from $here: $bad.
  Anything your user (or an agent running as you) can change could be edited before root runs it.
  Copy the release to a directory only root can change, check it there, and run it from there:
    sudo install -d -m 0755 /opt/keyflap-release
    sudo install -m 0644 keyflap-VERSION-darwin-arm64.tar.xz SHA256SUMS /opt/keyflap-release/
    (verify /opt/keyflap-release/keyflap-VERSION-darwin-arm64.tar.xz: docs/integrations/service-mode.md)
    sudo tar -xJf /opt/keyflap-release/keyflap-VERSION-darwin-arm64.tar.xz -C /opt/keyflap-release
    sudo /opt/keyflap-release/keyflap-VERSION-darwin-arm64/install.sh …"
fi
# A release has runtime-pins.sh next to this script; the source tree keeps it in ../linux.
pins=$here/runtime-pins.sh
[[ -f $pins ]] || pins=$here/../linux/runtime-pins.sh
bad=$(not_root_only "$pins")
[[ -z $bad ]] || die "refusing to read $pins: $bad"
# shellcheck source=../linux/runtime-pins.sh
source "$pins"
progress=$here/progress.sh
[[ -f $progress ]] || progress=$here/../linux/progress.sh
bad=$(not_root_only "$progress")
[[ -z $bad ]] || die "refusing to read $progress: $bad"
# shellcheck source=../linux/progress.sh
source "$progress"

usage() {
  cat <<'EOF'
usage: sudo ./install.sh --approver-origin URL [options]        (from a release tarball)
       sudo install.sh --bundle DIR --launcher FILE --approver-origin URL [options]  (source build)

  --approver-origin URL     https origin of the phone approver page (required, D5)
  --bundle DIR              output of packages/install/linux/build-bundle.sh (default: the
                            bundle/ next to this script, as in a release tarball)
  --launcher FILE           keyflap-launch, the launchd socket handover program (default: the
                            one next to this script, as in a release tarball)
  --user NAME               the person whose agents use the broker (default: $SUDO_USER);
                            only this user can reach the intent socket
  --approver-listen IP:P    approver listener (default 127.0.0.1:8766, behind e.g.
                            `tailscale serve`); held by launchd for the approver page. With
                            127.0.0.1, launchd holds [::1]:P too
  --tailscale-bin PATH      the tailscale CLI the signer runs (`tailscale serve status`) to check
                            that the approver origin still points at the approver listener; it
                            must be root-only. Default when the origin is a *.ts.net name: with
                            the standalone Tailscale app, no CLI: the signer asks its tailscaled
                            over loopback (the port in /Library/Tailscale/ipnport), and this
                            script lets _keyflap-signer read the token next to it (an ACL entry).
                            Else the first of /usr/bin, /usr/sbin or /usr/local/bin that is
                            root-only. The App Store Tailscale app can't be read this way
  --tls-cert FILE --tls-key FILE
                            serve the approver page with this certificate instead
  --apns-key FILE --apns-key-id ID --apns-team-id ID --apns-bundle-id ID
    [--apns-sandbox] [--apns-generic]
                            push to the Keyflap iOS app through APNs (docs/integrations/
                            ios-app.md); the .p8 key becomes a core credential
  --mcp-port N              MCP endpoint on 127.0.0.1:N (default 8765)
  --high-risk DOMAIN        always needs phone approval with user verification (repeatable)
  --password-source proton-pass [--proton-pass-vault NAME] [--proton-pass-bin PATH]
                            also offer Proton Pass logins. The signer runs pass-cli only from a
                            root-only path: /opt/keyflap/tools/pass-cli/, /usr/local/bin or
                            /usr/bin (searched in that order without PATH); its SHA-256 is
                            pinned (sudo keyflap password-source trust pass-cli
                            after updates)
  --password-source 1password [--1password-vault NAME] [--op-bin PATH] [--op-token-file FILE]
                            also offer 1Password logins through a service account. op is run only
                            from a root-only path, like pass-cli (/opt/keyflap/tools/op/,
                            /usr/local/bin or /usr/bin; trust op after updates). The token (FILE,
                            or a no-echo prompt) becomes a credential only the signer reads;
                            an upgrade keeps it unless FILE is given
  --password-source none    disconnect the password manager. Without --password-source an upgrade
                            keeps the one already connected, with its tool, pin, vault and token
                            (connect or change one without re-installing: sudo keyflap
                            password-source add proton-pass|1password)
  --ephemeral-browser       don't save the agents' browser sessions across restarts
  --node-tarball FILE       use this node-v22.23.4-darwin-arm64.tar.xz (still checksum-verified;
                            default: the one in the release tarball, else download it)
  --node-dir DIR            copy this Node 22 install instead (offline/tests; you vouch for it)
  --browsers-dir DIR        copy Playwright's chromium-1248 from DIR instead of downloading
                            (offline/tests; you vouch for it)
  --no-start                install everything but don't start the services (they start at
                            the next boot, or: sudo launchctl bootstrap system /Library/LaunchDaemons/com.keyflap.NAME.plist)

The managed browser is headless on macOS (a background service has no display; human checks
go to the live view on your phone). Re-running upgrades: pass the same options again (the
configuration is rewritten from them).
EOF
}

bundle='' launcher='' user=${SUDO_USER:-} origin='' listen='' tls_cert='' tls_key='' mcp_port=''
apns_key='' apns_key_id='' apns_team_id='' apns_bundle_id='' apns_sandbox=0 apns_generic=0
high_risk=() password_source='' no_password_source=0 pp_vault='' pp_vault_set=0 pp_bin=''
op_vault='' op_vault_set=0 op_bin='' op_token_file='' tailscale_bin=''
node_tarball='' node_dir='' browsers_dir='' start=1 ephemeral=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --bundle) bundle=${2:?}; shift 2 ;;
    --launcher) launcher=${2:?}; shift 2 ;;
    --user) user=${2:?}; shift 2 ;;
    --approver-origin) origin=${2:?}; shift 2 ;;
    --approver-listen) listen=${2:?}; shift 2 ;;
    --tls-cert) tls_cert=${2:?}; shift 2 ;;
    --tls-key) tls_key=${2:?}; shift 2 ;;
    --mcp-port) mcp_port=${2:?}; shift 2 ;;
    --apns-key) apns_key=${2:?}; shift 2 ;;
    --apns-key-id) apns_key_id=${2:?}; shift 2 ;;
    --apns-team-id) apns_team_id=${2:?}; shift 2 ;;
    --apns-bundle-id) apns_bundle_id=${2:?}; shift 2 ;;
    --apns-sandbox) apns_sandbox=1; shift ;;
    --apns-generic) apns_generic=1; shift ;;
    --high-risk) high_risk[${#high_risk[@]}]=${2:?}; shift 2 ;;
    --password-source) password_source=${2:?}; shift 2 ;;
    --proton-pass-vault) pp_vault=${2?}; pp_vault_set=1; shift 2 ;;
    --proton-pass-bin) pp_bin=${2:?}; shift 2 ;;
    --1password-vault) op_vault=${2?}; op_vault_set=1; shift 2 ;;
    --op-bin) op_bin=${2:?}; shift 2 ;;
    --op-token-file) op_token_file=${2:?}; shift 2 ;;
    --tailscale-bin) tailscale_bin=${2:?}; shift 2 ;;
    --node-tarball) node_tarball=${2:?}; shift 2 ;;
    --node-dir) node_dir=${2:?}; shift 2 ;;
    --browsers-dir) browsers_dir=${2:?}; shift 2 ;;
    --ephemeral-browser) ephemeral=1; shift ;;
    --no-start) start=0; shift ;;
    --xvfb|--headless) die "$1 is Linux-only: the managed browser is always headless on macOS" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option $1" ;;
  esac
done

if [[ $password_source == none ]]; then password_source=''; no_password_source=1; fi

# read_kept_source NODE CONFIG: the password manager an earlier install (or `keyflap
# password-source add`) left in CONFIG, as kept_kind (proton-pass|1password), kept_bin,
# kept_sha (its pin) and kept_vault. All empty when there is none.
read_kept_source() {
  kept_kind='' kept_bin='' kept_sha='' kept_vault=''
  [[ -f $2 ]] || return 0
  local line
  [[ -x $1 ]] || die "cannot read the password manager connected in $2: there is no Node at $1. Say what you want with --password-source proton-pass, 1password or none."
  line=$("$1" -e '
    const s = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).sources ?? {};
    const [kind, e] = s.protonPass ? ["proton-pass", s.protonPass] : s.onePassword ? ["1password", s.onePassword] : [];
    if (!e) process.exit(0);
    const f = [kind, e.bin, e.sha256 ?? "-", e.vault ?? ""];
    if (f.some((v) => typeof v !== "string" || /[\t\r\n]/.test(v))) process.exit(3);
    process.stdout.write(f.join("\t"));
  ' "$2" 2>/dev/null) || die "cannot read the password manager connected in $2 (the file is not valid, or names a tool in a form this installer will not carry over). Say what you want with --password-source proton-pass, 1password or none."
  [[ -n $line ]] || return 0
  IFS=$'\t' read -r kept_kind kept_bin kept_sha kept_vault <<<"$line"
  [[ $kept_sha != - ]] || kept_sha=''
}

# keep_password_source NODE CONFIG: an upgrade keeps the password manager connected earlier (here,
# or with `keyflap password-source add`): its tool, pin, vault, token and drop-in. An explicit
# --password-source overrides it; --password-source none disconnects it.
keep_password_source() {
  kept_source=0
  [[ -z $password_source && $no_password_source -eq 0 ]] || return 0
  read_kept_source "$1" "$2"
  [[ -n $kept_kind ]] || return 0
  kept_source=1
  password_source=$kept_kind
  if [[ $kept_kind == proton-pass ]]; then
    [[ -n $pp_bin ]] || pp_bin=$kept_bin
    [[ $pp_bin == "$kept_bin" ]] || kept_sha=''
    if [[ $pp_vault_set -eq 0 && -n $kept_vault ]]; then pp_vault=$kept_vault; pp_vault_set=1; fi
  else
    [[ -n $op_bin ]] || op_bin=$kept_bin
    [[ $op_bin == "$kept_bin" ]] || kept_sha=''
    if [[ $op_vault_set -eq 0 && -n $kept_vault ]]; then op_vault=$kept_vault; op_vault_set=1; fi
  fi
}

# check_password_source_flags: a manager's own flags need that manager, which may be the one kept
# from the last install (so `--op-token-file` alone rotates the connected 1Password's token).
check_password_source_flags() {
  if [[ $password_source != proton-pass && ( -n $pp_bin || $pp_vault_set -eq 1 ) ]]; then
    die "--proton-pass-* needs --password-source proton-pass"
  fi
  if [[ $password_source != 1password && ( -n $op_bin || $op_vault_set -eq 1 || -n $op_token_file ) ]]; then
    die "--1password-vault / --op-bin / --op-token-file need --password-source 1password"
  fi
}

# ---- checks: all of them before anything changes -------------------------------------
# Machine problems are collected and reported together; option errors stop at once.
problems=()
problem() { problems[${#problems[@]}]=$*; }

arch=$(uname -m)
if [[ $arch != arm64 ]]; then
  problem "this Mac is $arch: Keyflap supports Apple silicon (arm64) only; Intel Macs are not supported yet"
fi
if [[ -f $here/RELEASE ]]; then
  release_os=$(sed -n 's/^os=//p' "$here/RELEASE")
  release_arch=$(sed -n 's/^arch=//p' "$here/RELEASE")
  release_version=$(sed -n 's/^version=//p' "$here/RELEASE")
  if [[ ${release_os:-darwin} != darwin || $release_arch != arm64 ]]; then
    problem "this release is for ${release_os:-linux}-$release_arch, not macOS on Apple silicon: download keyflap-$release_version-darwin-arm64.tar.xz"
  fi
fi
macos=$(sw_vers -productVersion 2>/dev/null || echo 0)
if [[ ${macos%%.*} -lt 14 ]]; then
  problem "macOS $macos is too old: service mode needs macOS 14 or later (tested on 26)"
fi
for tool in dscl dscacheutil launchctl plutil shasum xattr install find tar; do
  command -v "$tool" >/dev/null || problem "$tool not found (part of macOS)"
done
filevault=$(fdesetup status 2>/dev/null || echo unknown)

if [[ -z $bundle && -f $here/bundle/.keyflap-bundle ]]; then bundle=$here/bundle; fi
if [[ -z $bundle ]]; then
  problem "no bundle: run this from an extracted release tarball, or pass --bundle DIR (packages/install/linux/build-bundle.sh output)"
elif [[ ! -f $bundle/.keyflap-bundle || ! -f $bundle/app/packages/cli/src/main.ts ]]; then
  problem "--bundle $bundle is not a directory made by build-bundle.sh"
fi
if [[ -z $launcher && -f $here/keyflap-launch ]]; then launcher=$here/keyflap-launch; fi
if [[ -z $launcher ]]; then
  problem "no keyflap-launch: run this from an extracted release tarball, or pass --launcher FILE (packages/install/macos/launcher/build.sh output)"
elif [[ ! -f $launcher ]]; then
  problem "--launcher $launcher is not a file"
elif [[ $(head -c 4 "$launcher" | od -An -tx1 | tr -d ' \n') != cffaedfe ]]; then
  problem "--launcher $launcher is not a Mach-O 64-bit program"
fi
# Every input root reads must be root-only too (the release dir was checked above).
for input in "$bundle" "$launcher" "$node_tarball" "$node_dir" "$browsers_dir" "$tls_cert" "$tls_key" "$apns_key" "$op_token_file"; do
  [[ -n $input && -e $input ]] || continue
  bad=$(not_root_only "$input")
  [[ -z $bad ]] || problem "$input can be changed by someone other than root: $bad. Copy it to a root-only directory first (sudo install -d -m 0700 /var/root/keyflap-input; sudo cp -R … /var/root/keyflap-input/)"
done

# Node: --node-dir, --node-tarball, the release's tarball, or a download.
node_file=node-v$NODE_VERSION-darwin-arm64.tar.xz
if [[ -z $node_dir && -z $node_tarball && -f $here/$node_file ]]; then node_tarball=$here/$node_file; fi
if [[ -n $node_dir ]]; then
  [[ -x $node_dir/bin/node ]] || problem "--node-dir $node_dir has no bin/node"
elif [[ -n $node_tarball ]]; then
  [[ -f $node_tarball ]] || problem "--node-tarball $node_tarball is not a file"
else
  command -v curl >/dev/null ||
    problem "curl not found: needed to download Node $NODE_VERSION (or pass --node-tarball FILE)"
fi
if [[ -n $browsers_dir && ! -d $browsers_dir/chromium-$CHROMIUM_REVISION ]]; then
  problem "--browsers-dir $browsers_dir has no chromium-$CHROMIUM_REVISION (the full browser; the headless shell is not used on macOS)"
fi

# The wrapper's home: /usr/local/bin is absent on a fresh Mac (root creates it); on a Mac where
# someone made /usr/local writable (Intel Homebrew did), a wrapper there could be swapped and run
# as root on the next sudo keyflap.
for d in /usr/local /usr/local/bin; do
  [[ -e $d ]] || continue
  bad=$(chain_problem "$d")
  [[ -z $bad ]] || problem "$d can be changed by someone other than root: $bad. The keyflap command is installed there and run as root (sudo chown root:wheel $d; sudo chmod 755 $d)"
done
if [[ -e $prefix ]]; then
  bad=$(chain_problem "$prefix")
  [[ -z $bad ]] || problem "$prefix can be changed by someone other than root: $bad"
fi

[[ -n $origin ]] || die "--approver-origin is required: service mode only runs with a phone approver (D5)"
origin_host=${origin#*://}; origin_host=${origin_host%%/*}; origin_host=${origin_host%%:*}
choose_tailscale
[[ -n $user ]] || die "--user is required (or run through sudo)"
[[ $user != root ]] || die "--user must be the person's own account, not root"
user_uid=$(id -u "$user" 2>/dev/null) || die "no such user: $user"
case $user in _keyflap-*|keyflap-core|keyflap-signer|keyflap-web) die "--user must not be a service user" ;; esac
user_group=$(id -gn "$user")
user_home=$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')
simple_app="$user_home/Library/Application Support/Keyflap"
if [[ -n $user_home && ( -f $user_home/Library/LaunchAgents/com.keyflap.simple.plist || -d $simple_app ) ]]; then
  die "$user has the simple install of Keyflap ($simple_app). Remove it first, as $user and without sudo:
  '$simple_app/uninstall.sh'
then run this again. Nothing moves across: the full install starts a new key store, because keys an
agent could read in the simple install should not be trusted as protected. Pair your phone again and
add your logins again. The uninstaller keeps ~/.keyflap (the old keys) until you pass --purge."
fi
if [[ -n $tls_cert || -n $tls_key ]]; then
  [[ -f $tls_cert && -f $tls_key ]] || die "--tls-cert and --tls-key must both be files"
fi
if [[ -n $apns_key || -n $apns_key_id || -n $apns_team_id || -n $apns_bundle_id ]]; then
  [[ -f $apns_key && -n $apns_key_id && -n $apns_team_id && -n $apns_bundle_id ]] ||
    die "APNs needs --apns-key FILE, --apns-key-id, --apns-team-id and --apns-bundle-id"
elif [[ $apns_sandbox -eq 1 || $apns_generic -eq 1 ]]; then
  die "--apns-sandbox / --apns-generic need --apns-key and the other --apns-* options"
fi
if [[ -n $password_source && $password_source != proton-pass && $password_source != 1password ]]; then
  die "--password-source must be proton-pass, 1password or none"
fi
keep_password_source "$prefix/node/bin/node" "$etc/signer.json"
check_password_source_flags
if [[ $password_source == proton-pass ]]; then
  # Never from a user's PATH or home: the signer runs it as the uid that holds the KEK.
  if [[ -z $pp_bin ]]; then
    for c in $prefix/tools/pass-cli/pass-cli /usr/local/bin/pass-cli /usr/bin/pass-cli; do
      if [[ -e $c ]]; then pp_bin=$c; break; fi
    done
  fi
  if [[ -z $pp_bin ]]; then
    problem "pass-cli not found in $prefix/tools/pass-cli/, /usr/local/bin or /usr/bin. Install it as root
    from Proton's verified download (never a copy from your home or Homebrew, and strip the
    quarantine attribute a browser download carries):
      sudo install -d -m 0755 $prefix/tools/pass-cli
      sudo install -o root -g wheel -m 0755 <the verified pass-cli> $prefix/tools/pass-cli/pass-cli
      sudo xattr -d com.apple.quarantine $prefix/tools/pass-cli/pass-cli
    (docs/integrations/proton-pass.md)"
  else
    bad=$(tool_problem "$pp_bin" pass-cli)
    [[ -z $bad ]] || problem "the signer would refuse pass-cli: $bad.
    Install it as root into $prefix/tools/pass-cli/ (from Proton's download, never a copy from your
    home or Homebrew) and pass --proton-pass-bin $prefix/tools/pass-cli/pass-cli"
  fi
fi
if [[ $password_source == 1password ]]; then
  if [[ -z $op_bin ]]; then
    for c in $prefix/tools/op/op /usr/local/bin/op /usr/bin/op; do
      if [[ -e $c ]]; then op_bin=$c; break; fi
    done
  fi
  if [[ -z $op_bin ]]; then
    problem "op (the 1Password CLI) not found in $prefix/tools/op/, /usr/local/bin or /usr/bin. Install it
    as root from 1Password's signed release (never a copy from your home or Homebrew):
      sudo install -d -m 0755 $prefix/tools/op
      sudo install -o root -g wheel -m 0755 <the verified op> $prefix/tools/op/op
      sudo xattr -d com.apple.quarantine $prefix/tools/op/op
    (docs/integrations/1password.md)"
  else
    bad=$(tool_problem "$op_bin" op)
    [[ -z $bad ]] || problem "the signer would refuse op: $bad.
    Install it as root into $prefix/tools/op/ (from 1Password's signed release, never a copy from
    your home or Homebrew) and pass --op-bin $prefix/tools/op/op"
  fi
  if [[ -n $op_token_file ]]; then
    if [[ ! -f $op_token_file ]]; then
      problem "--op-token-file $op_token_file is not a file"
    elif ! grep -q '[^[:space:]]' "$op_token_file"; then
      problem "--op-token-file $op_token_file is empty"
    fi
  elif [[ ! -f $creds/signer/op-service-account-token && ! -t 0 ]]; then
    problem "--password-source 1password needs the service account token: --op-token-file FILE (or run in a terminal to be prompted)"
  fi
fi

if [[ ${#problems[@]} -gt 0 ]]; then
  echo "install: this Mac isn't ready; nothing was changed:" >&2
  for p in "${problems[@]}"; do echo "  - $p" >&2; done
  exit 1
fi

# The only question, asked before anything changes.
op_token=''
if [[ $password_source == 1password && -z $op_token_file && ! -f $creds/signer/op-service-account-token ]]; then
  read -r -s -p "1Password service account token (not echoed): " op_token </dev/tty; echo >&2
  [[ -n $op_token ]] || die "no token given"
  pg_in_place=0
fi

new_version=$(cat "$bundle/app/VERSION" 2>/dev/null || cut -c1-12 "$bundle/app/REVISION" 2>/dev/null || echo unknown)
labels=(com.keyflap.signer com.keyflap.core com.keyflap.approver)
stage=''
trap 'code=$?; [[ -z $stage ]] || rm -rf "$stage"; progress_exit $code' EXIT

# ---- progress: on a terminal, a bar and a log; elsewhere the plain lines -------------------
upgrade=0
[[ -f $daemons/com.keyflap.core.plist ]] && upgrade=1
fetch_node=0 fetch_chromium=0
[[ -n $node_dir || -n $node_tarball ]] || fetch_node=1
[[ -n $browsers_dir || -d $prefix/browsers/chromium-$CHROMIUM_REVISION ]] || fetch_chromium=1
steps=$((6 + upgrade + fetch_chromium + start))
[[ -n $node_dir ]] || steps=$((steps + 1 + fetch_node))
[[ -z $tailscale_localapi ]] || steps=$((steps + 1))
progress_init "install · $new_version"
if [[ $pg_view -eq 1 ]]; then
  install -d -m 0755 -o root -g wheel /Library/Keyflap
  install -d -m 0711 -o root -g wheel "$logs"
fi
progress_start "$steps" "$(keyflap_install_log darwin)"

# ---- stop a running install (upgrade) ------------------------------------------------
if [[ $upgrade -eq 1 ]]; then
  old_version=$(cat $prefix/app/VERSION 2>/dev/null || cut -c1-12 $prefix/app/REVISION 2>/dev/null || echo unknown)
  progress_step 'Stopping Keyflap' "upgrading $old_version -> $new_version: stopping the running services (state and credentials are kept)"
  # bootout unloads the job and its sockets together (an open phone page or an agent can't
  # start a service again mid-upgrade), but returns before the job has exited: the core takes
  # up to 30 s to save browser state. Wait, then kill what the job left (Playwright's Chromium
  # is detached from the core's process group) and the per-uid agents macOS started for it.
  for label in "${labels[@]}"; do
    if launchctl print "system/$label" >/dev/null 2>&1; then
      launchctl bootout "system/$label" 2>/dev/null || true
    fi
  done
  for label in "${labels[@]}"; do
    for ((i = 0; i < 80; i++)); do
      launchctl print "system/$label" >/dev/null 2>&1 || break
      sleep 0.5
    done
  done
  for u in _keyflap-core _keyflap-signer _keyflap-web; do
    uid=$(id -u "$u" 2>/dev/null) || continue
    pkill -9 -u "$uid" 2>/dev/null || true
    launchctl bootout "user/$uid" 2>/dev/null || true
  done
else
  progress_step '' "installing $new_version"
fi

# ---- users ---------------------------------------------------------------------------
progress_step 'Creating service users' "service users _keyflap-core, _keyflap-signer, _keyflap-web"

# attr RECORD NAME: the single-word value of attribute NAME of /Users/… or /Groups/…, or nothing.
attr() { dscl . -read "$1" "$2" 2>/dev/null | sed -n "s/^$2: //p" | head -1; }
# missing RECORD NAME: whether the record has no attribute NAME.
missing() { dscl . -read "$1" "$2" 2>&1 | grep -q '^No such key'; }

free_id() {
  local used id
  used=$( { dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}')
  for ((id = 450; id <= 499; id++)); do
    if ! printf '%s\n' $used | grep -qx "$id"; then echo "$id"; return 0; fi
  done
  return 1
}

# service_user NAME HOME DESCRIPTION: creates the hidden user and its group, or checks that the
# existing ones match. Prints the uid. TCC refuses to re-set UniqueID or NFSHomeDirectory even to
# the same value, so only missing attributes are written.
service_user() {
  local name=$1 home=$2 desc=$3 alias=${1#_} id cur
  if dscl . -read "/Users/$name" UniqueID >/dev/null 2>&1; then
    id=$(attr "/Users/$name" UniqueID)
    [[ -n $id ]] || die "user $name has no UniqueID"
  elif dscl . -read "/Groups/$name" PrimaryGroupID >/dev/null 2>&1; then
    id=$(attr "/Groups/$name" PrimaryGroupID)
  else
    id=$(free_id) || die "no free uid between 450 and 499 for $name"
  fi
  if dscl . -read "/Groups/$name" PrimaryGroupID >/dev/null 2>&1; then
    cur=$(attr "/Groups/$name" PrimaryGroupID)
    [[ $cur == "$id" ]] || die "group $name has gid $cur but user $name has uid $id; fix the records (sudo dscl . -delete /Groups/$name needs Full Disk Access) and re-run"
  else
    dscl . -create "/Groups/$name"
    dscl . -create "/Groups/$name" PrimaryGroupID "$id"
    dscl . -create "/Groups/$name" RealName "$desc"
    dscl . -create "/Groups/$name" Password '*'
  fi
  if ! dscl . -read "/Users/$name" UniqueID >/dev/null 2>&1; then
    dscl . -create "/Users/$name"
    dscl . -create "/Users/$name" UniqueID "$id"
  fi
  for pair in "PrimaryGroupID=$id" "UserShell=/usr/bin/false" "NFSHomeDirectory=$home" "IsHidden=1" "Password=*"; do
    if missing "/Users/$name" "${pair%%=*}"; then
      dscl . -create "/Users/$name" "${pair%%=*}" "${pair#*=}"
    fi
  done
  if missing "/Users/$name" RealName; then dscl . -create "/Users/$name" RealName "$desc"; fi
  for pair in "PrimaryGroupID=$id" "UserShell=/usr/bin/false" "NFSHomeDirectory=$home"; do
    cur=$(attr "/Users/$name" "${pair%%=*}")
    [[ $cur == "${pair#*=}" ]] || die "user $name has ${pair%%=*} $cur, expected ${pair#*=}: another install made it; fix the record (needs Full Disk Access) and re-run"
  done
  if ! dscl . -read "/Users/$name" RecordName | grep -qw "$alias"; then
    dscl . -append "/Users/$name" RecordName "$alias"
  fi
  cur=$(id -u "$alias" 2>/dev/null || true)
  [[ $cur == "$id" ]] || die "the name $alias resolves to uid ${cur:-nothing}, not to $name ($id)"
  echo "$id"
}

core_uid=$(service_user _keyflap-core "$data/core" "Keyflap broker core")
signer_uid=$(service_user _keyflap-signer "$data/signer" "Keyflap broker signer")
web_uid=$(service_user _keyflap-web "$data/approver" "Keyflap broker approver page")
dscacheutil -flushcache 2>/dev/null || true

# ---- code and runtime, root-owned ------------------------------------------------------
progress_step 'Copying Keyflap' "code and runtime in $prefix"
install -d -m 0755 -o root -g wheel /opt
install -d -m 0755 -o root -g wheel /opt/keyflap /opt/keyflap/tools /opt/keyflap/libexec
stage=$(mktemp -d "$prefix/.stage.XXXXXX")
# dequarantine PATH: drops com.apple.quarantine from PATH and everything under it. A quarantined
# program that once tried to exec stays blocked even after the attribute is gone, so this runs on
# fresh copies before anything in them is executed.
dequarantine() { xattr -r -d com.apple.quarantine "$1" 2>/dev/null || true; }

# Fresh root-owned copies: nothing here may stay linked to a user-writable file.
cp -R "$bundle/app" "$stage/app"
dequarantine "$stage/app"
# pnpm's links are relative and stay inside the app; refuse anything pointing elsewhere.
while IFS= read -r link; do
  [[ -n $link ]] || continue
  target=$(readlink -f "$link" || true)
  [[ $target == "$stage/app/"* ]] || die "bundle symlink points outside the app: ${link#"$stage/"}"
done < <(find "$stage/app" -type l)

if [[ -n $node_dir ]]; then
  cp -RL "$node_dir" "$stage/node"
else
  # Verify and unpack the same root-owned copy (the release dir may be writable by you).
  if [[ -n $node_tarball ]]; then
    install -m 0600 "$node_tarball" "$stage/node.tar.xz"
  else
    progress_step 'Downloading Node' "downloading Node $NODE_VERSION (darwin-arm64)"
    node_url=https://nodejs.org/dist/v$NODE_VERSION/$node_file
    if [[ $pg_view -eq 1 ]]; then
      progress_watch curl "$stage/node.progress"
      curl -fSL --proto '=https' --tlsv1.2 -o "$stage/node.tar.xz" "$node_url" 2>"$stage/node.progress" ||
        { tr '\r' '\n' <"$stage/node.progress" | grep '^curl:' >&2; die "the Node download failed"; }
    else
      curl -fsSL --proto '=https' --tlsv1.2 -o "$stage/node.tar.xz" "$node_url"
    fi
  fi
  progress_step 'Unpacking Node' ''
  dequarantine "$stage/node.tar.xz"
  sum=$(shasum -a 256 "$stage/node.tar.xz" | cut -d' ' -f1)
  [[ $sum == "$(node_sha256 darwin arm64)" ]] || die "Node tarball checksum mismatch (expected $node_file)"
  mkdir "$stage/node"
  tar -xJf "$stage/node.tar.xz" -C "$stage/node" --strip-components=1 --no-same-owner
  rm -f "$stage/node.tar.xz"
fi
dequarantine "$stage/node"
"$stage/node/bin/node" --version | grep -q '^v22\.' || die "the runtime is not Node 22"

if [[ -n $browsers_dir ]]; then
  mkdir "$stage/browsers"
  cp -R "$browsers_dir/chromium-$CHROMIUM_REVISION" "$stage/browsers/"
elif [[ -d $prefix/browsers/chromium-$CHROMIUM_REVISION ]]; then
  # Upgrade: the pinned Chromium is already there, root-owned; keep it.
  cp -R "$prefix/browsers" "$stage/browsers"
else
  progress_step 'Downloading Chromium' "downloading Chromium $CHROMIUM_REVISION (Playwright's installer)"
  # Root runs Playwright's own installer from the root-owned copy in $stage. Only the full
  # browser: macOS runs it in new headless mode, never the headless shell. On a terminal its
  # per-10% lines move the bar; elsewhere they are dropped.
  playwright_out=/dev/null
  if [[ $pg_view -eq 1 ]]; then
    playwright_out=$stage/chromium.progress
    progress_watch playwright "$playwright_out"
  fi
  PLAYWRIGHT_BROWSERS_PATH=$stage/browsers "$stage/node/bin/node" \
    "$stage/app/packages/shim/node_modules/playwright/cli.js" install --no-shell chromium >"$playwright_out"
  [[ $playwright_out == /dev/null ]] || cat "$playwright_out"
fi
dequarantine "$stage/browsers"

install -m 0755 "$launcher" "$stage/keyflap-launch"
dequarantine "$stage/keyflap-launch"

chown -R root:wheel "$stage"
chmod -R u+rwX,go+rX,go-w "$stage"
find "$stage" -type f \( -perm -4000 -o -perm -2000 \) -exec chmod ug-s {} +
for part in app node browsers; do
  rm -rf "$prefix/$part.old"
  if [[ -e $prefix/$part ]]; then mv "$prefix/$part" "$prefix/$part.old"; fi
  mv "$stage/$part" "$prefix/$part"
  rm -rf "$prefix/$part.old"
done
mv "$stage/keyflap-launch" "$prefix/libexec/keyflap-launch"
NODE=$prefix/node/bin/node

# ---- secrets: 0400 files owned by the service that reads them ------------------------------
progress_step 'Creating keys' "credentials in $creds"
install -d -m 0755 -o root -g wheel /Library/Keyflap
install -d -m 0711 -o root -g wheel "$creds"
install -d -m 0500 -o _keyflap-signer -g _keyflap-signer "$creds/signer"
install -d -m 0500 -o _keyflap-core -g _keyflap-core "$creds/core"
install -d -m 0500 -o _keyflap-web -g _keyflap-web "$creds/approver"
# put_secret SERVICE OWNER NAME: stdin -> $creds/SERVICE/NAME, 0400, owned by OWNER.
put_secret() {
  (umask 077; cat >"$creds/$1/$3.tmp")
  chown "$2:$2" "$creds/$1/$3.tmp"
  chmod 0400 "$creds/$1/$3.tmp"
  mv "$creds/$1/$3.tmp" "$creds/$1/$3"
}
# The KEK protects the key store: never regenerated once it exists. Same for the channel key;
# the core gets its own copy of it (two decrypted copies, as on Linux), kept equal to the signer's.
[[ -f $creds/signer/kek ]] || head -c 32 /dev/urandom | put_secret signer _keyflap-signer kek
[[ -f $creds/signer/channel-key ]] || head -c 32 /dev/urandom | put_secret signer _keyflap-signer channel-key
put_secret core _keyflap-core channel-key <"$creds/signer/channel-key"
if [[ -n $tls_cert ]]; then
  put_secret approver _keyflap-web approver-tls-cert <"$tls_cert"
  put_secret approver _keyflap-web approver-tls-key <"$tls_key"
else
  rm -f "$creds/approver/approver-tls-cert" "$creds/approver/approver-tls-key"
fi
if [[ -n $apns_key ]]; then
  put_secret core _keyflap-core apns-key <"$apns_key"
else
  rm -f "$creds/core/apns-key"
fi
# The 1Password service account token: only the signer reads it, never a config file or a
# command line.
if [[ $password_source == 1password ]]; then
  if [[ -n $op_token_file ]]; then
    tr -d '\r\n' <"$op_token_file" | put_secret signer _keyflap-signer op-service-account-token
  elif [[ -n $op_token ]]; then
    printf '%s' "$op_token" | put_secret signer _keyflap-signer op-service-account-token
  fi
  unset op_token
else
  rm -f "$creds/signer/op-service-account-token"
fi

# ---- data, tmp and log dirs, the user's hook token -----------------------------------------
progress_step 'Preparing data folders' "data in $data"
install -d -m 0711 -o root -g wheel "$data"
install -d -m 0700 -o _keyflap-core -g _keyflap-core "$data/core" "$data/core/tmp"
install -d -m 0700 -o _keyflap-signer -g _keyflap-signer "$data/signer" "$data/signer/tmp"
install -d -m 0700 -o _keyflap-web -g _keyflap-web "$data/approver" "$data/approver/tmp"
# launchd opens StandardErrorPath as the job's user: a root-only log dir fails the job. 0711 so
# the owner (and their agents) can't list it, with a 0700 dir per service for the file.
install -d -m 0711 -o root -g wheel "$logs"
install -d -m 0700 -o _keyflap-core -g _keyflap-core "$logs/core"
install -d -m 0700 -o _keyflap-signer -g _keyflap-signer "$logs/signer"
install -d -m 0700 -o _keyflap-web -g _keyflap-web "$logs/approver"
# Socket directories: launchd creates the sockets inside with the plists' owners and modes.
install -d -m 0755 -o root -g wheel "$run" "$run/core"
install -d -m 0750 -o root -g _keyflap-core "$run/signer"
install -d -m 0750 -o root -g _keyflap-web "$run/approver"

# A fresh host token each install: one copy for the core, one plain copy for the user's hook.
# The hook dir is recreated by root so no user-made symlink is followed. The agent tokens setup
# stored there (agent-<id>.token, read by `keyflap mcp-headers`) are shown only once and can't
# be re-issued, so an upgrade keeps them: read and written back as the user (a symlink in their
# own dir yields only what they could read anyway), only well-formed ones, and only when the dir
# already belonged to this user.
token_names=()
token_values=()
if [[ -d $hook && ! -L $hook && $(stat -f %Su "$hook") == "$user" ]]; then
  for f in "$hook"/agent-*.token; do
    [[ -e $f ]] || continue
    name=${f##*/}
    [[ $name =~ ^agent-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.token$ ]] || continue
    tok=$(sudo -u "$user" -- head -c 200 "$f" 2>/dev/null) || continue
    tok=${tok%$'\n'}
    [[ $tok =~ ^aab_agent_[A-Za-z0-9_-]{43}$ ]] || continue
    token_names[${#token_names[@]}]=$name
    token_values[${#token_values[@]}]=$tok
  done
fi
rm -rf "$hook"
install -d -m 0700 -o root -g wheel "$hook"
(umask 077; "$NODE" -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url')+'\n')" >"$hook/host-token")
put_secret core _keyflap-core host-token <"$hook/host-token"
chown "$user:$user_group" "$hook" "$hook/host-token"
for ((i = 0; i < ${#token_names[@]}; i++)); do
  printf '%s\n' "${token_values[$i]}" |
    sudo -u "$user" -- sh -c 'umask 077; cat >"$1"' sh "$hook/${token_names[$i]}"
done
unset token_names token_values tok

if [[ -n $tailscale_localapi ]]; then
  progress_step 'Connecting to Tailscale' "letting _keyflap-signer read Tailscale's token in $tailscale_localapi"
  grant_tailscale_token "$tailscale_localapi"
fi

# ---- configuration -----------------------------------------------------------------------
progress_step 'Writing settings' "configuration in $etc"
install -d -m 0755 -o root -g wheel "$etc"
cfg_args=(--out-dir "$etc" --approver-origin "$origin")
[[ -n $listen ]] && cfg_args[${#cfg_args[@]}]=--approver-listen && cfg_args[${#cfg_args[@]}]=$listen
[[ -n $tls_cert ]] && cfg_args[${#cfg_args[@]}]=--tls
[[ -n $mcp_port ]] && cfg_args[${#cfg_args[@]}]=--mcp-port && cfg_args[${#cfg_args[@]}]=$mcp_port
if [[ -n $apns_key ]]; then
  cfg_args=("${cfg_args[@]}" --apns-key-id "$apns_key_id" --apns-team-id "$apns_team_id" --apns-bundle-id "$apns_bundle_id")
  [[ $apns_sandbox -eq 1 ]] && cfg_args[${#cfg_args[@]}]=--apns-sandbox
  [[ $apns_generic -eq 1 ]] && cfg_args[${#cfg_args[@]}]=--apns-generic
fi
for ((i = 0; i < ${#high_risk[@]}; i++)); do cfg_args=("${cfg_args[@]}" --high-risk "${high_risk[$i]}"); done
if [[ -n $pp_bin ]]; then
  # install-config.ts checks it again (tool.ts) and pins its SHA-256 in signer.json.
  cfg_args=("${cfg_args[@]}" --proton-pass-bin "$pp_bin")
  if [[ $kept_source -eq 1 && -n $kept_sha ]]; then cfg_args=("${cfg_args[@]}" --proton-pass-sha256 "$kept_sha"); fi
  [[ $pp_vault_set -eq 1 ]] && cfg_args=("${cfg_args[@]}" --proton-pass-vault "$pp_vault")
fi
if [[ -n $op_bin ]]; then
  cfg_args=("${cfg_args[@]}" --op-bin "$op_bin")
  if [[ $kept_source -eq 1 && -n $kept_sha ]]; then cfg_args=("${cfg_args[@]}" --op-sha256 "$kept_sha"); fi
  [[ $op_vault_set -eq 1 ]] && cfg_args=("${cfg_args[@]}" --1password-vault "$op_vault")
fi
[[ -n $tailscale_bin ]] && cfg_args=("${cfg_args[@]}" --tailscale-bin "$tailscale_bin")
[[ -n $tailscale_localapi ]] && cfg_args=("${cfg_args[@]}" --tailscale-localapi "$tailscale_localapi")
[[ $ephemeral -eq 1 ]] && cfg_args[${#cfg_args[@]}]=--ephemeral-browser
# install-config.ts writes the darwin browser settings itself (headless, full Chromium).
"$NODE" --disable-warning=ExperimentalWarning $prefix/app/packages/cli/src/service/install-config.ts "${cfg_args[@]}"
chmod 0644 /Library/Keyflap/etc/core.json /Library/Keyflap/etc/signer.json /Library/Keyflap/etc/approver.json
# launchd binds the approver's listener: an IP address and port.
listen_spec=$("$NODE" -e '
  const c = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
  const net = require("node:net");
  const h = c.listen.host;
  if (!net.isIP(h)) process.exit(3);
  process.stdout.write([h, c.listen.port, net.isIPv6(h) ? "IPv6" : "IPv4"].join(" "));
' "$etc/approver.json") || die "--approver-listen must be an IP address and port in service mode (e.g. 127.0.0.1:8766)"
listen_host=${listen_spec%% *}
listen_port=$(echo "$listen_spec" | cut -d' ' -f2)
listen_family=${listen_spec##* }

# ---- launchd -----------------------------------------------------------------------------
progress_step 'Adding the background services' "LaunchDaemons com.keyflap.signer, com.keyflap.core, com.keyflap.approver"
# render_plist NAME: the template with the ids filled in, root:wheel 0644 (launchd refuses
# anything else). The ::1 twin of the approver listener only makes sense for 127.0.0.1.
render_plist() {
  local label=com.keyflap.$1 v6
  if [[ $listen_host == 127.0.0.1 ]]; then v6='/@V6: /d'; else v6='/@V6: start/,/@V6: end/d'; fi
  sed -e "$v6" \
    -e "s|@USER_UID@|$user_uid|g" -e "s|@CORE_GID@|$core_uid|g" -e "s|@SIGNER_UID@|$signer_uid|g" \
    -e "s|@WEB_GID@|$web_uid|g" -e "s|@LISTEN_HOST@|$listen_host|g" -e "s|@LISTEN_PORT@|$listen_port|g" \
    -e "s|@LISTEN_FAMILY@|$listen_family|g" "$here/launchd/$label.plist" >"$daemons/$label.plist.tmp"
  grep -q '@[A-Z_6: ]*@' "$daemons/$label.plist.tmp" && die "unfilled placeholder in $label.plist"
  plutil -lint -s "$daemons/$label.plist.tmp" >/dev/null || die "$label.plist is not a valid property list"
  chown root:wheel "$daemons/$label.plist.tmp"
  chmod 0644 "$daemons/$label.plist.tmp"
  mv "$daemons/$label.plist.tmp" "$daemons/$label.plist"
}
render_plist signer
render_plist core
render_plist approver

install -d -m 0755 -o root -g wheel /usr/local/bin
install -m 0755 -o root -g wheel "$here/keyflap-wrapper.sh" /usr/local/bin/keyflap
dequarantine /usr/local/bin/keyflap

if [[ $start -eq 1 ]]; then
  progress_step 'Starting Keyflap' "starting"
  # `launchctl enable` only when a bootstrap is refused: it leaves a permanent override entry.
  for label in "${labels[@]}"; do
    launchctl bootstrap system "$daemons/$label.plist" 2>/dev/null ||
      { launchctl enable "system/$label" && launchctl bootstrap system "$daemons/$label.plist"; } ||
      die "launchctl bootstrap system/$label failed: sudo launchctl print system/$label; sudo tail -n 50 $logs/${label#com.keyflap.}/${label#com.keyflap.}.log"
  done
fi

listen_shown=$listen_host:$listen_port
[[ $listen_host == 127.0.0.1 ]] && listen_shown="$listen_shown (and [::1]:$listen_port)"
browser="headless (full Chromium, its own sandbox on); the first start takes up to a minute while macOS scans the new browser"
[[ $start -eq 1 ]] || browser="$browser; services not started (--no-start)"
if [[ $filevault != *On* ]]; then
  cat <<EOF

note: FileVault is off ($filevault). The key store's KEK and the other credentials are files on
disk that only root and the service users can read while macOS runs; whoever has the disk can
read them. Turn FileVault on: System Settings > Privacy & Security > FileVault.
EOF
  progress_warn "FileVault is off, so whoever has this Mac's disk can read Keyflap's keys. Turn it on: System Settings > Privacy & Security > FileVault."
fi
[[ $start -eq 1 ]] || progress_warn "The services were not started (--no-start); they start at the next boot."
kept_words=''
if [[ $kept_source -eq 1 ]]; then
  case $password_source in
    1password) kept_words=" Kept: 1Password (the tool, its pin, the vault and the token)." ;;
    *) kept_words=" Kept: Proton Pass (the tool, its pin, the vault and its login)." ;;
  esac
fi
if [[ $upgrade -eq 1 ]]; then
  cat <<EOF

Upgraded to $new_version. Kept: the key store and its KEK, the channel key, the database
(phones, agents, passwords, policies) and saved browser sessions. The host token was
re-issued; your Claude Code hook reads the new copy; agent tokens are kept. Managed browser: $browser.$kept_words

Check it: sudo keyflap status
EOF
else
  cat <<EOF

Installed $new_version. The broker runs as _keyflap-core / _keyflap-signer, and the phone approver
page as _keyflap-web on $listen_shown; your user ($user) reaches the broker only through MCP
(with an agent token) and the intent socket (your Claude Code hook).
Managed browser: $browser.
macOS shows a "Background Items Added" notification for the three Keyflap services (System
Settings > General > Login Items & Extensions); they must stay allowed there.

Next (docs/integrations/service-mode.md):
  sudo keyflap setup                   # guided: pair your phone, add an agent

or step by step:
  sudo keyflap approver pair           # one-time link: open it on your phone
  sudo keyflap agent add "Claude Code" # prints the agent token and Claude Code config
  sudo keyflap status
EOF
fi
if [[ $pg_view -eq 1 ]]; then
  if [[ $upgrade -eq 1 ]]; then
    progress_finish "Upgraded Keyflap to $new_version"
    progress_say "Your phone, agents, passwords and saved sign-ins are kept."
    [[ -z $kept_words ]] || progress_say "${kept_words# }"
  else
    progress_finish "Installed Keyflap $new_version"
    progress_say 'macOS shows "Background Items Added" for Keyflap. Keep them allowed.'
  fi
  progress_say
  if [[ -z ${KEYFLAP_PROGRESS_FROM:-} ]]; then
    if [[ $upgrade -eq 1 ]]; then progress_say "Check it: sudo keyflap status"; else progress_say "Next: sudo keyflap setup"; fi
  fi
  progress_say "Details: $pg_log"
fi
