#!/usr/bin/env bash
# Installs (or upgrades) the Keyflap broker in service mode on a systemd Linux machine.
# docs/ISOLATION_PLAN.md (design, D1-D6) and docs/integrations/service-mode.md (how to).
#
#   sudo ./install.sh --approver-origin https://HOST [options]      # from a release tarball
#   sudo packages/install/linux/install.sh --bundle DIR --approver-origin https://HOST [options]
#
# What it does, all as root:
#   - checks the machine first (systemd >= 250, systemd-creds, tools, architecture, Xvfb)
#     and changes nothing if a check fails;
#   - system users keyflap-core, keyflap-signer and keyflap-web (systemd-sysusers);
#   - root-owned code and runtime in /opt/keyflap: the bundle (the release's bundle/, or
#     build-bundle.sh output) copied with fresh root-owned inodes, a pinned Node 22 (the
#     release's tarball or a download, checksum-verified either way, or --node-dir), and
#     Playwright's Chromium 1248 (playwright install, or --browsers-dir);
#   - secrets as systemd credentials in /etc/keyflap/credentials (root 0700), sealed with
#     systemd-creds (TPM2 when present, else the host key): the key-store KEK (D1), the
#     signer channel key and the host token. A plain copy of the host token goes to
#     /var/lib/keyflap/hook for the user's Claude Code hook;
#   - /etc/keyflap/{core,signer,approver}.json, systemd units and sockets, tmpfiles.d,
#     /usr/local/bin/keyflap. The phone approver page is served by its own service
#     (keyflap-approver, user keyflap-web), never by the core (docs/APPROVER_INTEGRITY_PLAN.md).
#   - the managed Chromium runs headed on a private Xvfb display by default (many sites'
#     bot walls refuse headless Chromium); --headless opts out.
# On a terminal it shows progress (progress.sh) and a short summary, and writes the detail to
# /var/log/keyflap/install.log (root, 0600); elsewhere it prints the plain `==>` lines.
# Nothing secret is printed or logged. Re-running upgrades the code and keeps the key store, its KEK,
# the channel key and the database, then restarts the services.
#
# Everything root runs or installs from must be root-only: this script's directory (and the
# bundle and Node tarball in it), every input file, Xvfb, and a password tool. A file your
# user (or an agent running as you) could change between your check and this run would run
# as root, or as the signer. The installer refuses to start otherwise.
set -euo pipefail
umask 022

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
die() {
  if [[ ${pg_active:-0} -eq 1 ]]; then progress_fail "install: $*"; else echo "install: $*" >&2; fi
  exit 1
}
[[ $EUID -eq 0 ]] || die "run as root (sudo)"

# not_root_only PATH: prints the first thing that makes PATH changeable by someone other than
# root (a parent directory, or for a directory anything inside it), or nothing.
not_root_only() {
  local real d uid mode bad
  real=$(readlink -f -- "$1" 2>/dev/null) || { echo "$1 (cannot be resolved)"; return 0; }
  [[ -e $real ]] || { echo "$1 (does not exist)"; return 0; }
  d=$real
  while :; do
    read -r uid mode < <(stat -c '%u %a' -- "$d")
    if [[ $uid != 0 ]]; then echo "$d (owned by uid $uid)"; return 0; fi
    if (( (8#$mode & 8#022) != 0 )); then echo "$d (mode $mode: writable by group or others)"; return 0; fi
    [[ $d == / ]] && break
    d=$(dirname -- "$d")
  done
  if [[ -d $real ]]; then
    bad=$(find "$real" ! -type l \( ! -user 0 -o -perm /022 \) -print -quit 2>/dev/null || echo "$real (unreadable)")
    if [[ -n $bad ]]; then echo "$bad (not root-owned, or writable by group or others)"; return 0; fi
  fi
}

# tool_problem PATH COMMAND: why the signer would refuse to run PATH as COMMAND, or nothing.
# The same rules as @aab/sources tool.ts, which install-config.ts and the signer apply too.
tool_problem() {
  local p=$1 cmd=$2 real bad
  [[ $p == /* ]] || { echo "$p is not an absolute path"; return 0; }
  [[ -f $p ]] || { echo "$p does not exist"; return 0; }
  real=$(readlink -f -- "$p")
  [[ $real == "$p" ]] || { echo "$p is a symbolic link (or has one on the way) to $real"; return 0; }
  case $(dirname -- "$p") in
    /usr/bin|/usr/local/bin|/usr/sbin|/usr/local/sbin|/bin|/sbin) ;;
    "/opt/keyflap/tools/$cmd"|"/opt/keyflap/tools/$cmd"/*) ;;
    *) echo "$p is not in a system bin directory or /opt/keyflap/tools/$cmd/"; return 0 ;;
  esac
  bad=$(not_root_only "$p")
  [[ -z $bad ]] || { echo "$bad: someone other than root could replace $cmd"; return 0; }
  (( (8#$(stat -c %a -- "$p") & 8#6000) == 0 )) || { echo "$p has a setuid/setgid bit"; return 0; }
  [[ -x $p ]] || echo "$p is not executable"
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

tailscale_candidates=(/usr/bin/tailscale /usr/sbin/tailscale /usr/local/bin/tailscale)

# choose_tailscale: sets tailscale_bin to the tailscale the signer will run (never from a user's
# PATH or home); reports what stands in the way through problem.
choose_tailscale() {
  [[ -n $tailscale_bin || $origin_host == *.ts.net ]] || return 0
  local bad
  if [[ -z $tailscale_bin ]]; then
    pick_tool tailscale "${tailscale_candidates[@]}"
    tailscale_bin=$picked
    if [[ -z $tailscale_bin ]]; then
      problem "no tailscale the signer can run in /usr/bin, /usr/sbin or /usr/local/bin.$refusals
    The signer runs it to check that $origin still points at the approver. Install Tailscale as root
    (tailscale.com/download or your distribution's package), or pass --tailscale-bin PATH"
      return 0
    fi
  fi
  bad=$(tool_problem "$tailscale_bin" tailscale)
  [[ -z $bad ]] || problem "the signer would refuse tailscale: $bad.
    Install Tailscale as root (tailscale.com/download or your distribution's package, never a copy from
    your home) and pass --tailscale-bin /usr/bin/tailscale"
}

# The installer itself first: a copy your user can change is not one to run as root (M4).
bad=$(not_root_only "$here")
if [[ -n $bad ]]; then
  die "refusing to run from $here: $bad.
  Anything your user (or an agent running as you) can change could be edited before root runs it.
  Copy the release to a directory only root can change, check it there, and run it from there:
    sudo install -d -m 0755 /opt/keyflap-release
    sudo install -m 0644 keyflap-VERSION-linux-ARCH.tar.xz SHA256SUMS /opt/keyflap-release/
    (verify /opt/keyflap-release/keyflap-VERSION-linux-ARCH.tar.xz: docs/integrations/service-mode.md)
    sudo tar -xJf /opt/keyflap-release/keyflap-VERSION-linux-ARCH.tar.xz -C /opt/keyflap-release
    sudo /opt/keyflap-release/keyflap-VERSION-linux-ARCH/install.sh …"
fi
# shellcheck source=runtime-pins.sh
source "$here/runtime-pins.sh"
# shellcheck source=progress.sh
source "$here/progress.sh"

usage() {
  cat <<'EOF'
usage: sudo ./install.sh --approver-origin URL [options]        (from a release tarball)
       sudo install.sh --bundle DIR --approver-origin URL [options]  (from a source build)

  --approver-origin URL     https origin of the phone approver page (required, D5)
  --bundle DIR              output of build-bundle.sh (default: the bundle/ next to this
                            script, as in a release tarball)
  --user NAME               the person whose agents use the broker (default: $SUDO_USER);
                            only this user can reach the intent socket
  --approver-listen IP:P    approver listener (default 127.0.0.1:8766, behind e.g.
                            `tailscale serve`); held by systemd for the approver page
  --tailscale-bin PATH      the tailscale CLI the signer runs (`tailscale serve status`) to check
                            that the approver origin still points at the approver listener; it
                            must be root-only. Default when the origin is a *.ts.net name: the
                            first of /usr/bin, /usr/sbin or /usr/local/bin that is root-only
  --tls-cert FILE --tls-key FILE
                            serve the approver page with this certificate instead
  --apns-key FILE --apns-key-id ID --apns-team-id ID --apns-bundle-id ID
    [--apns-sandbox] [--apns-generic]
                            push to the Keyflap iOS app through APNs (docs/integrations/
                            ios-app.md); the .p8 key is sealed as a credential
  --mcp-port N              MCP endpoint on 127.0.0.1:N (default 8765)
  --high-risk DOMAIN        always needs phone approval with user verification (repeatable)
  --password-source proton-pass [--proton-pass-vault NAME] [--proton-pass-bin PATH]
                            also offer Proton Pass logins. The signer runs pass-cli only from a
                            root-only path: /opt/keyflap/tools/pass-cli/, /usr/local/bin or
                            /usr/bin (searched in that order without PATH); its SHA-256 is
                            pinned (sudo keyflap password-source trust pass-cli after updates)
  --password-source 1password [--1password-vault NAME] [--op-bin PATH] [--op-token-file FILE]
                            also offer 1Password logins through a service account. op is run only
                            from a root-only path, like pass-cli (/opt/keyflap/tools/op/,
                            /usr/local/bin or /usr/bin; trust op after updates). The token (FILE,
                            or a no-echo prompt) is sealed as a credential only the signer reads;
                            an upgrade keeps the sealed token unless FILE is given
  --password-source none    disconnect the password manager. Without --password-source an upgrade
                            keeps the one already connected, with its tool, pin, vault and token
                            (connect or change one without re-installing: sudo keyflap
                            password-source add proton-pass|1password)
  --xvfb [PATH]             Xvfb for the headed browser (the default; PATH defaults to the
                            Xvfb on root's PATH, else /usr/bin/Xvfb; it must be root-only)
  --headless                run the managed browser headless instead of on Xvfb
  --ephemeral-browser       don't save the agents' browser sessions across restarts
  --node-tarball FILE       use this node-v22.23.4-linux-*.tar.xz (still checksum-verified;
                            default: the one in the release tarball, else download it)
  --node-dir DIR            copy this Node 22 install instead (offline/tests; you vouch for it)
  --browsers-dir DIR        copy Playwright browsers from DIR instead of downloading
                            (offline/tests; you vouch for it)
  --no-start                install everything but don't start the services

Re-running upgrades: pass the same options again (the configuration is rewritten from them).
EOF
}

bundle='' user=${SUDO_USER:-} origin='' listen='' tls_cert='' tls_key='' mcp_port=''
apns_key='' apns_key_id='' apns_team_id='' apns_bundle_id='' apns_sandbox=0 apns_generic=0
high_risk=() password_source='' no_password_source=0 pp_vault='' pp_vault_set=0 pp_bin='' xvfb='' headless=0
op_vault='' op_vault_set=0 op_bin='' op_token_file='' tailscale_bin=''
node_tarball='' node_dir='' browsers_dir='' start=1 ephemeral=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --bundle) bundle=${2:?}; shift 2 ;;
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
    --high-risk) high_risk+=("${2:?}"); shift 2 ;;
    --password-source) password_source=${2:?}; shift 2 ;;
    --proton-pass-vault) pp_vault=${2?}; pp_vault_set=1; shift 2 ;;
    --proton-pass-bin) pp_bin=${2:?}; shift 2 ;;
    --1password-vault) op_vault=${2?}; op_vault_set=1; shift 2 ;;
    --op-bin) op_bin=${2:?}; shift 2 ;;
    --op-token-file) op_token_file=${2:?}; shift 2 ;;
    --tailscale-bin) tailscale_bin=${2:?}; shift 2 ;;
    --xvfb)
      if [[ $# -gt 1 && $2 == /* ]]; then xvfb=$2; shift 2; else xvfb=auto; shift; fi ;;
    --headless) headless=1; shift ;;
    --node-tarball) node_tarball=${2:?}; shift 2 ;;
    --node-dir) node_dir=${2:?}; shift 2 ;;
    --browsers-dir) browsers_dir=${2:?}; shift 2 ;;
    --ephemeral-browser) ephemeral=1; shift ;;
    --no-start) start=0; shift ;;
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
problem() { problems+=("$*"); }

case $(uname -m) in
  x86_64) arch=x64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) arch=''; problem "unsupported architecture $(uname -m): service mode supports x86_64 and aarch64" ;;
esac
release_arch=''
if [[ -f $here/RELEASE ]]; then
  release_arch=$(sed -n 's/^arch=//p' "$here/RELEASE")
  release_version=$(sed -n 's/^version=//p' "$here/RELEASE")
  if [[ -n $arch && $release_arch != "$arch" ]]; then
    problem "this release is for linux-$release_arch but this machine is linux-$arch: download keyflap-$release_version-linux-$arch.tar.xz"
  fi
fi

if [[ ! -d /run/systemd/system ]]; then
  problem "systemd is not running here (service mode needs systemd as PID 1)"
else
  sd_version=$(systemctl --version 2>/dev/null | head -1 | awk '{print $2}')
  sd_version=${sd_version%%[!0-9]*}
  if [[ -z $sd_version || $sd_version -lt 250 ]]; then
    problem "systemd ${sd_version:-?} is too old: service mode needs systemd >= 250 (LoadCredentialEncrypted=, systemd-creds)"
  fi
fi
for tool in systemd-creds systemd-sysusers systemd-tmpfiles; do
  command -v "$tool" >/dev/null || problem "$tool not found (part of systemd >= 250)"
done
for tool in sha256sum find install; do
  command -v "$tool" >/dev/null || problem "$tool not found (coreutils/findutils)"
done

if [[ -z $bundle && -f $here/bundle/.keyflap-bundle ]]; then bundle=$here/bundle; fi
if [[ -z $bundle ]]; then
  problem "no bundle: run this from an extracted release tarball, or pass --bundle DIR (packages/install/linux/build-bundle.sh output)"
elif [[ ! -f $bundle/.keyflap-bundle || ! -f $bundle/app/packages/cli/src/main.ts ]]; then
  problem "--bundle $bundle is not a directory made by build-bundle.sh"
fi
# Every input root reads must be root-only too (the release dir was checked above).
for input in "$bundle" "$node_tarball" "$node_dir" "$browsers_dir" "$tls_cert" "$tls_key" "$apns_key" "$op_token_file"; do
  [[ -n $input && -e $input ]] || continue
  bad=$(not_root_only "$input")
  [[ -z $bad ]] || problem "$input can be changed by someone other than root: $bad. Copy it to a root-only directory first (sudo install -d -m 0700 /root/keyflap-input; sudo cp -r … /root/keyflap-input/)"
done

# Node: --node-dir, --node-tarball, the release's tarball, or a download.
if [[ -z $node_dir && -z $node_tarball && -n $arch && -f $here/node-v$NODE_VERSION-linux-$arch.tar.xz ]]; then
  node_tarball=$here/node-v$NODE_VERSION-linux-$arch.tar.xz
fi
if [[ -n $node_dir ]]; then
  [[ -x $node_dir/bin/node ]] || problem "--node-dir $node_dir has no bin/node"
else
  if [[ -n $node_tarball ]]; then
    [[ -f $node_tarball ]] || problem "--node-tarball $node_tarball is not a file"
  else
    command -v curl >/dev/null ||
      problem "curl not found: needed to download Node $NODE_VERSION (install curl, or pass --node-tarball FILE)"
  fi
  command -v tar >/dev/null || problem "tar not found"
  command -v xz >/dev/null ||
    problem "xz not found: needed to unpack Node (Debian/Ubuntu: xz-utils, Fedora: xz, Arch: xz)"
fi

# The managed browser: headed on Xvfb unless --headless.
if [[ $headless -eq 1 && -n $xvfb ]]; then die "--headless and --xvfb exclude each other"; fi
if [[ $headless -eq 0 ]]; then
  if [[ -z $xvfb || $xvfb == auto ]]; then
    xvfb=$(command -v Xvfb || true)
    [[ -n $xvfb ]] || xvfb=/usr/bin/Xvfb
  fi
  if [[ -x $xvfb ]]; then xvfb=$(readlink -f -- "$xvfb"); fi
  if [[ ! -x $xvfb ]]; then
    problem "Xvfb not found at $xvfb. Service mode runs Chromium headed on a private Xvfb display by
    default, because many sites' bot walls refuse headless Chromium. Install it:
      Debian/Ubuntu:  sudo apt install xvfb
      Fedora:         sudo dnf install xorg-x11-server-Xvfb
      Arch:           sudo pacman -S xorg-server-xvfb
    then re-run; or pass --xvfb PATH if it lives elsewhere, or --headless to stay headless."
  else
    # The core runs it: it and every directory above it must be root-only (checked again
    # at every start).
    bad=$(not_root_only "$xvfb")
    [[ -z $bad ]] || problem "Xvfb at $xvfb can be replaced by someone other than root: $bad (use your distribution's Xvfb in /usr/bin)"
  fi
fi
if [[ -n $browsers_dir ]]; then
  if [[ ! -d $browsers_dir/chromium_headless_shell-$CHROMIUM_REVISION && ! -d $browsers_dir/chromium-$CHROMIUM_REVISION ]]; then
    problem "--browsers-dir $browsers_dir has no Chromium $CHROMIUM_REVISION"
  elif [[ $headless -eq 0 && ! -d $browsers_dir/chromium-$CHROMIUM_REVISION ]]; then
    problem "--browsers-dir $browsers_dir has no full chromium-$CHROMIUM_REVISION (the headed browser needs it; or --headless)"
  fi
fi

[[ -n $origin ]] || die "--approver-origin is required: service mode only runs with a phone approver (D5)"
origin_host=${origin#*://}; origin_host=${origin_host%%/*}; origin_host=${origin_host%%:*}
choose_tailscale
[[ -n $user ]] || die "--user is required (or run through sudo)"
[[ $user != root ]] || die "--user must be the person's own account, not root"
id -u "$user" >/dev/null 2>&1 || die "no such user: $user"
case $user in keyflap-core|keyflap-signer|keyflap-web) die "--user must not be a service user" ;; esac
user_group=$(id -gn "$user")
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
keep_password_source /opt/keyflap/node/bin/node /etc/keyflap/signer.json
check_password_source_flags
if [[ $password_source == proton-pass ]]; then
  # Never from a user's PATH or home: the signer runs it as the uid that holds the KEK.
  if [[ -z $pp_bin ]]; then
    for c in /opt/keyflap/tools/pass-cli/pass-cli /usr/local/bin/pass-cli /usr/bin/pass-cli; do
      if [[ -e $c ]]; then pp_bin=$c; break; fi
    done
  fi
  if [[ -z $pp_bin ]]; then
    problem "pass-cli not found in /opt/keyflap/tools/pass-cli/, /usr/local/bin or /usr/bin. Install it as root,
    from Proton's pass-cli download or your distribution's package (never a copy from your home):
      sudo install -d -m 0755 /opt/keyflap/tools/pass-cli
      sudo install -o root -g root -m 0755 <the verified pass-cli> /opt/keyflap/tools/pass-cli/pass-cli
    (docs/integrations/proton-pass.md)"
  else
    bad=$(tool_problem "$pp_bin" pass-cli)
    [[ -z $bad ]] || problem "the signer would refuse pass-cli: $bad.
    Install it as root into /opt/keyflap/tools/pass-cli/ (from Proton's download or your distribution's
    package, never a copy from your home) and pass --proton-pass-bin /opt/keyflap/tools/pass-cli/pass-cli"
  fi
fi
if [[ $password_source == 1password ]]; then
  # Never from a user's PATH or home: the signer runs it as the uid that holds the KEK.
  if [[ -z $op_bin ]]; then
    for c in /opt/keyflap/tools/op/op /usr/local/bin/op /usr/bin/op; do
      if [[ -e $c ]]; then op_bin=$c; break; fi
    done
  fi
  if [[ -z $op_bin ]]; then
    problem "op (the 1Password CLI) not found in /opt/keyflap/tools/op/, /usr/local/bin or /usr/bin. Install
    it as root, from 1Password's apt/dnf repository or its signed release (never a copy from your home):
      sudo install -d -m 0755 /opt/keyflap/tools/op
      sudo install -o root -g root -m 0755 <the verified op> /opt/keyflap/tools/op/op
    (docs/integrations/1password.md)"
  else
    bad=$(tool_problem "$op_bin" op)
    [[ -z $bad ]] || problem "the signer would refuse op: $bad.
    Install it as root into /opt/keyflap/tools/op/ (from 1Password's repository or signed release, never
    a copy from your home) and pass --op-bin /opt/keyflap/tools/op/op"
  fi
  if [[ -n $op_token_file ]]; then
    if [[ ! -f $op_token_file ]]; then
      problem "--op-token-file $op_token_file is not a file"
    elif ! grep -q '[^[:space:]]' "$op_token_file"; then
      # Sealed empty, every read would fail later with only source_token_missing in the log.
      problem "--op-token-file $op_token_file is empty"
    fi
  elif [[ ! -f /etc/keyflap/credentials/op-service-account-token.cred && ! -t 0 ]]; then
    problem "--password-source 1password needs the service account token: --op-token-file FILE (or run in a terminal to be prompted)"
  fi
fi

if [[ ${#problems[@]} -gt 0 ]]; then
  echo "install: this machine isn't ready; nothing was changed:" >&2
  for p in "${problems[@]}"; do echo "  - $p" >&2; done
  exit 1
fi

# The only question, asked before anything changes.
op_token=''
if [[ $password_source == 1password && -z $op_token_file && ! -f /etc/keyflap/credentials/op-service-account-token.cred ]]; then
  read -r -s -p "1Password service account token (not echoed): " op_token </dev/tty; echo >&2
  [[ -n $op_token ]] || die "no token given"
  pg_in_place=0
fi

new_version=$(cat "$bundle/app/VERSION" 2>/dev/null || cut -c1-12 "$bundle/app/REVISION" 2>/dev/null || echo unknown)
stage=''
trap 'code=$?; [[ -z $stage ]] || rm -rf "$stage"; progress_exit $code' EXIT

# ---- progress: on a terminal, a bar and a log; elsewhere the plain lines -------------------
upgrade=0
[[ -f /etc/systemd/system/keyflap-core.service ]] && upgrade=1
fetch_node=0 fetch_chromium=0
[[ -n $node_dir || -n $node_tarball ]] || fetch_node=1
[[ -n $browsers_dir || ( -d /opt/keyflap/browsers/chromium-$CHROMIUM_REVISION && -d /opt/keyflap/browsers/chromium_headless_shell-$CHROMIUM_REVISION ) ]] ||
  fetch_chromium=1
steps=$((6 + upgrade + fetch_chromium + start))
[[ -n $node_dir ]] || steps=$((steps + 1 + fetch_node))
progress_init "install · $new_version"
if [[ $pg_view -eq 1 ]]; then
  [[ ! -L /var/log/keyflap ]] || rm -f /var/log/keyflap
  install -d -m 0700 -o root -g root /var/log/keyflap
fi
progress_start "$steps" "$(keyflap_install_log linux)"

# ---- stop a running install (upgrade) ------------------------------------------------
if [[ $upgrade -eq 1 ]]; then
  old_version=$(cat /opt/keyflap/app/VERSION 2>/dev/null || cut -c1-12 /opt/keyflap/app/REVISION 2>/dev/null || echo unknown)
  progress_step 'Stopping Keyflap' "upgrading $old_version -> $new_version: stopping the running services (state and credentials are kept)"
  # The sockets too: an open phone page (or an agent) would otherwise socket-activate a
  # service again mid-upgrade, and that old process would keep holding the approver port.
  systemctl stop keyflap-approver.socket keyflap-core-approver.socket keyflap-core-intent.socket \
    keyflap-core-admin.socket keyflap-signer.socket keyflap-signer-admin.socket \
    keyflap-approver.service keyflap-core.service keyflap-signer.service 2>/dev/null || true
  if [[ -n $xvfb ]] && grep -q '"mode": "headless"' /etc/keyflap/core.json 2>/dev/null; then
    echo "    note: the managed browser now runs headed on Xvfb (the default since this release);"
    echo "    sites that bound a session to the headless user agent may ask for a fresh sign-in."
    echo "    Re-run with --headless to keep it headless."
    progress_warn "The browser now runs headed on Xvfb, so some sites may ask for a fresh sign-in. Re-run with --headless to keep it headless."
  fi
else
  progress_step '' "installing $new_version"
fi


# ---- users ---------------------------------------------------------------------------
progress_step 'Creating service users' "service users keyflap-core, keyflap-signer, keyflap-web"
install -D -m 0644 "$here/sysusers.conf" /etc/sysusers.d/keyflap.conf
systemd-sysusers /etc/sysusers.d/keyflap.conf

# ---- code and runtime, root-owned ------------------------------------------------------
progress_step 'Copying Keyflap' "code and runtime in /opt/keyflap"
install -d -m 0755 -o root -g root /opt/keyflap /opt/keyflap/tools
# Earlier releases copied pass-cli here from the user's PATH: never run that copy again.
rm -f /opt/keyflap/bin/pass-cli
rmdir /opt/keyflap/bin 2>/dev/null || true
stage=$(mktemp -d /opt/keyflap/.stage.XXXXXX)

# Fresh root-owned copies: nothing here may stay linked to a user-writable file.
cp -r --no-preserve=ownership "$bundle/app" "$stage/app"
# pnpm's links are relative and stay inside the app; refuse anything pointing elsewhere.
while IFS= read -r -d '' link; do
  target=$(readlink -f "$link" || true)
  [[ $target == "$stage/app/"* ]] || die "bundle symlink points outside the app: ${link#"$stage/"}"
done < <(find "$stage/app" -type l -print0)

if [[ -n $node_dir ]]; then
  cp -rL --no-preserve=ownership "$node_dir" "$stage/node"
else
  # Verify and unpack the same root-owned copy (the release dir may be writable by you).
  if [[ -n $node_tarball ]]; then
    install -m 0600 "$node_tarball" "$stage/node.tar.xz"
  else
    progress_step 'Downloading Node' "downloading Node $NODE_VERSION (linux-$arch)"
    node_url=https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$arch.tar.xz
    if [[ $pg_view -eq 1 ]]; then
      progress_watch curl "$stage/node.progress"
      curl -fSL --proto '=https' --tlsv1.2 -o "$stage/node.tar.xz" "$node_url" 2>"$stage/node.progress" ||
        { tr '\r' '\n' <"$stage/node.progress" | grep '^curl:' >&2; die "the Node download failed"; }
    else
      curl -fsSL --proto '=https' --tlsv1.2 -o "$stage/node.tar.xz" "$node_url"
    fi
  fi
  progress_step 'Unpacking Node' ''
  echo "$(node_sha256 linux "$arch")  $stage/node.tar.xz" | sha256sum -c --quiet - ||
    die "Node tarball checksum mismatch (expected node-v$NODE_VERSION-linux-$arch.tar.xz)"
  mkdir "$stage/node"
  tar -xJf "$stage/node.tar.xz" -C "$stage/node" --strip-components=1 --no-same-owner
  rm -f "$stage/node.tar.xz"
fi
"$stage/node/bin/node" --version | grep -q '^v22\.' || die "the runtime is not Node 22"

if [[ -n $browsers_dir ]]; then
  mkdir "$stage/browsers"
  for d in "$browsers_dir"/chromium-"$CHROMIUM_REVISION" "$browsers_dir"/chromium_headless_shell-"$CHROMIUM_REVISION"; do
    if [[ -d $d ]]; then cp -r --no-preserve=ownership "$d" "$stage/browsers/"; fi
  done
elif [[ -d /opt/keyflap/browsers/chromium-$CHROMIUM_REVISION && -d /opt/keyflap/browsers/chromium_headless_shell-$CHROMIUM_REVISION ]]; then
  # Upgrade: the pinned Chromium is already there, root-owned; keep it.
  cp -r /opt/keyflap/browsers "$stage/browsers"
else
  progress_step 'Downloading Chromium' "downloading Chromium $CHROMIUM_REVISION (Playwright's installer)"
  # Root runs Playwright's own installer from the root-owned copy in $stage. On a terminal its
  # per-10% lines move the bar; elsewhere they are dropped.
  playwright_out=/dev/null
  if [[ $pg_view -eq 1 ]]; then
    playwright_out=$stage/chromium.progress
    progress_watch playwright "$playwright_out"
  fi
  PLAYWRIGHT_BROWSERS_PATH=$stage/browsers "$stage/node/bin/node" \
    "$stage/app/packages/shim/node_modules/playwright/cli.js" install chromium >"$playwright_out"
  [[ $playwright_out == /dev/null ]] || cat "$playwright_out"
fi

chown -R root:root "$stage"
chmod -R u+rwX,go+rX,go-w "$stage"
find "$stage" -type f -perm /6000 -exec chmod ug-s {} +
for part in app node browsers; do
  rm -rf "/opt/keyflap/$part.old"
  [[ -e /opt/keyflap/$part ]] && mv "/opt/keyflap/$part" "/opt/keyflap/$part.old"
  mv "$stage/$part" "/opt/keyflap/$part"
  rm -rf "/opt/keyflap/$part.old"
done
NODE=/opt/keyflap/node/bin/node

# ---- secrets (systemd credentials) -----------------------------------------------------
progress_step 'Creating keys' "credentials in /etc/keyflap/credentials"
install -d -m 0755 -o root -g root /etc/keyflap
install -d -m 0700 -o root -g root /etc/keyflap/credentials
creds=/etc/keyflap/credentials
seal() { # seal NAME: stdin -> $creds/NAME.cred, sealed to this machine
  systemd-creds encrypt --with-key=auto --name="$1" - "$creds/$1.cred.tmp" 2>/dev/null
  chmod 0600 "$creds/$1.cred.tmp"
  mv "$creds/$1.cred.tmp" "$creds/$1.cred"
}
# The KEK protects the key store: never regenerated once it exists.
[[ -f $creds/kek.cred ]] || head -c 32 /dev/urandom | seal kek
[[ -f $creds/channel-key.cred ]] || head -c 32 /dev/urandom | seal channel-key
if [[ -n $tls_cert ]]; then
  seal approver-tls-cert <"$tls_cert"
  seal approver-tls-key <"$tls_key"
else
  rm -f "$creds/approver-tls-cert.cred" "$creds/approver-tls-key.cred"
fi
if [[ -n $apns_key ]]; then
  seal apns-key <"$apns_key"
else
  rm -f "$creds/apns-key.cred"
fi

# The 1Password service account token: only the signer reads it (LoadCredentialEncrypted=
# in a drop-in below), never a config file or a command line.
if [[ $password_source == 1password ]]; then
  if [[ -n $op_token_file ]]; then
    tr -d '\r\n' <"$op_token_file" | seal op-service-account-token
  elif [[ -n $op_token ]]; then
    printf '%s' "$op_token" | seal op-service-account-token
  fi
  unset op_token
else
  rm -f "$creds/op-service-account-token.cred"
fi

# ---- data dirs and the user's hook token -------------------------------------------------
progress_step 'Preparing data folders' "data in /var/lib/keyflap"
install -d -m 0711 -o root -g root /var/lib/keyflap
install -d -m 0700 -o keyflap-core -g keyflap-core /var/lib/keyflap/core
install -d -m 0700 -o keyflap-signer -g keyflap-signer /var/lib/keyflap/signer
# A fresh host token each install: one sealed copy for the core, one plain copy for the
# user's hook. The hook dir is recreated by root so no user-made symlink is followed.
# The agent tokens setup stored there (agent-<id>.token, read by `keyflap mcp-headers`) are
# shown only once and can't be re-issued, so an upgrade keeps them: read and written back
# as the user (a symlink in their own dir yields only what they could read anyway), only
# well-formed ones, and only when the dir already belonged to this user.
declare -A agent_tokens=()
hook=/var/lib/keyflap/hook
if [[ -d $hook && ! -L $hook && $(stat -c %U "$hook") == "$user" ]]; then
  for f in "$hook"/agent-*.token; do
    name=${f##*/}
    [[ $name =~ ^agent-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.token$ ]] || continue
    tok=$(runuser -u "$user" -- head -c 200 -- "$f" 2>/dev/null) || continue
    tok=${tok%$'\n'}
    [[ $tok =~ ^aab_agent_[A-Za-z0-9_-]{43}$ ]] || continue
    agent_tokens[$name]=$tok
  done
fi
rm -rf "$hook"
install -d -m 0700 -o root -g root "$hook"
(umask 077; "$NODE" -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url')+'\n')" >"$hook/host-token")
seal host-token <"$hook/host-token"
chown "$user:$user_group" "$hook" "$hook/host-token"
for name in "${!agent_tokens[@]}"; do
  printf '%s\n' "${agent_tokens[$name]}" |
    runuser -u "$user" -- sh -c 'umask 077; cat >"$1"' sh "$hook/$name"
done
unset agent_tokens tok

# ---- configuration -----------------------------------------------------------------------
progress_step 'Writing settings' "configuration in /etc/keyflap"
cfg_args=(--out-dir /etc/keyflap --approver-origin "$origin")
[[ -n $listen ]] && cfg_args+=(--approver-listen "$listen")
[[ -n $tls_cert ]] && cfg_args+=(--tls)
[[ -n $mcp_port ]] && cfg_args+=(--mcp-port "$mcp_port")
if [[ -n $apns_key ]]; then
  cfg_args+=(--apns-key-id "$apns_key_id" --apns-team-id "$apns_team_id" --apns-bundle-id "$apns_bundle_id")
  [[ $apns_sandbox -eq 1 ]] && cfg_args+=(--apns-sandbox)
  [[ $apns_generic -eq 1 ]] && cfg_args+=(--apns-generic)
fi
for d in "${high_risk[@]}"; do cfg_args+=(--high-risk "$d"); done
if [[ -n $pp_bin ]]; then
  # install-config.ts checks it again (tool.ts) and pins its SHA-256 in signer.json.
  cfg_args+=(--proton-pass-bin "$pp_bin")
  if [[ $kept_source -eq 1 && -n $kept_sha ]]; then cfg_args+=(--proton-pass-sha256 "$kept_sha"); fi
  [[ $pp_vault_set -eq 1 ]] && cfg_args+=(--proton-pass-vault "$pp_vault")
fi
if [[ -n $op_bin ]]; then
  # Checked again and pinned by install-config.ts, as for pass-cli.
  cfg_args+=(--op-bin "$op_bin")
  if [[ $kept_source -eq 1 && -n $kept_sha ]]; then cfg_args+=(--op-sha256 "$kept_sha"); fi
  [[ $op_vault_set -eq 1 ]] && cfg_args+=(--1password-vault "$op_vault")
fi
[[ -n $tailscale_bin ]] && cfg_args+=(--tailscale-bin "$tailscale_bin")
[[ -n $xvfb ]] && cfg_args+=(--xvfb "$xvfb")
[[ $ephemeral -eq 1 ]] && cfg_args+=(--ephemeral-browser)
"$NODE" --disable-warning=ExperimentalWarning /opt/keyflap/app/packages/cli/src/service/install-config.ts "${cfg_args[@]}"
chmod 0644 /etc/keyflap/core.json /etc/keyflap/signer.json /etc/keyflap/approver.json
# systemd binds the approver's listener (keyflap-approver.socket): an IP address and port.
listen_stream=$("$NODE" -e '
  const c = JSON.parse(require("node:fs").readFileSync("/etc/keyflap/approver.json", "utf8"));
  const net = require("node:net");
  const h = c.listen.host;
  if (!net.isIP(h)) process.exit(3);
  process.stdout.write((net.isIPv6(h) ? `[${h}]` : h) + ":" + c.listen.port);
') || die "--approver-listen must be an IP address and port in service mode (e.g. 127.0.0.1:8766)"

# ---- systemd -----------------------------------------------------------------------------
progress_step 'Adding the background services' "systemd units"
install -m 0644 "$here/tmpfiles.conf" /etc/tmpfiles.d/keyflap.conf
systemd-tmpfiles --create /etc/tmpfiles.d/keyflap.conf
for unit in keyflap-signer.service keyflap-signer.socket keyflap-signer-admin.socket keyflap-core.service \
  keyflap-core-admin.socket keyflap-core-approver.socket keyflap-approver.service; do
  install -m 0644 "$here/units/$unit" "/etc/systemd/system/$unit"
done
sed "s/@USER@/$user/g" "$here/units/keyflap-core-intent.socket" >/etc/systemd/system/keyflap-core-intent.socket
chmod 0644 /etc/systemd/system/keyflap-core-intent.socket
sed "s/@LISTEN@/$listen_stream/g" "$here/units/keyflap-approver.socket" >/etc/systemd/system/keyflap-approver.socket
chmod 0644 /etc/systemd/system/keyflap-approver.socket
rm -rf /etc/systemd/system/keyflap-core.service.d /etc/systemd/system/keyflap-approver.service.d \
  /etc/systemd/system/keyflap-signer.service.d
if [[ -z $pp_bin && -z $op_bin ]]; then
  # No password tool: the signer needs no network at all.
  install -d -m 0755 /etc/systemd/system/keyflap-signer.service.d
  cat >/etc/systemd/system/keyflap-signer.service.d/no-network.conf <<'EOF'
[Service]
RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX
EOF
fi
if [[ -n $op_bin ]]; then
  install -d -m 0755 /etc/systemd/system/keyflap-signer.service.d
  cat >/etc/systemd/system/keyflap-signer.service.d/1password.conf <<'EOF'
[Service]
LoadCredentialEncrypted=op-service-account-token:/etc/keyflap/credentials/op-service-account-token.cred
EOF
fi
if [[ -n $tls_cert ]]; then
  # TLS belongs to the approver front, which serves the page; the core never sees the key.
  install -d -m 0755 /etc/systemd/system/keyflap-approver.service.d
  cat >/etc/systemd/system/keyflap-approver.service.d/tls.conf <<'EOF'
[Service]
LoadCredentialEncrypted=approver-tls-cert:/etc/keyflap/credentials/approver-tls-cert.cred
LoadCredentialEncrypted=approver-tls-key:/etc/keyflap/credentials/approver-tls-key.cred
EOF
fi
if [[ -n $apns_key ]]; then
  install -d -m 0755 /etc/systemd/system/keyflap-core.service.d
  cat >/etc/systemd/system/keyflap-core.service.d/apns.conf <<'EOF'
[Service]
LoadCredentialEncrypted=apns-key:/etc/keyflap/credentials/apns-key.cred
EOF
fi
install -m 0755 -o root -g root "$here/keyflap-wrapper.sh" /usr/local/bin/keyflap
systemctl daemon-reload

sockets=(keyflap-signer.socket keyflap-signer-admin.socket keyflap-core-intent.socket keyflap-core-admin.socket
  keyflap-core-approver.socket keyflap-approver.socket)
services=(keyflap-signer.service keyflap-core.service keyflap-approver.service)
if [[ $start -eq 1 ]]; then
  progress_step 'Starting Keyflap' "starting"
  # Restart the sockets too, so an upgrade picks up a changed --approver-listen.
  systemctl enable "${sockets[@]}" >/dev/null
  systemctl restart "${sockets[@]}"
  systemctl enable "${services[@]}" >/dev/null
  systemctl restart "${services[@]}"
else
  systemctl enable "${sockets[@]}" "${services[@]}" >/dev/null
fi

if [[ -n $xvfb ]]; then browser="headed on a private Xvfb display ($xvfb)"; else browser=headless; fi
[[ $start -eq 1 ]] || browser="$browser; services not started (--no-start)"
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

Installed $new_version. The broker runs as keyflap-core / keyflap-signer, and the phone approver
page as keyflap-web on $listen_stream; your user ($user) reaches the broker only through MCP
(with an agent token) and the intent socket (your Claude Code hook).
Managed browser: $browser.

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
    progress_say
  else
    progress_finish "Installed Keyflap $new_version"
  fi
  if [[ -z ${KEYFLAP_PROGRESS_FROM:-} ]]; then
    if [[ $upgrade -eq 1 ]]; then progress_say "Check it: sudo keyflap status"; else progress_say "Next: sudo keyflap setup"; fi
  fi
  progress_say "Details: $pg_log"
fi
