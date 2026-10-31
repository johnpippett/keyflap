#!/usr/bin/env bash
# Shared helpers for the verify-aab scripts. Source this file; do not run it.
set -euo pipefail
umask 077

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$SKILL_DIR/../../.." && pwd)"
REAL_HOME="$HOME"
STATE_ROOT="$REAL_HOME/.local/state/verify/aab"
POINTER="$STATE_ROOT/current.env"
PW_BROWSERS="${PLAYWRIGHT_BROWSERS_PATH:-$REAL_HOME/.cache/ms-playwright}"
NODE_BIN="$(command -v node || true)"
MAIN="$REPO/packages/cli/src/main.ts"

die() { echo "verify-aab: $*" >&2; exit 1; }
utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# starttime (clock ticks since boot) of a pid; empty if the pid is gone.
pid_start() { [[ -r /proc/$1/stat ]] && sed 's/.*) //' "/proc/$1/stat" | awk '{print $20}' || true; }

descendants() { local c; for c in $(pgrep -P "$1" 2>/dev/null || true); do echo "$c"; descendants "$c"; done; }

# Every pid this run started: processes tagged VERIFY_RUN=$RUN in their environment, plus
# all their descendants (the signer is spawned with a bare environment, so it carries no
# tag but is always a child of the tagged daemon). Found by tag and parentage, never by
# process name. The tag also catches processes that left the tree (e.g. crashpad handlers).
owned_pids() {
  local d p tagged=() all=()
  for d in /proc/[0-9]*; do
    p="${d#/proc/}"
    [[ $p == $$ ]] && continue
    if { tr '\0' '\n' <"$d/environ" | grep -qxF "VERIFY_RUN=$RUN"; } 2>/dev/null; then tagged+=("$p"); fi
  done
  for p in "${tagged[@]}"; do all+=("$p"); while IFS= read -r c; do [[ -n $c ]] && all+=("$c"); done < <(descendants "$p"); done
  [[ ${#all[@]} -gt 0 ]] && printf '%s\n' "${all[@]}" | sort -un
  return 0
}

# Sets RUN, EVID, DATA and the SBX prefix from the pointer file launch.sh wrote.
load_run() {
  [[ -f $POINTER ]] || die "no active run ($POINTER missing). Run scripts/launch.sh first."
  # shellcheck disable=SC1090
  source "$POINTER"
  [[ -d $RUN ]] || die "run dir $RUN is gone. Run scripts/cleanup.sh to clear the pointer."
  DATA="$RUN/data"
  build_sbx
}

# SBX: a command prefix that runs anything with a clean, sandboxed environment. No
# DISPLAY / WAYLAND_DISPLAY / DBUS: nothing can reach the desktop. No proxy, token or
# password-manager variables from the caller's shell.
build_sbx() {
  SBX=(env -i
    "PATH=$(dirname "$NODE_BIN"):/usr/bin:/bin"
    "HOME=$RUN/home" "TMPDIR=$RUN/tmp"
    "XDG_CONFIG_HOME=$RUN/xdg-config" "XDG_DATA_HOME=$RUN/xdg-data"
    "XDG_CACHE_HOME=$RUN/xdg-cache" "XDG_STATE_HOME=$RUN/xdg-state"
    "XDG_RUNTIME_DIR=$RUN/xdg-runtime"
    "PLAYWRIGHT_BROWSERS_PATH=$PW_BROWSERS"
    "LANG=C.UTF-8" "VERIFY_RUN=$RUN")
  NODE=("$NODE_BIN" --disable-warning=ExperimentalWarning)
}

# Runs "$@" in the sandbox with KEYFLAP_PASSPHRASE set from the run's passphrase file. The
# value never appears in any argv: sh reads it from the file and execs the command.
with_pass() {
  "${SBX[@]}" sh -c 'KEYFLAP_PASSPHRASE=$(cat "$1"); export KEYFLAP_PASSPHRASE; shift; exec "$@"' sh "$RUN/passphrase" "$@"
}

# keyflap CLI inside the sandbox (no passphrase). Extra args are the keyflap args.
keyflap() { (cd "$RUN/home" && "${SBX[@]}" "${NODE[@]}" "$MAIN" "$@"); }

# Appends "RESULT <name> PASS|FAIL <detail>" to the evidence results log and stdout.
result() {
  local line="RESULT $1 $2 ${3:-}"
  echo "$line"
  [[ -n ${EVID:-} && -d ${EVID:-} ]] && echo "$(utc) $line" >>"$EVID/results.log" || true
}

# Logs the script's invocation and exit code to the evidence dir's commands.log.
log_invocation() {
  local cmd="$1"
  [[ -n ${EVID:-} && -d ${EVID:-} ]] || return 0
  echo "$(utc) START $cmd" >>"$EVID/commands.log"
  # shellcheck disable=SC2064
  trap "echo \"\$(utc) END   $cmd -> exit \$?\" >>\"$EVID/commands.log\"" EXIT
}

# Fingerprint of the user's live broker, from process and socket tables only. It reads no
# live data: just pids, start times, command lines and port owners. Compared before/after.
live_fingerprint() {
  local p mine=" "
  # Exclude everything this run started, so the fingerprint is the live broker only.
  [[ -n ${RUN:-} ]] && mine=" $(owned_pids | tr '\n' ' ')"
  echo "## processes running the broker or signer entry points (pid start cmd)"
  for p in $(pgrep -f 'packages/(cli|signer)/src/main.ts' 2>/dev/null | sort -n || true); do
    [[ -r /proc/$p/cmdline ]] || continue
    [[ $mine == *" $p "* ]] && continue
    echo "pid=$p start=$(pid_start "$p") cmd=$(tr '\0' ' ' <"/proc/$p/cmdline")"
  done
  echo "## listeners on 8765 and 8766 (live broker MCP and phone approver ports)"
  ss -ltnpH 2>/dev/null | awk '$4 ~ /:(8765|8766)$/ {print $4, $6}' | sort || true
}

# Starts `keyflap daemon` in the sandbox (headless, terminal approver, --mcp-port 0) and waits
# for it. stdin is the approve FIFO, opened read-write so it never sees EOF: drive.mjs
# answers the y/N prompts by writing to it. Needs RUN, DATA, SBX, NODE. Sets DAEMON_PID.
# Extra daemon flags (the `handoff` feature's simulated phone approver on loopback) come
# from $RUN/daemon.args, one per line, so a restart keeps the mode.
start_daemon() {
  local extra=()
  [[ -s $RUN/daemon.args ]] && mapfile -t extra <"$RUN/daemon.args"
  [[ -p $RUN/approve.fifo ]] || mkfifo "$RUN/approve.fifo"
  exec 3<>"$RUN/approve.fifo"
  (cd "$RUN/home" && exec "${SBX[@]}" sh -c 'KEYFLAP_PASSPHRASE=$(cat "$1"); export KEYFLAP_PASSPHRASE; shift; exec "$@"' sh "$RUN/passphrase" \
    "${NODE[@]}" "$MAIN" daemon --unprotected --data-dir "$DATA" --mcp-port 0 "${extra[@]}" \
    <&3 >"$RUN/logs/daemon.out" 2>"$RUN/logs/daemon.err") &
  DAEMON_PID=$!
  echo "$DAEMON_PID" >"$RUN/daemon.pid"
  exec 3>&-
  for _ in $(seq 1 150); do grep -q 'Ctrl-C to stop' "$RUN/logs/daemon.err" 2>/dev/null && break; sleep 0.2; done
  grep -q 'Ctrl-C to stop' "$RUN/logs/daemon.err" || return 1
}

# Writes $RUN/state.json from the RP and daemon logs (the daemon's MCP port is random).
write_state() {
  local rp_url rp_origin mcp_url intent_sock approver_origin
  rp_url="$(sed -n 's/.*"url":"\([^"]*\)".*/\1/p' "$RUN/logs/rp.out" | head -1)"
  rp_origin="$(sed -n 's/.*"origin":"\([^"]*\)".*/\1/p' "$RUN/logs/rp.out" | head -1)"
  mcp_url="$(sed -n 's/.*MCP endpoint: *\(\S*\).*/\1/p' "$RUN/logs/daemon.err" | head -1)"
  intent_sock="$(sed -n 's/.*intent socket: *\(\S*\).*/\1/p' "$RUN/logs/daemon.err" | head -1)"
  approver_origin="$(grep -A1 -x -- '--approver-origin' "$RUN/daemon.args" 2>/dev/null | tail -1 || true)"
  cat >"$RUN/state.json" <<JSON
{"rpUrl":"$rp_url","rpOrigin":"$rp_origin","mcpUrl":"$mcp_url","intentSocket":"$intent_sock","approverOrigin":"$approver_origin",
 "agentId":"$(cat "$RUN/agent.id")","daemonPid":$(cat "$RUN/daemon.pid"),"rpPid":$(cat "$RUN/rp.pid"),
 "dataDir":"$DATA","approveFifo":"$RUN/approve.fifo","daemonOut":"$RUN/logs/daemon.out"}
JSON
}

# A free loopback TCP port (asked from the kernel; never 8765 / 8766, which are taken).
free_port() { "${SBX[@]}" "${NODE[@]}" -e "const s=require('net').createServer().listen(0,'127.0.0.1',()=>{console.log(s.address().port);s.close()})"; }

# Stops the sandbox daemon (SIGTERM: it saves each agent's browser state, then closes the
# browser and the signer) and starts it again on the same data dir, as the owner would.
# The old logs are kept as daemon.<n>.out/.err. Only ever our own daemon pid.
restart_daemon() {
  stop_daemon
  start_daemon || { sed 's/^/daemon.err: /' "$RUN/logs/daemon.err" >&2; die "daemon did not come back"; }
  write_state
}

# The stop half of restart_daemon: SIGTERM to our daemon pid only, wait for it, its signer
# and its browser, and keep its logs as daemon.<n>.out/.err.
stop_daemon() {
  local pid n=1
  pid="$(cat "$RUN/daemon.pid")"
  tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -qF -- "--data-dir $DATA" || die "daemon pid $pid is not ours"
  kill -TERM "$pid"
  for _ in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
  kill -0 "$pid" 2>/dev/null && die "daemon $pid did not stop within 30 s"
  # The signer (its child) and Chromium go with it; wait until only the RP is left.
  for _ in $(seq 1 80); do [[ "$(owned_pids | grep -vx "$(cat "$RUN/rp.pid")" | wc -l)" == 0 ]] && break; sleep 0.25; done
  while [[ -e $RUN/logs/daemon.$n.out ]]; do n=$((n + 1)); done
  mv "$RUN/logs/daemon.out" "$RUN/logs/daemon.$n.out"
  mv "$RUN/logs/daemon.err" "$RUN/logs/daemon.$n.err"
}
