#!/usr/bin/env bash
# Read-only check: is the running instance ours, current, ready, and isolated from the
# user's live broker? Run it first whenever anything looks off. Exit 0 = worth driving.
# Usage: scripts/doctor.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_run
log_invocation "scripts/doctor.sh"
exec > >(tee -a "$EVID/doctor.txt") 2>&1
echo "== doctor $(utc) =="

fails=0
ok()   { echo "ok    $*"; }
bad()  { echo "FAIL  $*"; fails=$((fails + 1)); }
check() { local msg="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg"; fi; }

state() { sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",}]*\).*/\1/p" "$RUN/state.json" | head -1; }
DPID="$(state daemonPid)"; RPID="$(state rpPid)"; MCP_URL="$(state mcpUrl)"
MCP_PORT="${MCP_URL##*:}"; MCP_PORT="${MCP_PORT%%/*}"
RP_PORT="$(state rpOrigin)"; RP_PORT="${RP_PORT##*:}"
SOCK="$(state intentSocket)"

# 1. Our processes are up and are what we think they are.
check "daemon pid $DPID is alive" kill -0 "$DPID"
tr '\0' ' ' <"/proc/$DPID/cmdline" 2>/dev/null | grep -qF -- "$MAIN daemon --unprotected --data-dir $DATA --mcp-port 0" &&
  ok "daemon command line has our data dir and --mcp-port 0 (not the live one)" || bad "daemon command line is not ours"
check "test RP pid $RPID is alive" kill -0 "$RPID"

# 2. We own the ports.
ss -ltnpH 2>/dev/null | awk -v p=":$MCP_PORT\$" '$4 ~ p' | grep -q "pid=$DPID," && ok "MCP port $MCP_PORT is owned by daemon pid $DPID" || bad "MCP port $MCP_PORT is not owned by our daemon"
ss -ltnpH 2>/dev/null | awk -v p=":$RP_PORT\$" '$4 ~ p' | grep -q "pid=$RPID," && ok "RP port $RP_PORT is owned by RP pid $RPID" || bad "RP port $RP_PORT is not owned by our RP"
case "$MCP_PORT:$RP_PORT" in 8765:*|8766:*|*:8765|*:8766) bad "a sandbox port collides with the live broker ports" ;; *) ok "no sandbox port is 8765 or 8766" ;; esac

# 3. Right build: same commit as at launch, and no source newer than the process.
[[ "$(git -C "$REPO" rev-parse HEAD)" == "$(cat "$RUN/head")" ]] && ok "git HEAD unchanged since launch ($(cut -c1-9 "$RUN/head"))" || bad "git HEAD moved since launch: relaunch"
newer="$(find "$REPO"/packages/*/src -name '*.ts' -newer "$RUN/started" 2>/dev/null | head -3)"
[[ -z $newer ]] && ok "no source file is newer than the running daemon" || bad "source changed after launch (relaunch): $newer"

# 4. Ready means usable: auth works, the socket is private, the agent lists seven tools.
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$MCP_URL" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d '{}')"
[[ $code == 401 ]] && ok "MCP rejects a request with no agent token (401)" || bad "MCP without a token answered $code (want 401)"
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$MCP_URL" -H "authorization: Bearer $(cat "$RUN/agent.token")" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"doctor","version":"1"}}}')"
[[ $code == 200 ]] && ok "MCP initialize with the agent token answers 200" || bad "MCP initialize answered $code (want 200)"
[[ "$(stat -c %a "$SOCK" 2>/dev/null)" == 600 ]] && ok "intent socket exists with mode 600" || bad "intent socket missing or not mode 600"
[[ -S $DATA/run/signer.sock ]] && ok "signer socket exists" || bad "signer socket missing"
curl -s -o /dev/null -w '%{http_code}' "$(state rpOrigin)/" | grep -q 200 && ok "test RP answers 200" || bad "test RP does not answer"
# The handoff feature's simulated phone approver (loopback, never the live 8766).
APPROVER="$(state approverOrigin)"
if [[ -n $APPROVER ]]; then
  AP_PORT="${APPROVER##*:}"
  [[ $AP_PORT != 8765 && $AP_PORT != 8766 ]] && ok "approver port $AP_PORT is not a live broker port" || bad "approver port collides with the live broker"
  ss -ltnpH 2>/dev/null | awk -v p="127.0.0.1:$AP_PORT\$" '$4 ~ p' | grep -q "pid=$DPID," && ok "approver listens on 127.0.0.1:$AP_PORT (our daemon)" || bad "approver port $AP_PORT is not our daemon's loopback listener"
fi

# 5. Isolation proof: every process this run started.
owned="$(owned_pids | sort -n | tr '\n' ' ')"
n="$(wc -w <<<"$owned")"
echo "-- isolation: $n processes carry VERIFY_RUN=$RUN"
[[ $n -ge 3 ]] && ok "run owns $n processes (daemon, signer, browser, RP, helpers)" || bad "run owns only $n processes"
allow=("$PW_BROWSERS/" "$REAL_HOME/.local/share/mise/" "$REPO/" "$RUN/")
viol=0; withhome=0; bare=0
for p in $owned; do
  envf="/proc/$p/environ"; [[ -r $envf ]] || continue
  e="$(tr '\0' '\n' <"$envf")"
  # A bare environment (the signer; Chromium's zygote children) has no HOME at all: fine.
  # A HOME that is not the sandbox is not.
  if grep -q '^HOME=' <<<"$e"; then
    grep -qx "HOME=$RUN/home" <<<"$e" && withhome=$((withhome + 1)) || { echo "  pid $p: HOME is not the sandbox"; viol=1; }
  else
    bare=$((bare + 1))
  fi
  grep -qE '^(DISPLAY|WAYLAND_DISPLAY|DBUS_SESSION_BUS_ADDRESS|XDG_SESSION_ID)=' <<<"$e" && { echo "  pid $p: desktop variable present"; viol=1; }
  # Open files and mapped files under the real HOME, other than the read-only allowlist.
  while IFS= read -r f; do
    [[ $f == "$REAL_HOME"/* ]] || continue
    a=0; for pre in "${allow[@]}"; do [[ $f == "$pre"* ]] && a=1; done
    [[ $a == 1 ]] || { echo "  pid $p: touches $f"; viol=1; }
  done < <({ ls -l "/proc/$p/fd" 2>/dev/null | awk '{print $NF}'; awk '{print $6}' "/proc/$p/maps" 2>/dev/null; readlink "/proc/$p/cwd" 2>/dev/null; } | sort -u)
done
echo "-- $withhome process(es) have HOME=$RUN/home; $bare have a bare environment (no HOME)"
[[ $viol == 0 ]] && ok "no owned process has the real HOME, a desktop variable, or a file under your home beyond the read-only allowlist (browser cache, mise node, repo, run dir)" || bad "isolation violation (see above)"

# 6. The live broker is untouched.
live_fingerprint >"$RUN/live-now.txt"
if diff <(grep -v '^#' "$EVID/live-before.txt") <(grep -v '^#' "$RUN/live-now.txt") >"$RUN/live.diff" 2>&1; then
  ok "live broker processes and port owners are identical to the launch-time fingerprint"
else
  bad "live broker fingerprint changed:"; cat "$RUN/live.diff"
fi

if [[ $fails -eq 0 ]]; then result doctor PASS "all checks ok, $n owned processes"; else result doctor FAIL "$fails check(s) failed"; exit 1; fi
