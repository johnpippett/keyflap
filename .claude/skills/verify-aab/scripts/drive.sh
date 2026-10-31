#!/usr/bin/env bash
# Drives one mapped feature against the running sandbox, as an MCP agent would, and saves
# evidence to the evidence dir. Usage: scripts/drive.sh <feature>
#   features: passkey | password-totp | policy | agents-intents | status-audit | challenge |
#             persistence (restarts the sandbox daemon on the same data dir mid-way) |
#             handoff (restarts it with a simulated phone approver on loopback; run it last)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
feature="${1:-}"
case "$feature" in passkey|password-totp|policy|agents-intents|status-audit|challenge|persistence|handoff) ;; *) die "usage: drive.sh passkey|password-totp|policy|agents-intents|status-audit|challenge|persistence|handoff" ;; esac
load_run
log_invocation "scripts/drive.sh $feature"
mkdir -p "$EVID/$feature"
drive() { (cd "$RUN/home" && "${SBX[@]}" "REPO=$REPO" "RUN=$RUN" "EVID=$EVID" "${NODE[@]}" "$SKILL_DIR/scripts/drive.mjs" "$1") 2>&1 | tee -a "$EVID/$feature/drive.txt"; return "${PIPESTATUS[0]}"; }
: >"$EVID/$feature/drive.txt"
set +e
if [[ $feature == persistence ]]; then
  # Phase 1 signs in; then the owner restarts the broker; phase 2 checks the agent is still
  # signed in with no approval prompt.
  drive persistence-before; rc=$?
  if [[ $rc == 0 ]]; then
    echo "----- restarting the sandbox daemon on the same data dir -----" | tee -a "$EVID/$feature/drive.txt"
    (set -e; restart_daemon) 2>&1 | tee -a "$EVID/$feature/drive.txt"; rc=${PIPESTATUS[0]}
    [[ $rc == 0 ]] && { drive persistence-after; rc=$?; }
  fi
elif [[ $feature == handoff ]]; then
  # The owner switches the broker to the phone approver. Here the "phone" is a headless
  # Chromium with a virtual authenticator that drive.mjs starts inside the sandbox; the
  # approver listens on a free loopback port, http://approver.localhost (no TLS, no
  # Tailscale, no push service). Pairing a phone latches the key store to phone mode, so
  # the terminal approver can't approve in this sandbox afterwards: run this feature last.
  if ! grep -qx -- '--approver' "$RUN/daemon.args" 2>/dev/null; then
    port="$(free_port)"
    [[ $port =~ ^[0-9]+$ && $port != 8765 && $port != 8766 ]] || die "no free port ($port)"
    printf '%s\n' --approver phone --approver-origin "http://approver.localhost:$port" --approver-listen "127.0.0.1:$port" >"$RUN/daemon.args"
    echo "----- restarting the sandbox daemon with the phone approver on 127.0.0.1:$port -----" | tee -a "$EVID/$feature/drive.txt"
    # While it is stopped, also store a password-only item for hc.localhost (the handoff
    # RP from rp-server.mjs): a fill with password + TOTP re-verifies one phone assertion
    # per field, and the virtual authenticator's sign counter makes the second one fail
    # (see features/handoff.md, Gotchas).
    (set -e; stop_daemon
     printf '%s\n' 'correct horse battery staple' |
       (cd "$RUN/home" && with_pass "${NODE[@]}" "$MAIN" password add hc.localhost --username alice --data-dir "$DATA") >"$RUN/logs/password-add-hc.out" 2>&1
     start_daemon || { sed 's/^/daemon.err: /' "$RUN/logs/daemon.err" >&2; exit 1; }
     write_state) 2>&1 | tee -a "$EVID/$feature/drive.txt"; rc=${PIPESTATUS[0]}
  else
    rc=0
  fi
  [[ $rc == 0 ]] && { drive handoff; rc=$?; }
else
  drive "$feature"; rc=$?
fi
set -e
if [[ $rc == 0 ]]; then result "drive-$feature" PASS "see $EVID/$feature/"; else result "drive-$feature" FAIL "exit $rc, see $EVID/$feature/drive.txt"; exit 1; fi
