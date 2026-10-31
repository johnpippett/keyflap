#!/usr/bin/env bash
# Stops what this run started and removes its sandbox. Never touches the evidence dir,
# and never kills by process name: it signals only pids tagged VERIFY_RUN=<this run>.
# Safe to run twice, and after a failed launch. Usage: scripts/cleanup.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
[[ -f $POINTER ]] || { echo "nothing to clean (no $POINTER)"; exit 0; }
load_run
log_invocation "scripts/cleanup.sh"
exec > >(tee -a "$EVID/cleanup.txt") 2>&1
echo "== cleanup $(utc) =="

[[ $RUN == /tmp/aabv-* && ! -L $RUN ]] || die "refusing to remove unexpected run dir: $RUN"
[[ $EVID == "$STATE_ROOT"/* ]] || die "refusing: evidence dir outside $STATE_ROOT: $EVID"

# Snapshot "pid starttime" for everything this run owns (tagged pids and descendants), so
# an orphan (e.g. the signer after its parent dies) can still be matched, and a reused pid
# never is.
snap="$(for p in $(owned_pids); do echo "$p $(pid_start "$p")"; done)"
echo "owned pids before stop: $(awk '{printf "%s ", $1}' <<<"$snap")"
alive_snap() { local p st; while read -r p st; do [[ -n $p && -n $st && "$(pid_start "$p")" == "$st" ]] && echo "$p"; done <<<"$snap"; }

# 1. Graceful: ask the daemon and the RP to stop (the daemon tears down signer + browser).
for f in daemon.pid rp.pid; do
  if [[ -s $RUN/$f ]]; then
    p="$(cat "$RUN/$f")"
    grep -qE "^$p " <<<"$snap" && kill -TERM "$p" 2>/dev/null || true
  fi
done
for _ in $(seq 1 60); do [[ -z "$(alive_snap)$(owned_pids)" ]] && break; sleep 0.25; done

# 2. Whatever is left (same pid AND start time as the snapshot, or still tagged) gets SIGKILL.
for p in $( { alive_snap; owned_pids; } | sort -un ); do
  echo "still running after SIGTERM: pid $p ($(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null | cut -c1-90)); SIGKILL"
  kill -KILL "$p" 2>/dev/null || true
done
sleep 0.5

# 3. Confirm nothing is left: processes, listeners, sockets, temp dirs.
fail=0
rest="$( { alive_snap; owned_pids; } | sort -un | tr '\n' ' ')"
[[ -z $rest ]] && echo "ok    none of the run's processes remain (checked by pid+start time and by env tag)" || { echo "FAIL  still running: $rest"; fail=1; }
for f in daemon.pid rp.pid; do
  if [[ -s $RUN/$f ]]; then p="$(cat "$RUN/$f")"; ss -ltnpH 2>/dev/null | grep -q "pid=$p," && { echo "FAIL  pid $p still listening"; fail=1; }; fi
done
[[ $fail == 0 ]] && echo "ok    no listener from this run remains"

# 4. Live broker still identical (only if we have the launch-time fingerprint).
if [[ -f $EVID/live-before.txt ]]; then
  live_fingerprint >"$RUN/live-after.txt"
  cp "$RUN/live-after.txt" "$EVID/live-after.txt"
  if diff <(grep -v '^#' "$EVID/live-before.txt") <(grep -v '^#' "$RUN/live-after.txt") >/dev/null; then
    echo "ok    live broker pids, start times and port owners unchanged"
  else
    echo "FAIL  live broker fingerprint changed (diff live-before.txt live-after.txt)"; fail=1
  fi
  stat -c '%n %s %Y' "$REAL_HOME"/.keyflap/* "$REAL_HOME"/.aab/* 2>/dev/null >"$EVID/live-stat-after.txt" || true
  diff -q "$EVID/live-stat-before.txt" "$EVID/live-stat-after.txt" >/dev/null 2>&1 &&
    echo "ok    live data dir file names, sizes and mtimes identical" ||
    echo "note  live data dir metadata differs; the live daemon writes its own files. Check that no pid of this run had it open (doctor.txt)."
fi

# 5. Remove the sandbox (the run dir only) and the pointer. Evidence stays.
if [[ $fail == 0 ]]; then
  # daemon.<n>.* are the logs of earlier daemons of this run (drive.sh persistence restarts it).
  for f in "$RUN"/logs/daemon*.out "$RUN"/logs/daemon*.err; do [[ -f $f ]] && cp "$f" "$EVID/" || true; done
  cp "$RUN/logs/rp.out" "$EVID/rp.out" 2>/dev/null || true
  rm -rf -- "$RUN"
  [[ ! -e $RUN ]] && echo "ok    removed $RUN" || { echo "FAIL  could not remove $RUN"; fail=1; }
  rm -f -- "$POINTER"
fi

[[ -d $EVID ]] && echo "ok    evidence still exists: $EVID ($(ls "$EVID" | wc -l) entries)" || { echo "FAIL  evidence dir is missing"; fail=1; }

# 6. Write the run record from the logs the scripts kept.
if [[ $fail == 0 ]]; then result cleanup PASS "no strays; evidence kept"; else result cleanup FAIL "see above"; fi
{
  echo "# verify-aab run record"
  echo
  cat "$EVID/setup.txt" 2>/dev/null
  echo
  echo "## Commands (exact, in order)"
  echo '```'; cat "$EVID/commands.log" 2>/dev/null; echo '```'
  echo
  echo "## Results"
  echo '```'; cat "$EVID/results.log" 2>/dev/null; echo '```'
  echo
  echo "## Files in this evidence dir"
  (cd "$EVID" && find . -type f | sort | sed 's/^/- /')
  echo
  echo "Repeat: scripts/launch.sh, scripts/doctor.sh, scripts/drive.sh <feature>, scripts/cleanup.sh (see .claude/skills/verify-aab/SKILL.md)."
} >"$EVID/run-record.md"


[[ $fail == 0 ]] || exit 1
