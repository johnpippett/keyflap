#!/usr/bin/env bash
# Starts an isolated broker stack for verification: sandbox dirs, the test RP, and
# `keyflap daemon` (headless, terminal approver) on free ports. Prints the run and evidence dirs.
# Usage: scripts/launch.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -x $NODE_BIN ]] || die "node not found on PATH"
# Patched release per Node line (packages/cli/src/doctor.ts MIN_NODE, CVE-2026-111497).
"$NODE_BIN" -e 'const v=process.versions.node.split(".").map(Number), m={22:[23,4],24:[22,1],26:[12,1]}[v[0]]; process.exit(v[0]>26||(m&&(v[1]>m[0]||(v[1]===m[0]&&v[2]>=m[1])))?0:1)' || die "need node ^22.23.4, ^24.22.1 or >= 26.12.1"
[[ -d $REPO/node_modules ]] || die "run pnpm install first (the user's call; this skill never installs)"
[[ -d $PW_BROWSERS ]] || die "Playwright browsers not found at $PW_BROWSERS"
[[ ! -f $POINTER ]] || die "a run is already recorded in $POINTER. Run scripts/cleanup.sh first."

mkdir -p -m 700 "$STATE_ROOT"
EVID="$STATE_ROOT/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p -m 700 "$EVID"
# Short path on purpose: unix socket paths must stay under ~100 bytes.
RUN="$(mktemp -d /tmp/aabv-XXXXXX)"
mkdir -p "$RUN"/{home,tmp,xdg-config,xdg-data,xdg-cache,xdg-state,xdg-runtime,data,logs}
printf 'RUN=%q\nEVID=%q\n' "$RUN" "$EVID" >"$POINTER"
DATA="$RUN/data"
load_run
log_invocation "scripts/launch.sh"

{
  echo "# Setup"
  echo "- started: $(utc)"
  echo "- repo: $REPO  HEAD $(git -C "$REPO" rev-parse --short HEAD)  dirty-files: $(git -C "$REPO" status --porcelain | wc -l)"
  echo "- node: $("$NODE_BIN" -v) ($NODE_BIN)"
  echo "- sandbox run dir: $RUN (HOME, TMPDIR, XDG_*, data dir all inside)"
  echo "- evidence dir: $EVID"
  echo "- playwright browsers (read-only): $PW_BROWSERS"
} | tee "$EVID/setup.txt"

live_fingerprint >"$EVID/live-before.txt"
# Metadata only (names, sizes, mtimes), never contents. The live daemon may write its own files meanwhile.
stat -c '%n %s %Y' "$REAL_HOME"/.keyflap/* "$REAL_HOME"/.aab/* 2>/dev/null >"$EVID/live-stat-before.txt" || true
echo "live broker fingerprint saved: $EVID/live-before.txt"

# Random key-store passphrase for this sandbox only. Never printed or put in argv.
head -c 24 /dev/urandom | base64 >"$RUN/passphrase"

# Seed: one agent, and one native password item (the test RP's documented fixture
# credentials). `keyflap password add` needs the daemon stopped, so seed before the start.
out="$RUN/agent-add.out"
keyflap agent add verify-agent --data-dir "$DATA" >"$out"
grep -oE 'aab_agent_[A-Za-z0-9_-]{43}' "$out" | head -1 >"$RUN/agent.token"
grep -oE '\(id [^)]+\)' "$out" | head -1 | sed 's/(id //; s/)//' >"$RUN/agent.id"
rm -f "$out"
[[ -s $RUN/agent.token && -s $RUN/agent.id ]] || die "could not read the agent token/id from 'keyflap agent add'"
printf '%s\n%s\n' 'correct horse battery staple' 'JBSWY3DPEHPK3PXP' |
  (cd "$RUN/home" && with_pass "${NODE[@]}" "$MAIN" password add rp.localhost --username alice --totp --data-dir "$DATA") >"$RUN/logs/password-add.out" 2>&1 ||
  { cat "$RUN/logs/password-add.out" >&2; die "password add failed"; }

# Test RP on rp.localhost, free port. Backgrounded as a simple command (env execs sh, sh
# execs node) so $! is the node pid itself.
cd "$RUN/home"
touch "$RUN/started"
"${SBX[@]}" "REPO=$REPO" "${NODE[@]}" "$SKILL_DIR/scripts/rp-server.mjs" >"$RUN/logs/rp.out" 2>"$RUN/logs/rp.err" &
echo $! >"$RUN/rp.pid"
for _ in $(seq 1 50); do grep -q '"origin"' "$RUN/logs/rp.out" 2>/dev/null && break; sleep 0.2; done
grep -q '"origin"' "$RUN/logs/rp.out" || { cat "$RUN/logs/rp.err" >&2; die "test RP did not start"; }
RP_URL="$(sed -n 's/.*"url":"\([^"]*\)".*/\1/p' "$RUN/logs/rp.out" | head -1)"
RP_ORIGIN="$(sed -n 's/.*"origin":"\([^"]*\)".*/\1/p' "$RUN/logs/rp.out" | head -1)"

# The daemon (lib.sh start_daemon): headless, terminal approver, answers through a FIFO.
start_daemon || { sed 's/^/daemon.err: /' "$RUN/logs/daemon.err" >&2; bash "$SKILL_DIR/scripts/cleanup.sh" >&2 || true; die "daemon did not become ready"; }
MCP_URL="$(sed -n 's/.*MCP endpoint: *\(\S*\).*/\1/p' "$RUN/logs/daemon.err" | head -1)"
INTENT_SOCK="$(sed -n 's/.*intent socket: *\(\S*\).*/\1/p' "$RUN/logs/daemon.err" | head -1)"
write_state
git -C "$REPO" rev-parse HEAD >"$RUN/head"

{
  echo "- test RP: $RP_ORIGIN  (pid $(cat "$RUN/rp.pid"))"
  echo "- MCP endpoint: $MCP_URL  (daemon pid $(cat "$RUN/daemon.pid"))"
  echo "- intent socket: $INTENT_SOCK"
  echo "- agent: verify-agent id $(cat "$RUN/agent.id") (token kept in $RUN/agent.token, 0600; never printed)"
  echo "- seeded: password+TOTP item for rp.localhost / alice (test RP fixture credentials)"
} | tee -a "$EVID/setup.txt"
echo "READY. Next: scripts/doctor.sh, then scripts/drive.sh <feature>. Evidence: $EVID"
