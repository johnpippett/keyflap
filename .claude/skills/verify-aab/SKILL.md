---
name: verify-aab
description: Prove a change to Keyflap (the `keyflap` broker) works by driving the real stack in an isolated sandbox. It starts its own daemon, signer, headless browser and local test relying party, then acts as an MCP agent and as the user (approvals, CLI). Use it after changing broker, signer, MCP, shim, approver, policy or CLI code, and whenever you must show that a sign-in flow still works. Never touches the user's live broker.
---

# verify-aab

Drive the real broker end to end, in a sandbox, and keep the evidence.

All commands run from the repo root. Set `V=.claude/skills/verify-aab/scripts` first.

## Read this first: the user's live broker

Assume the user runs a real broker on this machine: `keyflap daemon` on 127.0.0.1:8765 (MCP) and 8766 (phone approver), data in `~/.keyflap` (or `~/.aab`, its name before the rename), signer, possibly a headed Chromium and a real Proton Pass vault. Never stop, restart, drive or read it. Never run `keyflap` without `--data-dir` pointing into the sandbox. These scripts do that for you. Do not bypass them.

## What the sandbox is

`launch.sh` creates `/tmp/aabv-XXXXXX` (short on purpose: unix socket paths must stay under about 100 bytes). Inside it:

- A fake `HOME`, `TMPDIR` and `XDG_*` dirs. Every process starts with `env -i`, so it has no `DISPLAY`, `WAYLAND_DISPLAY`, D-Bus, proxy or token variables.
- A data dir (`data/`) with its own SQLite file, key store, host token and sockets. A random key-store passphrase lives in `passphrase` (mode 600). It is never printed or put in argv.
- A test RP on `rp.localhost` (free port) from `packages/test-rp`, plus three challenge-mode RPs on `waf.`, `cf.` and `text.rp.localhost` for the `challenge` feature. Never a third-party site.
- `keyflap daemon --unprotected --data-dir <sandbox>/data --mcp-port 0`: headless (no `--headed`), terminal approver, no phone approver, no Proton Pass.
- Playwright's browser cache is the only thing read from the real home (`~/.cache/ms-playwright`, read-only).
- Every process is tagged `VERIFY_RUN=<run dir>` in its environment. Cleanup finds processes by that tag and by parentage, never by name.

Paths the app reads (checked in source): `--data-dir` (default `~/.keyflap`) holds everything; `homedir()` is only used for that default and for display; `os.tmpdir()` holds Playwright's browser profile; Chromium's own config and cache follow `XDG_*`. All of these are inside the sandbox, and `doctor.sh` checks the open files to prove it. The signer is started with a bare environment (only `PATH`) and takes its paths from arguments.

## Launch

```bash
$V/launch.sh
```

It takes about 5 seconds. It checks for a patched Node (^22.23.4, ^24.22.1 or >= 26.12.1), makes the sandbox, records a fingerprint of the live broker, registers an agent `verify-agent`, stores a password + TOTP item for `rp.localhost` (the test RP's fixture login `alice`), starts the RP and the daemon, and waits for `Ctrl-C to stop.` in the daemon log. Ready means the MCP port answers and the intent socket exists. It writes the pointer file `~/.local/state/verify/aab/current.env`; the other scripts read it.

It refuses to start if a run is already recorded. Run `cleanup.sh` first.

## Doctor

```bash
$V/doctor.sh
```

Read-only. Run it after launch and whenever anything looks off. It exits 0 only if all of these hold:

- the daemon and RP pids are alive and are ours (command line has our `--data-dir`);
- we own the MCP and RP ports, and neither is 8765 or 8766;
- `git HEAD` is unchanged since launch and no `packages/*/src/**/*.ts` file is newer than the daemon (otherwise relaunch: the daemon runs old code);
- MCP answers 401 without a token and 200 with the agent token; the intent socket is mode 600; the signer socket exists;
- isolation: no process of ours has a `HOME` other than the sandbox, a desktop variable, or an open or mapped file under your real home except the read-only allowlist (browser cache, mise node, the repo, the run dir);
- the live broker's pids, start times and port owners match the launch-time fingerprint.

## Drive

```bash
$V/drive.sh passkey          # proof feature: enroll + sign in + denial
$V/drive.sh password-totp
$V/drive.sh policy
$V/drive.sh agents-intents
$V/drive.sh status-audit
$V/drive.sh challenge        # password fill answered by a human check -> "challenge"
$V/drive.sh persistence      # sign in, restart the sandbox daemon (same data dir), still signed in
$V/drive.sh handoff          # human check -> browser_handoff -> simulated phone live view -> Done; then the
                             # check-before-sign-in case: ONE approval for check + sign-in (run last)
```

`drive.sh` runs `drive.mjs` in the sandbox. It acts like the agent (MCP over HTTP with the agent token, using `connectAgent` from `packages/core/test/mcp-harness.ts`) and like the user (intents on the intent socket with the host token, y/N answers on the daemon's stdin FIFO, the `keyflap` CLI). Each step prints `PASS` or `FAIL`. It exits 1 if any step fails.

The recipes, selectors and expected end states are in `features/`. Start with `features/README.md`.

Run `passkey` on a fresh launch, and once per launch. A second passkey for the same site makes the broker deny with `ambiguous_credential` (by design). The driver checks this first and says so.

Prefer ARIA locators (`role` + `name`, `label`) like the scripts do. Do not use coordinates.

## Evidence

Evidence goes outside the repo: `~/.local/state/verify/aab/<UTC-timestamp>/`. Cleanup never deletes it.

| File | What it proves |
|---|---|
| `setup.txt`, `commands.log`, `results.log` | setup, exact script invocations with exit codes, every `RESULT` line |
| `run-record.md` | all of the above in one file, written by `cleanup.sh`; use it to repeat the run |
| `doctor.txt` | readiness and the isolation proof (env and open-file checks) |
| `live-before.txt`, `live-after.txt` | live broker pids, start times and port owners before and after |
| `<feature>/drive.txt` | the step log |
| `<feature>/steps.jsonl` | every MCP tool call and its result (no secrets: agents never get any) |
| `<feature>/prompt-N.txt` | the exact approval prompt the user would see |
| `<feature>/snapshot-*.txt` | accessibility snapshot of the page after each action |
| `<feature>/audit-tail.json`, `audit-verify.txt` | audit events and the hash-chain check |
| `daemon.out`, `daemon.err`, `rp.out` | process logs (copied at cleanup, before the sandbox is removed) |

Proof standards:

- Exercise the real path: MCP tools, intent socket, the `keyflap` CLI. Never call internals or test-only endpoints.
- Capture the action and the result, not just the final page. Check side effects too: audit events, the hash chain, the RP's page state.
- The approval prompt is the user's view. Assert it shows the verbatim words, the verified origin, the agent name and the credential type.
- No screenshots of the managed browser (the `handoff` feature saves viewport screenshots of the simulated *phone's* page, a separate browser). Attaching a CDP session to a managed page resets its WebAuthn environment (see CLAUDE.md), and the agent surface has no screenshot tool. The accessibility snapshot is the page evidence. If you ever add a screenshot of a separate Playwright page, use a viewport screenshot, not full-page (full-page hung about one run in four), and wait a moment after animations.
- Terminal-approver approvals carry `userVerified=false`. They cannot prove phone or high-risk behavior.

## Cleanup

```bash
$V/cleanup.sh
```

Run it at the end, and after every failed attempt. It is safe to run twice. It:

1. snapshots every pid it owns with its start time;
2. sends SIGTERM to the daemon and RP, waits up to 15 s, then SIGKILLs only leftovers that match the snapshot or the tag;
3. checks no process or listener of the run remains, and that the live broker fingerprint is unchanged;
4. copies the logs to the evidence dir, removes `/tmp/aabv-*` (the run dir only) and the pointer file;
5. confirms the evidence dir still exists and writes `run-record.md`.

It never kills by name and never removes evidence.

## Helpers

| Script | Invocation | Purpose |
|---|---|---|
| `scripts/lib.sh` | sourced by the others | sandbox env (`SBX`), `owned_pids`, `result`, live fingerprint |
| `scripts/launch.sh` | `$V/launch.sh` | start the sandbox stack |
| `scripts/doctor.sh` | `$V/doctor.sh` | read-only health and isolation check |
| `scripts/drive.sh` | `$V/drive.sh <feature>` | run one feature; saves evidence |
| `scripts/drive.mjs` | called by `drive.sh` | the feature recipes in code |
| `scripts/rp-server.mjs` | called by `launch.sh` | the repo's test RP on a free port |
| `scripts/cleanup.sh` | `$V/cleanup.sh` | stop, verify, remove sandbox, write run record |

`lib.sh` also has `start_daemon`, `write_state`, `restart_daemon` and `free_port` (used by `launch.sh`, by `drive.sh persistence`, which restarts the sandbox daemon on the same data dir, and by `drive.sh handoff`, which restarts it with the flags in `$RUN/daemon.args`).

Run a one-off `keyflap` command in the sandbox:

```bash
source $V/lib.sh && load_run && keyflap status --json --data-dir "$DATA"
```

## Needs approval (documented, not driven)

Do not drive these without the user's say-so. They cost money, act on the real desktop, or touch real accounts. See `features/needs-approval.md`.

- Phone approver with the user's real phone (`--approver phone`) and the iOS app: need the user's phone, Tailscale, push services. (`drive.sh handoff` uses a simulated phone on loopback inside the sandbox instead.)
- Proton Pass source (`--password-source proton-pass`): reads the user's real vault.
- `--headed`: opens a window on the user's desktop.
- Service mode install, uninstall: need root. `pnpm test:isolation`: podman or docker, systemd container.
- Any real third-party site.

## Not covered by this skill

- The repo's own suites (`pnpm test:unit`, `pnpm test:e2e`, `pnpm test:isolation`). Run them as CLAUDE.md says before pushing. This skill did not check whether they stay out of your real home or the repo tree (a test runner may write a cache).
- The security invariants. The skill checks some behavior (prompt content, fail-closed denial, no secret in logs and audit), but the invariant tests are in `packages/*/test/inv*`.
- allow-for grants, ask-strong, session TTL, high-risk sites, the denylist beyond `--deny`.
- macOS, and Node versions other than 26.7.0.

## If the product needs a change to isolate it

None was needed. If a future change adds a path the app reads outside `--data-dir`, `TMPDIR` or `XDG_*`, stop and tell the user. Do not patch product code to make the sandbox work.
