# Saved browser sessions across a restart (`persistence`)

The agent signs in once; the owner restarts the broker; the agent is still signed in with no approval prompt. The saved state is encrypted, `0600`, and listed by counts only (SESSIONS_PLAN section 2).

## Sub-features

- `ps-save` after a broker login the agent's state is saved to `<data dir>/browser-state/<agentId>.state` (0600 in a 0700 dir), an `{v, iv, tag, ct}` envelope with no cookie name, host or user in plaintext.
- `ps-list` `keyflap sessions list --json` shows `rp.localhost` with a cookie count and no values; `keyflap status` shows `Saved sessions: 1 agents, N sites`.
- `ps-restart` after `SIGTERM` and a fresh `keyflap daemon` on the same data dir, `browser_open <rp>account` lands on the account page, `Signed in as alice`, with no prompt in the new daemon's output.
- `ps-audit` the audit since the restart has `browser_state.restored` (sites and counts only) and no `request`, `approval`, `fill.released` or `passkey.signed`; the chain verifies.

## How to get to it (user POV)

- The user stops the daemon (Ctrl-C) and starts it again. Nothing else: persistence is on by default (`--ephemeral-browser` turns it off).
- `keyflap sessions list | clear | keep | unkeep` inspect and change it.

## Driving it with verify-aab

Preconditions:

- `scripts/doctor.sh` printed `RESULT doctor PASS`.
- Can run after `password-totp` (already signed in: no prompt in phase 1) or on a fresh launch (phase 1 answers one prompt `y`).

- **Run all of it.** `scripts/drive.sh persistence`. Exit code `0`. It runs `drive.mjs persistence-before`, then `restart_daemon` from `lib.sh` (SIGTERM to our daemon pid only, wait for it and its signer and browser to exit, keep its logs as `daemon.1.out/err`, start a new daemon on the same data dir, rewrite `state.json`), then `drive.mjs persistence-after`.
- **Proof.** `<evidence dir>/persistence/`: `snapshot-before-restart.txt`, `sessions-list-before.json`, `status-before.txt`, `snapshot-after-restart.txt`, `audit-since-restart.json`, `audit-verify.txt`, `drive.txt` (with the restart in the middle); the old daemon's logs are copied as `daemon.1.out` / `daemon.1.err` at cleanup.

## Gotchas

- Run `scripts/doctor.sh` again after this feature if you drive more: the daemon pid and MCP port changed (the new values are in `state.json`).
- The restart is the sandbox daemon only (pid from `daemon.pid`, checked against its `--data-dir`). Never the live broker.
- The policy feature's deny rule, if still set, makes the restore drop `rp.localhost` (by design); the policy recipe removes its rule.
