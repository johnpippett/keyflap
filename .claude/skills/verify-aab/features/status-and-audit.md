# Status and audit

The user checks what the broker holds and whether the audit log is intact. These commands read SQLite only and work while the daemon runs.

## Sub-features

- `sa-status` `keyflap status --json` lists agents, credential counts, policies, and the audit chain check.
- `sa-verify` `keyflap audit verify` exits 0 when the hash chain is intact.
- `sa-tail` `keyflap audit tail --json` lists recent entries.

## How to get to it (user POV)

- Run `keyflap status`, `keyflap audit verify`, `keyflap audit tail`.

## Driving it with verify-aab

Preconditions:

- `scripts/doctor.sh` printed `RESULT doctor PASS`.

- **Run all of it.** `scripts/drive.sh status-audit`. Exit code `0`.
- **Status.** `keyflap status --json --data-dir <sandbox>/data` exits `0`. `agents` includes the `verify-agent` id, `credentials.passwords` is at least `1`, `audit.intact` is `true`.
- **Verify and tail.** `keyflap audit verify` exits `0` and prints `Audit hash chain intact (N entries).` `keyflap audit tail --json` returns at least one entry.
- **Proof.** `<evidence dir>/status-audit/`: `status.json`, `audit-verify.txt`, `drive.txt`.

## Gotchas

- Audit payloads hold identifiers and origins only. A secret in this output is a bug: stop and tell the user.
- Always pass the sandbox `--data-dir`. Without it, `keyflap` reads the user's live `~/.keyflap`.
- Not driven: tampering with the log to see `audit verify` fail. That test needs a copy of the database. The repo's `inv10-audit.e2e.test.ts` covers it.
