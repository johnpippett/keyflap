# Password and TOTP sign-in

An agent reaches a password login page and asks the broker to sign in. The broker fills the username, password and one-time code itself after one approval. The agent never sees the secrets.

## Sub-features

- `pw-status` `auth_status` lists the credential types for the verified origin, with no account names or secrets.
- `pw-login` `auth_login` fills and submits the form, including the one-time-code step, after one approval.
- `pw-prompt` the prompt shows `Credential: password + one-time code` and the user's words.
- `pw-noleak` the password and the TOTP seed are not in the agent's view, the daemon logs or the audit log.
- `pw-audit` the audit trail has `fill.released` and `fill.completed`, and the hash chain verifies.

## How to get to it (user POV)

- The agent calls `browser_open` on the site's password login page, then `auth_login`.
- The user stores the item with `keyflap password add <site> --username <name> --totp` (daemon stopped) and answers the prompt.

## Driving it with verify-aab

Preconditions:

- `scripts/doctor.sh` printed `RESULT doctor PASS`.
- The launch seeded a password + TOTP item for `rp.localhost` (user `alice`). No further setup.

- **Run all of it.** `scripts/drive.sh password-totp`. Exit code `0`.
- **Status.** `browser_open {url: "<rp>password/login"}` then `auth_status`. The result has `origin` equal to the RP origin. `credentials` is `[{"type":"password"},{"type":"totp"}]` on a fresh launch, or `[{"type":"passkey"},{"type":"password"},{"type":"totp"}]` if the passkey feature ran first.
- **Login.** Record the intent `sign in to the test RP with my password`, then `auth_login`. The prompt shows `Credential: password + one-time code`. The script answers `y`. The tool returns `{"status":"success"}`. The snapshot shows `Signed in as alice`.
- **No leaks.** The strings `correct horse battery staple` and `JBSWY3DPEHPK3PXP` do not appear in anything the MCP server sent, in `daemon.out`, `daemon.err` or the audit log.
- **Audit.** `keyflap audit tail --json` has `fill.released` and `fill.completed`. `keyflap audit verify` exits `0`.
- **Proof.** `<evidence dir>/password-totp/`: `prompt-1.txt`, `snapshot-after-login.txt`, `steps.jsonl`, `audit-tail.json`, `audit-verify.txt`.

## Gotchas

- `keyflap password add` and `keyflap password remove` need the daemon stopped (the signer's lock). Add items before `launch.sh` starts the daemon, or stop the run first. The launch script seeds the item for you.
- The password and TOTP seed in the seed are the test RP's public fixture credentials from CLAUDE.md, not real secrets. A different site needs real credentials: list that as a prerequisite and ask the user.
- After `passkey` ran in the same launch, `auth_status` also lists the passkey. The script accepts exactly the two lists above and fails on anything else.
- The TOTP code depends on the clock. A step across a 30-second boundary can fail once. Retry the feature.
