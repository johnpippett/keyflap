# Passkey sign-up and sign-in

An agent signs up on a site, asks the broker to create a passkey, and later signs in with it. The user approves each step on the approval prompt. The agent never holds the private key and only sees `success`, `denied` or another status.

## Sub-features

- `pk-tools` the agent sees exactly the seven broker tools.
- `pk-enroll` `auth_enroll_passkey` creates a passkey after one approval.
- `pk-prompt` the approval prompt shows the user's verbatim words, the verified origin, the agent name and the credential type, and nothing the page or agent wrote.
- `pk-login` `auth_login` signs in with the passkey after one approval.
- `pk-deny` a "no" answer returns `denied` and the page stays signed out.
- `pk-audit` intents, requests, approvals and denials are in the audit trail and the hash chain verifies.
- `pk-noleak` the host token and the key-store passphrase are not in the agent's view, the daemon logs or the audit log.

## How to get to it (user POV)

- The agent calls `browser_open` on the site's sign-up page, `browser_click` on "Add a passkey", then `auth_enroll_passkey`.
- The agent calls `browser_click` on "Sign in with a passkey", then `auth_login`.
- The user records what they asked for through the intent socket (Claude Code does this with its `UserPromptSubmit` hook) and answers the prompt with `y` or `N`.

## Driving it with verify-aab

Preconditions:

- `scripts/doctor.sh` printed `RESULT doctor PASS` for this launch.
- Fresh launch: no passkey enrolled yet. `keyflap status --json` reports `credentials.passkeys` as `0`.

- **Run all of it.** `scripts/drive.sh passkey`. Exit code `0` and `RESULT drive-passkey PASS`.
- **Tools.** The script calls `tools/list` over MCP. The names equal `TOOL_NAMES` from `packages/mcp/src/tools.ts` and the count is 7.
- **Sign up.** `browser_open {url: "<rp>signup"}` then `browser_type {target: {label: "Username"}, text: "pk-…", submit: true}`. The returned `url` is `<rp>account`.
- **Enroll.** Record the intent `add a passkey to my test RP account`. `browser_click {target: {role: "button", name: "Add a passkey"}}`, then `auth_enroll_passkey`. A prompt appears in the daemon's stdout with `"add a passkey to my test RP account"`, `Site:       http://rp.localhost:<port>`, `Agent:      verify-agent`, `Credential: passkey (register)`. The script answers `y`. The tool returns `{"status":"success"}`. The snapshot shows `passkey added` and `Passkeys registered: 1`.
- **Sign in.** `browser_click {role: "button", name: "Log out"}`, `browser_open {url: "<rp>login"}`, record the intent `sign in to the test RP with my passkey`, `browser_click {role: "button", name: "Sign in with a passkey"}`, then `auth_login`. The prompt shows `Credential: passkey (sign-in)`. The script answers `y`. The tool returns `{"status":"success"}`. The snapshot shows `Signed in as pk-…`.
- **Deny.** Log out, open the login page, record a new intent, click the passkey button, call `auth_login`, and answer `N`. The tool returns `{"status":"denied"}`. The snapshot shows `Signed out` and the page's own error status.
- **Audit.** `keyflap audit tail --json` contains `intent.recorded`, `request`, `approval` (two `approved: true`, one `approved: false`), `passkey.created`, `passkey.signed` and `denied` with `reason: approval_user_denied`. `keyflap audit verify` exits `0`.
- **Proof.** Evidence in `<evidence dir>/passkey/`: `prompt-1.txt`, `prompt-2.txt`, `prompt-3.txt`, `snapshot-after-enroll.txt`, `snapshot-after-login.txt`, `snapshot-after-deny.txt`, `steps.jsonl`, `audit-tail.json`, `audit-verify.txt`.

## Gotchas

- Run it once per launch. A second passkey for the same site makes `auth_login` deny with `ambiguous_credential` (documented in `docs/IMPLEMENTATION_NOTES.md`, "Several broker credentials for one rpId"). The script's first step fails with a clear message if one exists already.
- `auth_enroll_passkey` and `auth_login` return when the ceremony ends. The page's own script finishes a moment later and shows `working` until then. Poll the snapshot. A single read right after the call can show the old state.
- The terminal approver cannot do user verification. It answers `userVerified=false`, so this run says nothing about the phone approver or about high-risk sites (those are always denied here).
- An intent expires. If the prompt never appears, check that the intent was recorded for this agent id just before the click. A login with no live intent is denied by design.
- The prompt lines are plain text in `daemon.out`. The script splits on the first line of the box. If the prompt format changes, update `BLOCK` in `scripts/drive.mjs`.
