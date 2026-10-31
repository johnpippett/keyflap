# Agents and intents

The user registers agents, and what they type becomes the live intent that gates every login. The intent socket only accepts the host token. A revoked agent loses access at once.

## Sub-features

- `ai-host-token` the intent socket answers 401 without the host token or with a wrong one.
- `ai-hook` `keyflap hook claude-code --agent <id>` records the prompt as an intent, writes nothing to stdout, and exits 0.
- `ai-audit-hash` the audit trail stores a SHA-256 of the intent text, not the text.
- `ai-revoke` `keyflap agent revoke <id>` makes the agent's MCP token fail with 401 at once.

## How to get to it (user POV)

- Claude Code runs the hook on every prompt.
- The user runs `keyflap agent add <name>`, `keyflap agent list`, `keyflap agent revoke <id>`.

## Driving it with verify-aab

Preconditions:

- `scripts/doctor.sh` printed `RESULT doctor PASS`.

- **Run all of it.** `scripts/drive.sh agents-intents`. Exit code `0`.
- **Host token.** POST `/v1/intents` on the intent socket with no `Authorization` header and with `Bearer not-the-token`. Both answer `401`.
- **Hook.** Run `node packages/cli/src/main.ts hook claude-code --agent <id> --data-dir <sandbox>/data` with stdin `{"hook_event_name":"UserPromptSubmit","prompt":"hook words: open the test RP"}`. Exit code `0`, stdout empty. The latest `intent.recorded` audit entry has `textSha256` equal to the SHA-256 of the prompt, and the entry does not contain the prompt text.
- **Revoke.** `keyflap agent add temp-agent` prints a token. An MCP `initialize` with it answers `200`. `keyflap agent revoke <id>` exits `0`. The same request now answers `401`.
- **Proof.** `<evidence dir>/agents-intents/`: `drive.txt`, `audit-tail.json`, `audit-verify.txt`.

## Gotchas

- Never invoke the hook through `pnpm`. It prints a banner on stdout, and Claude Code feeds hook stdout to the model. The script runs `node …/main.ts` directly.
- The hook always exits 0, even on failure. A failure only means no intent was recorded. Check the audit trail, not the exit code.
- The model must not be able to read the host token (`<data dir>/host-token`). In the sandbox the script reads it as the host would.
- The agent token is printed once by `keyflap agent add`. The script keeps it in a mode 600 file in the sandbox. Do not log it.
