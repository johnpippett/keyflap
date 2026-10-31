# Human check after sign-in (`challenge`)

The broker fills a password form and the site answers with a human check instead of the account page. The broker reports `challenge`, never solves the check, and the agent sees only `humanCheck: true` (SESSIONS_PLAN section 1).

## Sub-features

- `ch-help` the `auth_login` tool description lists the `challenge` outcome, says the broker will not solve it, and points the agent at `browser_handoff`.
- `ch-waf` a site answering with `x-amzn-waf-action: captcha` (status 405) gives `{"status":"challenge"}`.
- `ch-cf` a site answering with `cf-mitigated: challenge` (status 403) gives `{"status":"challenge"}`.
- `ch-flag` `browser_snapshot` and `auth_status` carry `humanCheck: true` on the challenge page.
- `ch-text` a page that only says "Let's confirm you are human", with no structured signal, reads as `success` and `humanCheck: false` (page text is never trusted).
- `ch-audit` `fill.completed` has `outcome: "challenge"` and the provider; the agent's view has no provider name.

## How to get to it (user POV)

- The agent opens a password login page and calls `auth_login`; the user approves; the site shows "Let's confirm you are human".
- The agent calls `browser_handoff` so the user completes the check on their phone (see `handoff.md`). With the terminal approver that answers `unsupported`, and the agent tells the user.

## Driving it with verify-aab

Preconditions:

- `scripts/doctor.sh` printed `RESULT doctor PASS`.
- `scripts/rp-server.mjs` also started three challenge RPs (`waf.rp.localhost`, `cf.rp.localhost`, `text.rp.localhost`; second JSON line of `logs/rp.out`). The seeded `rp.localhost` item covers them (same registrable domain).

- **Run all of it.** `scripts/drive.sh challenge`. Exit code `0`. Three approval prompts are answered `y`.
- **Header modes.** For `waf` and `cf`: intent, `browser_open {url: "<rp>password/login"}`, `auth_login` → `{"status":"challenge"}`; the snapshot shows `Let's confirm you are human` and `humanCheck: true`; `auth_status` has `humanCheck: true`; the last `fill.completed` has `outcome: "challenge"` and `humanCheck: "aws-waf"` / `"cloudflare"`.
- **Text only.** The same on `text` → `{"status":"success"}`, `humanCheck: false`.
- **Proof.** `<evidence dir>/challenge/`: `prompt-1..3.txt`, `snapshot-waf.txt`, `snapshot-cf.txt`, `snapshot-text.txt`, `steps.jsonl`, `audit-tail.json`, `audit-verify.txt`.

## Gotchas

- The frame-widget mode needs the daemon's test-only `challengeHosts` option, which the CLI doesn't expose; it is covered by `packages/core/test/fill-challenge.e2e.test.ts`, not here.
- The seeded item has TOTP, so the check comes after the one-time-code step. That is still one approval.
- Never point this at a real provider host or site; the test RPs fake only the response headers.
