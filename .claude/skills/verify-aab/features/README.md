# Keyflap verification map

This directory is the maintained source for verifying what a user or agent can do with the broker. Read this index before driving anything, then use the matching feature file as the recipe.

## Baseline preconditions

- Run `scripts/launch.sh` from the repo root. It starts a sandbox stack: daemon (headless, terminal approver), signer, managed Chromium, and the test RP at `http://rp.localhost:<port>/`.
- The sandbox has one agent, `verify-agent`, and one password + TOTP item for `rp.localhost` (login `alice`; fixture credentials from `packages/test-rp`).
- The key-store passphrase is random and stays in the sandbox. Never print it.
- Run `scripts/doctor.sh` and require `RESULT doctor PASS`.
- Never drive an instance this run did not start. The user's live broker listens on 127.0.0.1:8765 and 8766 and keeps its data in `~/.keyflap` (or `~/.aab`, its name before the rename).
- Use a fresh launch for `passkey`.

## Driving conventions

- Run every feature with `scripts/drive.sh <feature>`. It runs inside the sandbox environment.
- The agent acts only through the eight MCP tools: `browser_open`, `browser_click`, `browser_type`, `browser_snapshot`, `auth_status`, `auth_login`, `auth_enroll_passkey`, `browser_handoff`. `auth_status` and `browser_snapshot` also return `humanCheck` (a boolean).
- The user acts through the intent socket (what they typed), the approval prompt (y/N on the daemon's stdin), and the `keyflap` CLI.
- Locate elements by ARIA role and name, or by label. Do not use coordinates (the one exception is the simulated owner's tap in the `handoff` live view, which is a picture).
- After an auth tool returns, the page's own script may still be running. Poll the snapshot for the end state. Do not use a fixed sleep.
- Keep quoted names and flags exactly as written.

## Proof and skip reporting

- Capture the user action and the resulting state, not only the final page.
- Page proof is an accessibility snapshot. There is no screenshot of the managed browser (see `SKILL.md`, Evidence).
- Approval proof is the saved prompt text: the user's words, verified origin, agent name, credential type.
- Side-effect proof is the audit trail (`audit-tail.json`) and `keyflap audit verify`.
- Record the feature ID and entry point with every artifact. `drive.sh` saves them under `<evidence dir>/<feature>/`.
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a skipped entry point as verified through a different path.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph. It then has exactly four H2 sections, in this order: `Sub-features`, `How to get to it (user POV)`, `Driving it with verify-aab`, `Gotchas`. The third section starts with `Preconditions:`.

## Features

| Feature | Cost | Status |
|---|---|---|
| [Passkey sign-up and sign-in](./passkey-sign-in.md): enroll a passkey, sign in, deny | free, isolated | driven in the proof run |
| [Password and TOTP sign-in](./password-totp-sign-in.md): the broker fills the form and the code | free, isolated | driven |
| [Site policy](./site-policy.md): `keyflap policy` deny rule | free, isolated | driven |
| [Agents and intents](./agents-and-intents.md): host token, Claude Code hook, revoke | free, isolated | driven |
| [Status and audit](./status-and-audit.md): `keyflap status`, `audit verify`, `audit tail` | free, isolated | driven |
| [Human check after sign-in](./challenge.md): the `challenge` outcome and `humanCheck` | free, isolated | driven |
| [Saved sessions across a restart](./persistence.md): restart the sandbox daemon, still signed in | free, isolated | driven |
| [Human handoff on the phone](./handoff.md): `browser_handoff`, a simulated phone's live view, tap, Done; one approval for a check in front of the sign-in (P3b) | free, isolated (simulated phone on loopback); run it last | driven |
| [Needs approval](./needs-approval.md): phone and iOS approvers, Proton Pass, headed mode, service mode, isolation suite, real sites | costly or risky | never driven without the user's say-so |
