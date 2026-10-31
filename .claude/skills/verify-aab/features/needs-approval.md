# Needs approval

Features that cost money, act on the real desktop or OS, touch real accounts, or need root. Document them here. Do not drive them in a proof run. Ask the user first.

This file is a list, not a feature recipe, so it does not use the four-section shape.

| Feature | Why it needs approval | What it needs | Where the repo documents or tests it |
|---|---|---|---|
| Phone approver with the user's real phone (`keyflap daemon --approver phone`) | Needs the user's phone, a TLS front (Tailscale), and the user to approve on the phone. Opens a pairing URL. The `handoff` feature drives a *simulated* phone on loopback instead, inside the sandbox. | A paired phone | `docs/integrations/phone-approver.md`, `packages/core/test/inv6-phone-approval.e2e.test.ts` |
| iOS approver app (parked) | Needs a device, Face ID, and APNs. | The user's iPhone, an Apple developer account for push | `docs/integrations/ios-app.md`, `packages/core/test/inv6-native-approver.e2e.test.ts` |
| Proton Pass source (`--password-source proton-pass`) | Reads the user's real vault with a real token (a Proton Pass PAT from a file the user points you to). | A logged-in `pass-cli` | `docs/integrations/proton-pass.md`; tests use the fake `pass-cli` in `@aab/sources/testing` |
| 1Password source (`--password-source 1password`) | Reads the user's real vault with a real service account token. | `op` and a service account token | `docs/integrations/1password.md`; tests use the fake `op` in `@aab/sources/testing` |
| `keyflap daemon --headed` | Opens a Chromium window on the user's desktop and takes focus. | The user's display | CLAUDE.md (Commands) |
| Service mode install and uninstall | Needs root, creates system users and systemd units (launchd jobs on a Mac). | `sudo` | `docs/integrations/service-mode.md` |
| The simple Mac install | Installs a LaunchAgent and a key store in the user's real home on a Mac. | A real Mac | `docs/integrations/simple-mac-install.md` |
| `pnpm test:isolation` | Starts a throwaway systemd container (podman or docker). About one minute. | rootless podman or docker | `packages/isolation/` |
| Any real third-party site | Real accounts, bot walls, possible lockouts. Automated tests must use `packages/test-rp` only (CLAUDE.md). | The user's explicit request | `docs/IMPLEMENTATION_NOTES.md` (huggingface.co validation) |
| The user's live broker on 127.0.0.1:8765 | Real agents, real approvals. | Never | n/a |

## Gotchas

- A mock is fine only where a boundary already isolates the external system. The fake `pass-cli` is one. A fake phone is not, except the `handoff` feature's simulated phone: a separate headless Chromium with a CDP virtual authenticator on a loopback `http://approver.localhost` origin, the same stand-in the repo's phone e2e tests use. It never reaches a push service, Tailscale or the user's phone.
- Never start a nested compositor or display server in a sandbox for these. Use the repo's own suites.
