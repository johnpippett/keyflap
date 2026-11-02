# Keyflap

A local broker that signs AI agents into websites (passkeys, passwords + TOTP)
without the agent ever holding a secret. Design contract: `docs/ARCHITECTURE.md`.
Deviations and decisions: `docs/IMPLEMENTATION_NOTES.md` — read both before changing
security-relevant code, and record any new deviation there. The owner's dated product
decisions, with his reasons, are private: `../keyflap-site/notes/DECISIONS.md` (ideas not yet
decided: `notes/INBOX.md` there). Read it before changing policy, approvals, the high-risk list
or the CLI; the docs cite it as `DECISIONS.md`. Never add either file to this public repo.
Outside contributors: open an issue before you change policy, approvals, the high-risk list or the CLI.

## Non-negotiables

- **Section 5 (security invariants) of ARCHITECTURE.md is fixed.** Never weaken one to
  make a feature work. If an invariant blocks progress, stop and ask the user.
- Every invariant needs an automated test; a milestone is done only when its invariant
  tests pass. Name them so they're findable (`inv9-channel.test.ts`, `describe('invariant 2: …')`).
- **Fail closed.** Any error, timeout, or ambiguity is a denial. `Broker.handleWebAuthn` never throws.
- The origin for any credential operation comes only from the shim's frame URL
  (Playwright, trusted side). Never from page options, never from the agent. The
  document's security origin (Chromium, trusted side: `trustedFrame` / `verifiedOriginOfPage`)
  must also equal it, so sandboxed (opaque-origin) documents are denied; never skip that check.
- Approval prompts show only `ApprovalRequest.display` (user's verbatim words, verified
  origin, agent identity, credential type, plus broker-authored fields such as the allow-for
  window). Never page- or agent-written text.
- Policy (M5) can only ever skip a prompt through an allow-for grant the **signer** recorded
  from the user's own signed approval. Never on high-risk / ask-strong, never without a live
  intent, and no MCP tool input may reach policy or approvals.
- No approval-forging key on the broker machine in phone mode: the signer verifies the
  phone's WebAuthn assertion itself. Never verify in the core and re-sign.
- The signer is its own process behind an authenticated socket. Keep it that way. It has
  **zero npm dependencies** (only the workspace package `@aab/sources`, itself built-ins
  only); ask the user before adding any. Only the signer runs password-manager CLIs.
- Tests never touch a real password vault: use the fake `pass-cli` or fake `op` (`@aab/sources/testing`).
- Never log or audit secrets, challenges, or signatures. Audit payloads: identifiers and origins.
- Automated tests use only the local test RP (`packages/test-rp`). Never third-party sites.
- Don't build later milestones early (see section 15/17). Empty packages are fine.
- **Anything a person sees follows the Keyflap brand** (ink, one blue, paper; Barlow Condensed /
  Barlow / Martian Mono; split-flap, steel bezel; no red). Its source (rules, tokens, logo,
  website) is the private `keyflap-site` repo, checked out at `../keyflap-site`: read
  `../keyflap-site/brand/README.md` before changing anything a person sees, and extend the brand
  there first if a new surface needs something it lacks. Don't add brand source, website or
  design files to this repo; the app keeps only the copies it serves
  (`packages/approver/src/page/brand/`, refreshed by `../keyflap-site/scripts/sync-app-assets.sh`).

## Layout

```
packages/
  signer/    separate process: encrypted key store, approval verification (Ed25519 + phone WebAuthn
             assertions), high-risk list (src/risk.ts), its own public suffix list (src/psl.ts,
             src/psl/*.dat, refresh: scripts/update-psl.sh), socket server (node:crypto only); the
             approval-address watch (src/approver-address.ts: polls `tailscale serve status`, or on a Mac
             tailscaled's LocalAPI (src/tailscale-localapi.ts); latches on a mismatch, removes every
             phone; only root clears it); service mode
             (src/service.ts, src/systemd.ts: credentials, socket activation; src/admin-wire.ts)
  approver/  approval transports: TerminalApprover (Phase A), PhoneApprover (Phase B: pairing, approver
             page in src/page/ — it checks each statement and computes its challenge itself,
             src/page/approval-check.js — Web Push; the /handoff live view in src/page/handoff.*),
             the service-mode front that serves the page apart from the core (src/front.ts, user
             keyflap-web; docs/APPROVER_INTEGRITY_PLAN.md), ScriptedApprover (tests); Ed25519 approval
             keys (dev/tests). The web page is the supported phone approver; ios/ is parked
  shim/      Playwright launcher, page override script (src/page/webauthn-override.js), WebAuthn encoding
  core/      Broker orchestration, origin/rpId rules, intents, audit, SQLite (node:sqlite), runtime wiring,
             password fill driver (src/fill.ts) and tool-output scrubbing (src/scrub.ts), policy rules
             (src/policy.ts), allow-for grants (src/grants.ts), session TTL cleanup (src/session-ttl.ts),
             human-check detection (src/challenge.ts), encrypted per-agent saved browser state and its
             filters (src/browser-state.ts; docs/SESSIONS_PLAN.md), human handoff to the phone's live
             view (src/handoff.ts: gating, page.screenshot frames, owner input, handoff_open)
  test-rp/   local relying party (deliberately unbranded: it plays a third-party site): passkey register/login, password + TOTP, human-check modes
  mcp/       MCP Streamable HTTP server (the agent's only interface), the eight tool definitions
  cli/       `keyflap`: daemon, setup and doctor (src/setup/, src/doctor.ts), agent add/list/revoke, the
             Claude Code, Codex and Hermes hooks, CSV import (src/password-import.ts), simple-install
             detection (src/simple-install.ts) (src/main.ts, bin); service mode
             (src/service/: keyflap-core entry, admin-socket CLI, configs, Xvfb); the full-screen
             console (src/console/: `sudo keyflap`, and as your own user the unprotected console for
             dev mode and the simple install, src/console/dev-*.ts, always marked `! UNPROTECTED`)
  install/   service-mode installers: linux/ (build-bundle.sh, install.sh, uninstall.sh, systemd units;
             build-bundle.sh --os darwin also builds the Mac tarball), macos/ (bash 3.2 install.sh,
             uninstall.sh, launchd plist templates, the clean-environment wrapper, launcher/: keyflap-launch,
             the launchd socket handover; install-simple.sh, uninstall-simple.sh: the no-sudo simple
             install, docs/integrations/simple-mac-install.md), bootstrap/ (install-keyflap.sh.in, the
             one command for both OSes, and make-bootstrap.sh, which pins the release hashes into it)
  isolation/ service-mode isolation tests (inv1/5/7/9 vs a third uid) in a throwaway systemd container,
             or on a real Mac against the real install (darwin/run-on-mac.sh, from Linux)
  sources/   external CredentialSource adapters, run inside the signer (node built-ins only):
             Proton Pass via pass-cli (src/proton-pass.ts), 1Password via op (src/one-password.ts);
             fake pass-cli and fake op for tests in test/
```

## Commands

```
pnpm install
pnpm typecheck        # tsc 7, noEmit
pnpm lint             # biome check (pnpm lint:fix to apply)
pnpm check:escapes    # lint/type suppressions stay under the ceiling in scripts/check-escapes.mjs
pnpm check:comments   # no code comments in .ts, .js, .mjs (scripts/check-comments.ts)
pnpm check:bidi       # no invisible direction or line-separator characters in .ts, .js, .mjs
pnpm check:static     # typecheck, lint and the three source checks above, in parallel
pnpm check            # check:static, then pnpm test
pnpm test             # all vitest projects
pnpm test:unit        # fast, no browser
pnpm test:e2e         # Playwright Chromium + spawned signer
pnpm test:isolation   # service mode in a throwaway systemd container (Linux + podman or docker; ~3 min)
npx vitest run packages/core/test/origin.test.ts   # single file
pnpm test-rp          # test RP on http://localhost:3000 (alice / "correct horse battery staple")
pnpm keyflap daemon --unprotected --headed   # same-user dev mode (docs/ISOLATION_PLAN.md); broker + MCP on
                                # 127.0.0.1:8765; passphrase prompt (or KEYFLAP_PASSPHRASE); agents' browser
                                # state saved in <data-dir>/browser-state (--ephemeral-browser: off)
pnpm keyflap daemon --unprotected --approver phone --approver-origin https://HOST:8766
                                # phone approvals (docs/integrations/phone-approver.md)
pnpm keyflap daemon --unprotected --password-source proton-pass --proton-pass-vault Agent
                                # also offer Proton Pass logins (docs/integrations/proton-pass.md)
OP_SERVICE_ACCOUNT_TOKEN=… pnpm keyflap daemon --unprotected --password-source 1password --1password-vault Agent
                                # 1Password logins via a service account (docs/integrations/1password.md)
pnpm setup:preview [--scenario mac-fresh|linux-fresh|mac-rerun|mac-agents] [--capture DIR]
                                # the real setup screens against fakes; changes nothing (docs/integrations/setup.md)
pnpm console:preview [--mode service|dev|simple] [--capture DIR]   # the console screens against fakes
pnpm keyflap setup --unprotected    # guided dev setup: phone, agents, passwords, then doctor
pnpm keyflap doctor [--json] [--project DIR]   # read-only health check; exit 1 on a failure
pnpm keyflap                        # no command, as you: the unprotected console (dev mode, simple install)
pnpm keyflap agent add <name>       # prints the agent token once + Claude Code config; agent list|revoke <id>
pnpm keyflap approver list | approver remove <id>      # phone approvers; daemon stopped
pnpm keyflap password add <site> [--username U] [--totp]   # daemon stopped; secrets via no-echo prompt/stdin
                                # password list | password remove <id>
pnpm keyflap password import FILE.csv [--site S]... [--all] [--expect F]   # daemon stopped; a CSV export
pnpm keyflap policy set <site> (--deny|--ask|--ask-strong|--allow-for 30m) [--agent ID] [--session-ttl 2h|off]
                                # section 9 rules (docs/M5_PLAN.md); policy list [--json] | policy remove <site>;
                                # SQLite only, works while the daemon runs (it reads rules per request)
pnpm keyflap sessions list [--json] | sessions clear (--agent ID | --all) [--site S]
                                # saved browser sessions; dev mode queues clears (daemon applies <= 30 s)
pnpm keyflap sessions keep|unkeep <site> [--agent ID]  # owner opt-in to keep a high-risk site signed in
pnpm keyflap status [--json]        # agents, credentials, policies, saved sessions, audit chain; keyflap audit verify | audit tail
KEYFLAP_DEV_PASSPHRASE=dev pnpm --filter @aab/core dev --url http://localhost:3000/login --intent "sign in to the test RP"
                                # dev runner: no MCP, intent from the flag, one "dev-agent" page
```

Service mode (the real install; docs/integrations/service-mode.md). Never run these on the
dev machine as part of a task: installing needs root and is the owner's call.

```
packages/install/linux/build-bundle.sh /tmp/keyflap-bundle            # as the user
sudo install -d -m 0755 /opt/keyflap-release   # install.sh refuses to run from, or read, anything
sudo cp -r packages/install/linux /tmp/keyflap-bundle /opt/keyflap-release/   # non-root can change
sudo /opt/keyflap-release/linux/install.sh --bundle /opt/keyflap-release/keyflap-bundle \
  --approver-origin https://HOST:8766 [--xvfb]
sudo keyflap approver pair | agent add <name> | password add <site> | policy … | sessions … | status | audit …
                                # the installed `keyflap` talks to the root-only admin sockets
sudo keyflap                    # no command: the management console
sudo keyflap setup | doctor     # guided setup; health check
sudo keyflap password-source add proton-pass|1password [--vault V]   # connect a password manager now
sudo keyflap password-source remove           # disconnect it; trust pass-cli|op re-pins an updated tool
sudo packages/install/linux/uninstall.sh [--purge]
```

On a Mac (Apple silicon, macOS 14+) the same through `packages/install/macos/install.sh --bundle DIR
--launcher FILE` (`packages/install/macos/launcher/build.sh OUT_DIR` builds `keyflap-launch` in a
container on Linux), and the same `sudo keyflap …` as on Linux. Mac-only tests, run on a Mac:
`KEYFLAP_LAUNCH=FILE pnpm vitest run --project e2e packages/install/test/keyflap-launch.e2e.test.ts`
(add `KEYFLAP_LAUNCH_SUDO=1` for the LaunchDaemon cases) and the isolation run below.

`keyflap hook claude-code --agent <id>` is the Claude Code UserPromptSubmit hook
(`docs/integrations/claude-code.md`). It must never write to stdout (Claude Code feeds a
hook's stdout to the model) and always exits 0; never invoke it through `pnpm`, which
prints a banner to stdout.

Run `pnpm typecheck && pnpm lint && pnpm check:escapes && pnpm check:comments && pnpm check:bidi && pnpm test && pnpm test:isolation`
before pushing. The pre-push hook (`.githooks/pre-push`, opt-in per clone with
`pnpm hooks:install`) runs the static half, `pnpm check:static`, on every push. Never silence a
failing check: no `biome-ignore`, `@ts-ignore`, `.skip` or edited expectations to get green.
If a rule or an invariant test is wrong, stop and ask the owner.
CI runs only on GitHub-hosted runners, never a self-hosted one (a test pins it); the Linux e2e
suite runs in four shards. macOS CI runs on every pull request, after merging to main, and on
demand (`gh workflow run macos.yml --ref BRANCH`).
The isolation suite needs Linux with rootless podman or docker (~3 min) and is not part of
GitHub CI. Its macOS run installs Keyflap for real on a Mac and purges it afterwards:
`KEYFLAP_MAC=user@host packages/isolation/darwin/run-on-mac.sh` (an admin with `sudo -n`; ~2 min
on the Mac), never on a Mac whose install you want to keep; `packages/isolation/ci-job.yml` is a ready-made job for anyone who wants to add it
to `.github/workflows/`.

## Conventions

- **No code comments** (`pnpm check:comments` enforces it for `.ts`, `.js` and `.mjs`). Put the
  meaning in a name, a type, a test or a lint rule. If a constraint needs a warning, encode it
  instead. The only comments allowed are lint and type directives (`biome-ignore` with a reason,
  `@ts-*`), and those are capped by `pnpm check:escapes`. The removed comments are in git history
  at `9ed3308`.

- TypeScript run directly by Node 22 type stripping — no build step. That means:
  relative imports end in `.ts`; **erasable syntax only** (no enums, namespaces, or
  constructor parameter properties); use `import type` for types.
- The product and command are `keyflap`. Leftover `aab` names are deliberate: the `aab-…-v1`
  domain-separation tags, `aab_agent_` tokens, the `__Host-aab_device` cookie, the APNs payload
  keys, and `@aab/*` packages. Never rename those (IMPLEMENTATION_NOTES "Naming: Keyflap").
- Cross-package imports go through package `exports` (`@aab/signer/client`, `@aab/shim`, …).
- `src/page/webauthn-override.js` is injected into pages as text: plain browser JS, no imports.
- E2E tests run the RP on `rp.localhost` and attack from `evil.localhost` etc.; Chromium
  resolves `*.localhost` to loopback and treats it as a secure context. Use
  `page.route()` to serve hostile pages at a chosen origin.
- Unix socket paths must stay short (108 bytes on Linux, 103 on macOS; Node truncates longer
  ones silently, so `@aab/signer/platform` refuses them): use `os.tmpdir()` in tests
  (`vitest.setup.ts` makes it `/tmp` on macOS). Platform branches live in or name
  `packages/signer/src/platform.ts` (service mode: `SERVICE_PLATFORMS`, linux/systemd and
  darwin/launchd; the CLI's per-platform strings are in `cli/src/service/manager.ts` and
  `paths.ts`). Dev mode and the unit and e2e tests also run on macOS (`.github/workflows/macos.yml`).
- Playwright is pinned to 1.64.1 (Chromium revision 1248). The revision is also pinned in
  `packages/install/linux/runtime-pins.sh` (build-bundle.sh refuses a mismatch), the demo
  image digest (`demo/Containerfile`) and the isolation tests (`chromium-1248`); bump them
  together (IMPLEMENTATION_NOTES "Runtime pins"), and re-verify `shim/src/native-webauthn-block.ts`:
  it hooks Playwright internals to keep native WebAuthn off real authenticators (it fails
  closed if they change, so a bump that breaks it shows up as launch failures).