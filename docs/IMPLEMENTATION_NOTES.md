# Implementation notes

Decisions made while implementing ARCHITECTURE.md, especially where the code deviates
from or tightens the design. Keep this current.

## Status

- **M0 done:** monorepo, CI, test RP (passkey register/login, password + TOTP).
- **M1 done:** shim + signer + terminal approver; end-to-end register/sign-in against the
  test RP with keys only in the signer process. Invariant tests: 2, 3, 9, and 6/7 for
  the "page goes around the broker to native WebAuthn" case.
- Pulled forward because the M1 flows needed them (their invariant tests remain M2 work):
  a minimal intent store with auto-deny when there's no live intent, and the hash-chained
  audit log.
- **M2 done** (plan: `M2_PLAN.md`): agent registry, multi-agent
  broker, per-agent browser contexts, `AgentBrowserPort` implementation, intent socket,
  `startDaemon`. Also done: the MCP server, the `keyflap` CLI and the Claude Code reference
  integration (`docs/integrations/claude-code.md`).
- **M2 invariant tests** (1, 4, 5, 7, 10): `packages/core/test/inv{1,4,5,7,10}-*.e2e.test.ts`,
  driven through the real daemon + MCP server (SDK client, agent bearer token) with intents
  only over the intent socket; shared helper `test/mcp-harness.ts`.
- **M3 phase 1 done** (plan: `M3_PLAN.md`): native password/TOTP items in the signer, the
  fill flow behind `auth_login`, output scrubbing, post-fill verification, `keyflap password`.
  Invariant 8: `packages/core/test/inv8-fill.e2e.test.ts` (+ `scrub.test.ts`, signer side in
  `packages/signer/test/fill-release.test.ts`).
- **M3 phase 2 done:** the first external `CredentialSource` adapter, **Proton Pass via its
  CLI (`pass-cli`)** (owner decision, 2026-10-12). Details: "External credential sources"
  below; setup: `docs/integrations/proton-pass.md`. Invariants 1, 3 and 8 for it:
  `packages/core/test/inv8-proton-pass.e2e.test.ts` (+ `packages/signer/test/
  source-release.test.ts`, `packages/sources/test/proton-pass.test.ts`). Automated tests
  use only a fake `pass-cli` (`packages/sources/test/fake-pass-cli.ts`) and the local test
  RP, never a real vault; the adapter was also checked by hand, read only, against a real
  vault. The broker uses whatever vault and `pass-cli` session it is pointed at
  (`--proton-pass-vault`). If that session's token is shared with other local tooling, the
  broker keeps the vault's secrets away from the *model* (invariants hold as usual); it
  does not keep them away from other local tools that hold the same token. A dedicated
  vault and token for the broker avoid that.
- **M4 done** (plan: `M4_PLAN.md`): phone approver (pairing, WebAuthn approvals verified by
  the signer, Web Push), high-risk tier, `keyflap daemon --approver phone`, `keyflap approver`.
  Invariant 6: `packages/signer/test/inv6-user-verification.test.ts`,
  `packages/core/test/inv6-phone-approval.e2e.test.ts` (+ `packages/approver/test/
  phone-server.test.ts`, `webpush.test.ts`). Setup: `docs/integrations/phone-approver.md`.
- **M5 done** (plan: `M5_PLAN.md`): policy per origin pattern × agent (`deny`, `ask`,
  `ask-strong`, `allow-for`), the denylist, allow-for grants enforced by the signer, session
  TTL cleanup, `keyflap policy`, `keyflap status`, `keyflap audit`. Details: "Policy and sessions (M5)"
  below. Invariant 6 (and 4/10 inside allow-for windows): `packages/signer/test/
  inv6-policy-grants.test.ts`, `packages/core/test/inv6-policy-broker.test.ts`,
  `inv6-policy.e2e.test.ts` (daemon + MCP + the real CLI process),
  `inv6-policy-phone.e2e.test.ts` (phone page); plus `core/test/policy.test.ts`,
  `cli/test/policy.test.ts`, approver tests.
- **Service mode on Linux done** (isolation plan S2–S4, `ISOLATION_PLAN.md`): signer and core
  as systemd services under `keyflap-signer` / `keyflap-core`, auto-unlock with a sealed KEK (D1),
  root-only admin sockets (D3), phone approver required (D5), installer with a root-owned
  `/opt/keyflap` and pinned runtime (D4), optional headed Chromium on a private Xvfb display.
  Details: "Service mode" below; setup: `docs/integrations/service-mode.md`. Invariants 1, 7,
  9 against a third uid: `packages/isolation/test/inv{1,7,9}-isolation.test.ts`
  (`pnpm test:isolation`, a throwaway systemd container; CI job ready in `isolation/ci-job.yml`), plus
  `signer/test/service-mode.test.ts`, `signer/test/systemd.test.ts`,
  `cli/test/service-mode.e2e.test.ts`, `cli/test/service-config.test.ts`.
- **Service mode on macOS done** (`MAC_PLAN.md` M0 to M7, 2026-10-29 to 31): launchd, hidden
  `_keyflap-*` users, `keyflap-launch`, the isolation suite on a real Mac. Also the simple Mac
  install, the one-command install for both systems, the management console and the
  approval-address tripwire. Details: "Service mode on macOS (S5): the platform layer" and the
  sections after it.
- **Phone approver: the web page is the supported path (owner decision 2026-10-20).** The
  native iOS app (Phase C, below) is **parked**: the broker side stays merged and tested, but
  the app isn't shipped or verified on a device. Reasons: it needs an Apple developer account,
  the iOS SDK and signing for every user, and for an open-source, self-hosted broker push
  would need a relay run by whoever signs the app (APNs only accepts that team's key). Its one
  security advantage, a page whose code the core can't change, now holds for the web page too:
  **approver integrity done** (`APPROVER_INTEGRITY_PLAN.md`): the page checks the statement
  against its card and computes the challenge itself (all modes), and in service mode the
  page is served by its own service, `keyflap-approver` (user `keyflap-web`), not by the core. Details:
  "Approver integrity" below. Tests: `approver/test/inv5-approval-check.test.ts`,
  `approver/test/inv5-approver-front.test.ts`, `core/test/inv5-lying-core.e2e.test.ts`,
  `isolation/test/inv5-approver-isolation.test.ts`, `cli/test/service-mode.e2e.test.ts`
  (extended). Accepted (owner): an approver passkey in iCloud Keychain syncs to the owner's
  other Apple devices, and its user verification may be the device passcode; that is how
  Apple passkeys work, and approving from another of the owner's devices is wanted.
- **Phase C, native iOS approver (parked 2026-10-20; was in progress: everything but an on-device run):** the
  `ios/` app (SwiftUI; Secure Enclave approval key; Face ID; APNs with lock-screen
  actions, polling without it), a native approver key type in the signer, the app's API on
  the phone approver server, an optional APNs sender, terminal QR pairing. Details:
  "Native iOS approver (Phase C)" below; setup: `docs/integrations/ios-app.md`. Invariant 6:
  `packages/signer/test/inv6-native-approver.test.ts`,
  `packages/core/test/inv6-native-approver.e2e.test.ts` (+ `approver/test/native-api.test.ts`,
  `apns.test.ts`, `qr.test.ts`; cross-language vectors `signer/test/native-vectors.test.ts`
  and `ios/KeyflapApproverCore/Tests`, run on Linux in a swift container). Not yet verified:
  the app target's compile (needs the iOS SDK: the macOS workflow `ios/ci/ios.yml`, not
  yet installed, or xtool with the owner's Xcode .xip) and a run on a device.
- **Sessions plan P1 done** (`SESSIONS_PLAN.md` section 1): the honest `challenge` outcome
  for password fills and the agent's `humanCheck` flag. Details: "Human-check detection"
  below. Tests: `core/test/challenge.test.ts`, `core/test/fill-challenge.e2e.test.ts`
  (invariants 8, 10), `test-rp/test/challenge.test.ts`.
- **Sessions plan P2 done** (section 2): persistent per-agent browser state, encrypted with
  a data key from the signer, TTL clocks persisted with a fail-closed restore, the owner's
  per-site opt-in for high-risk sites, `keyflap sessions`. Details: "Persistent browser state"
  below. Tests: `core/test/browser-state.test.ts`, `session-persistence.e2e.test.ts`,
  `inv6-session-ttl-restore.e2e.test.ts`, `inv8-persisted-state.e2e.test.ts`,
  `signer/test/browser-state-key.test.ts`, `signer/test/inv9-channel.test.ts` (extended),
  `cli/test/sessions.test.ts`, `cli/test/service-mode.e2e.test.ts` (extended), and
  `isolation/test/inv1-isolation.test.ts` (extended).
- **Sessions plan P3 done** (section 3): human handoff on the web phone approver
  (`browser_handoff`, the eighth tool; the `/handoff` live view; Face ID start; Web Push and
  APNs "Human check on <host>"), plus the high-risk "Keep me signed in on <site>" checkbox on
  the phone approval card (decision 3). Details: "Human handoff (sessions plan P3)" below.
  Tests: `core/test/handoff.test.ts`, `handoff-phone.e2e.test.ts`,
  `inv{4,5,6,7,8}-handoff.e2e.test.ts`, `inv10-audit.e2e.test.ts` (extended),
  `keep-signed-in.e2e.test.ts`, `approver/test/handoff-server.test.ts`,
  `keep-signed-in.test.ts`, `apns.test.ts` (extended), `mcp/test/tools.test.ts` (eight
  tools), `signer/test/keep-signed-in.test.ts`, `inv6-policy-grants.test.ts` (extended),
  `ios/KeyflapApproverCore` (`keepSignedIn` refused). P4 (the iOS app's handoff screen) not
  built.
- **Sessions plan P3b done** (owner decision 2026-10-13, `SESSIONS_PLAN.md` "P3b: one approval
  for check + sign-in"): when a human check stands in front of a sign-in the broker could
  do right now, `browser_handoff` asks the owner once (a normal approval card, one Face ID)
  for both; the signer records a single-use grant from that approval and the agent's next
  `auth_login` there needs no prompt. Details: "One approval for check + sign-in (sessions
  plan P3b)" below. Tests: `signer/test/inv6-handoff-grant.test.ts`,
  `core/test/inv6-handoff-signin-broker.test.ts`, `core/test/handoff-signin-phone.e2e.test.ts`,
  `approver/test/handoff-signin.test.ts`, plus extended `handoff.test.ts`,
  `inv{4,5}-handoff.e2e.test.ts`, `inv10-audit.e2e.test.ts`, `inv9-channel.test.ts`,
  `test-rp/test/challenge.test.ts`.

## Stack changes (section 13)

| Suggested | Used | Why |
|---|---|---|
| `@noble/curves`, `@noble/hashes` | `node:crypto` | P-256 ECDSA (DER), Ed25519, AES-GCM, scrypt are all built in. The signer has **zero** npm deps. |
| `better-sqlite3` | `node:sqlite` | No native addon to build or download. Still flagged experimental in Node 22 (prints a warning; CI sets `--disable-warning=ExperimentalWarning`). |
| a CBOR library | ~40-line encoder in `shim/src/encoding.ts` | We only *encode* three fixed shapes (COSE key, attestation object, maps). Tested against RFC 8949 vectors and decoded by `@simplewebauthn/server`'s independent decoder. |
| build step | Node type stripping + `tsc --noEmit` (TS 7) | No dist output to drift from source. |

## Signer boundary (invariant 9, section 6.2)

- **No peer-credential check.** Node has no portable `SO_PEERCRED`. Instead the core
  generates a 32-byte channel key per spawn and passes it to the signer on a private
  stdin pipe (not argv/env). Each connection gets a fresh nonce; every request and
  response carries HMAC-SHA256 over (direction, nonce, seq, body) with strictly
  increasing seq. Socket dir is 0700, socket 0600. The signer's environment is just `PATH`.
- **Known limit — needs a decision:** a process running as the *same OS user* with
  debugging rights (ptrace, `/proc/<pid>/mem`) could read the channel key or key-store
  passphrase from memory, and could read the encrypted key file. For invariants 1/7/9 to
  hold against an agent that has shell access, the agent must run as a different OS user
  or in a sandbox. A native addon for `SO_PEERCRED` would not fix this on its own (a
  same-uid attacker passes the uid check). Out of scope for M1; flagged for the owner.
  **Decided and built (Linux; macOS since 2026-10-29):** service mode (`docs/ISOLATION_PLAN.md`, "Service mode"
  below): core and signer under their own service users, root-owned install. There the
  signer socket's owner and mode (set by systemd, or by launchd on a Mac) admit only `keyflap-core`, and the HMAC
  channel stays as a second layer with a channel key provisioned at install. Same-user
  `keyflap daemon` requires `--unprotected`, prints a banner and audits `daemon.unprotected`.
- **API tightened vs. the doc:**
  - `sign` takes `clientDataJSON` (not its hash) so the signer itself checks type,
    origin, `crossOrigin:false`, and that its hash equals the approved hash. It also
    checks `authenticatorData` is 37 bytes, its rpIdHash matches the credential's rpId,
    UP is set, UV only if the approval says the user was verified, no BE/BS/AT/ED flags.
  - `create_credential` also requires an approval (the doc's signature omits it).
  - Approval statement covers `(requestId, kind, verifiedOrigin, rpId, credentialId,
    intentHash, clientDataHash, userVerified, issuedAt, expiresAt)` — a superset of the
    doc's tuple. Single use (requestId), max lifetime 5 minutes, Ed25519, domain-separated
    canonical JSON.
  - Defense in depth for invariant 3: the signer requires the approved origin's host to
    equal the rpId or be a subdomain of it. The full public-suffix check lives in core
    (the signer stays dependency-free).
- **Channel hardening:** a connection must send its first correctly MACed request within
  `handshakeTimeoutMs` (default 10 s, a hard deadline, not an idle timer). After that
  there is no idle timeout, because the core keeps one long-lived connection open.
  Frames that are not plain JSON objects, and any exception from a frame handler, close
  only that connection; they never take down the signer.
- **One live signer per store:** the signer takes `<storePath>.lock` (pid, created
  atomically with link()) before opening the store and refuses to start if the holder
  is alive. A lock held by a dead pid, or unreadable, is removed and acquisition retried
  once. `startSignerServer` also refuses a socket path where something is listening and
  unlinks it only on ECONNREFUSED/ENOENT. Released on exit; SIGKILL leaves a stale lock
  that the next start reclaims. Known residual race: two starters reclaiming the *same*
  stale lock at the same moment can, in a narrow window, both proceed (Node has no
  `flock`). PID reuse can make a stale lock look live; that fails closed (refuses).
- **Key store:** one AES-256-GCM file, key from scrypt over a passphrase the signer
  receives at startup. The file records its scrypt parameters; every write uses the ones
  the in-memory key came from, and a store with other parameters is migrated on open
  (see "Key store scrypt parameters" below). The doc says "unlocked by approval"; per-approval unlock is still
  deferred after M4 (it needs a phone-held secret, e.g. a PRF-derived key, which M4 doesn't
  use; revisit with Phase C).

## Authenticator behavior (open questions 1 and 3)

- AAGUID all zeros, attestation `none`, BE=0/BS=0 (keys are device-bound software keys),
  signCount always 0.
- **UV flag:** set only when the approval reports user verification. The Phase A terminal
  approver cannot verify the user, so it reports `userVerified: false` and sites that
  *require* UV will reject it. That's intentional: claiming UV we didn't perform would lie
  to the relying party. Phase B (phone + biometric) will set it truthfully.
- `isUserVerifyingPlatformAuthenticatorAvailable()` → true; `isConditionalMediationAvailable()`
  → false. A `mediation: 'conditional'` call stays pending until aborted (like a user who
  never picks from autofill). `getClientCapabilities()` reports the same.
- `instanceof PublicKeyCredential` holds for returned objects; fields are own properties.

## Keeping pages off native WebAuthn (invariants 6, 7)

A page that reaches Chromium's own `navigator.credentials` implementation skips intent,
approval, signer checks and audit. On a host with a security key or platform
authenticator, that is a full bypass. The original override (configurable own properties)
was bypassable with `delete navigator.credentials.get`, `CredentialsContainer.prototype.get
.call(...)`, natives from a fresh iframe or popup realm, or a `publicKey` getter that hides
on the first read. Two layers now close this; `inv6-inv7-native-webauthn.e2e.test.ts` tests
each one on its own.

- **Layer A, browser (`shim/src/native-webauthn-block.ts`).** Every page target gets CDP
  `WebAuthn.enable` with **zero** virtual authenticators. Chromium then sends all native
  WebAuthn from that tab (main frame and every iframe, out-of-process ones included) into
  the empty virtual environment, where it times out with NotAllowedError. No authenticator
  is ever added, so section 6.3 holds. To be race-free, enable is sent on Playwright's own
  page session just before Playwright resumes the paused target, so it precedes every page
  script, popups included (the opener is blocked in `window.open` until then). The public
  API can't do this, so it uses Playwright's in-process server objects (`toImpl` →
  `CRConnection`), hooked only on the managed browser's connection. Fail-closed checks:
  - install throws if the internals don't look as expected;
  - a probe page must come out covered before launch returns;
  - any page that shows up uncovered is closed;
  - a page whose enable fails is closed.

  Playwright is pinned, so re-run the e2e tests when bumping it.
- **Layer B, page (`webauthn-override.js`).** The replacements are non-writable,
  non-configurable properties on `CredentialsContainer.prototype` *and* on
  `navigator.credentials`. The natives exist only in the script's closure and are called
  through a captured `Reflect.apply`, so a page that patches `Function.prototype.call`
  can't capture them. `publicKey` is read once. Requests without it go to Chromium with a
  null-prototype copy of the known non-WebAuthn members, so getters, Proxies and
  `Object.prototype` pollution can't smuggle a `publicKey` past the check. Chromium runs
  init scripts before page code in every new realm (appended about:blank iframes, srcdoc,
  `javascript:` iframes, sync `window.open` popups, after `document.open`), so no same-origin
  realm offers unpatched natives. The Signal API statics are made absent, since we report
  them unsupported.

What was measured on Chromium 1194 / Playwright 1.56.1, and rejected:
- `--disable-blink-features=WebAuth` only hides `PublicKeyCredential` and the response
  interfaces. `navigator.credentials.create({publicKey})` still runs natively and returns a
  credential from an authenticator. `--disable-features=WebAuthn|WebAuthenticationAPI` does
  nothing either.
- `context.on('page')` + `WebAuthn.enable` loses the race to a popup's inline script.
- A browser-level `Target.setAutoAttach` hold is not usable through Playwright's public
  CDP API. Releasing it by detaching deadlocks the target if Playwright resumed first,
  and the detach itself wipes the tab's WebAuthn environment (next item).

Known limits:
- **Any CDP session detaching from a tab resets that tab's virtual environment**, even one
  that never touched WebAuthn. Layer A sees the detach and re-enables. For those few
  milliseconds the tab is back on real authenticators. Only broker code can attach
  sessions (invariant 7), so broker code should not attach/detach sessions on managed pages.
- Requests made in a fresh popup's first milliseconds sometimes fail at once with
  NotSupportedError, with or without layer A. It looks like a Chromium-side cancellation,
  and no authenticator was reached even when one was present in the environment.
- Not covered by tests: prerendered pages, fenced frames, and Secure Payment Confirmation
  (`PaymentRequest`), which uses WebAuthn internally. Layer A's environment is per tab, so it
  should apply to them, but that's unverified.

## Agent surface (M2, core side)

- **Agents.** `agents` gained `token_hash` (SHA-256 hex of `aab_agent_` + 32 random bytes
  b64url) and `revoked_at`, added by `ALTER TABLE` on older databases. The token is shown
  once. Lookups go by hash; malformed tokens never reach SQL. Tokenless rows left by M1
  (`dev`) are not agents: they never resolve and aren't listed. Names are 1..64 printable
  chars (no control or bidi characters) and unique among active agents, since the name is
  what the prompt shows. Revoking an agent stops its token at once, makes its port refuse,
  and closes its browser context.
- **One broker, many agents.** `Broker.handleWebAuthn(req, agent, {page})`. The agent is
  bound when the core creates that agent's BrowserContext (`AgentSessions`), so it comes
  from the trusted side like the origin does. `page` only keys ceremony events.
- **Native WebAuthn block, restructured.** `installNativeWebAuthnBlock(browser)` installs
  the CDP-connection hook once per browser (still refuses a second install) and returns
  `cover(context)`, which adds that context's uncovered-page watchdog and runs a probe
  page; `ManagedBrowser.newContext(handler)` always covers before adding the binding and
  override. The hook was already connection-wide, so it covers every context; the
  inv6/inv7 tests check a second context created later.
- **Contexts** use `acceptDownloads: false`. The agent's "current page" is the most
  recently opened page of its context that is still open (popups included).
- **Navigation.** `browser_open` parses with `URL` and accepts only `http:`/`https:` (after
  the parser strips tabs/newlines, so `java\tscript:` is refused too).
- **Targets.** Strict shape: exactly one of role/text/label/placeholder/css, only that
  kind's options, string fields ≤ 1000 chars (role `[a-z]+`, ≤ 64). CSS is passed as
  `css=<selector>` and anything Playwright would read as another engine is refused first:
  `>>` anywhere, a leading `name=` (xpath=, text=, internal:…=, id=, _react= …), `//`,
  `..`, or a leading quote. Actions time out after 10 s; ambiguous targets (strict mode)
  and missing ones are tool errors with our own wording, never page text.
- **No typing secrets.** `browser_type` refuses targets that match
  `input[type=password i]` or an `autocomplete` token `one-time-code`, `current-password`
  or `new-password` ("use auth_login"). It also requires the target itself to be an
  input/textarea/contenteditable: Playwright's `fill()` retargets a label (or text inside
  one) to the label's control, which would otherwise route around the check. Both checks
  are locator queries, which run in Playwright's utility world. This is a guard rail, not
  a boundary against the page: a page could still switch a field's type after the check.
- **Snapshot redaction (feeds invariant 8 in M3).** `locator('body').ariaSnapshot()` runs
  in Playwright's utility world, but **renders input values verbatim, password fields
  included** (measured on 1.56.1: `- textbox "Password": hunter2`). So the port enumerates
  the sensitive fields (same selector as above) before and after the snapshot, takes each
  one's own one-line aria rendering, and in the page snapshot redacts the value of every
  node with the same role/name/attributes, then also replaces any occurrence of a
  sensitive value (≥ 4 chars, raw and JSON-escaped). If the fields can't be enumerated
  (error, > 50 fields), every textbox/searchbox/spinbutton/combobox value is redacted
  instead. Not in the snapshot at all: iframe contents and closed shadow roots (tested).
  Values a page copies into ordinary text are only caught by the value pass; M3's
  post-fill check owns that.
- **auth_login / auth_enroll_passkey** wait on broker ceremony events for the agent's
  current page. A ceremony in flight counts; so does one that ended in the last 60 s that
  no earlier call claimed (an approver can finish before the agent's next tool call). Each
  ended ceremony answers one call. `success` means the broker completed the ceremony; the
  RP verifies it right after. `not_eligible` when there's no page or its origin fails the
  WebAuthn origin rules; `no_credential` (login only) when no broker passkey's rpId is
  valid for the origin. A closed page ends the wait as `timeout`. Default 30 s, max 120 s.
- **Audit.** The port writes `tool.call {agentId, tool, ok, origin?}` (origin of the
  current page after the call, http(s) only); if that write fails the call fails. The MCP
  layer's observer writes a separate `mcp.tool_call {agentId, tool, ok}`, which also
  covers calls the MCP server rejects before they reach the port, including calls to a tool
  that doesn't exist (`tool: "(unknown)"`: the requested name is agent text, so it isn't
  logged).
- **Audit triggers** refuse UPDATE, DELETE and an INSERT whose `seq` already exists. The
  last one is needed because `INSERT OR REPLACE` deletes the conflicting row without firing
  DELETE triggers (measured; it used to overwrite rows).
- **Audit known limits.** The chain has no external anchor, so `verify()` cannot detect
  truncation of the tail, deletion of the whole table, or a rewrite of every row from some
  seq onward with recomputed hashes; it detects any edit, insertion or deletion followed by
  at least one untouched row. HTTP-level refusals on the MCP endpoint (bad agent token,
  Origin/Host checks) are not audited.
- **Intent socket** (`<dataDir>/run/intent.sock`): routes and status codes as in
  `M2_PLAN.md`. Also: the content type must be `application/json`; bodies with fields
  other than `agentId`/`text`, or invalid UTF-8, are 400; text length is counted in UTF-16
  code units; a declared Content-Length over 64 KiB is refused before reading. Rejections
  are audited as `intent.rejected {status, reason, agentId?}` (agentId only once the host
  token checked out). `host-token` must be a regular 0600 file holding a 43-char b64url
  token; a group/other-accessible one is refused rather than silently fixed. Text containing
  U+0000 is 400: SQLite reads TEXT back only up to the NUL, so the prompt would have shown a
  truncated version of the user's words. Every other character is stored verbatim; the
  approval render replaces control and bidi characters (incl. LRM/RLM/ALM) with U+FFFD.
- **Daemon.** `startDaemon` replaces M1's `startBrokerRuntime` (the dev runner now uses it).
  It also returns `sessions`, `browser`, `db`, `signer` and `resolveAgent`. The MCP server
  plugs in through `startMcp({resolve, onToolCall, host, port})`, since `@aab/mcp` is
  built separately; `mcpUrl` is null without it. Teardown runs in reverse start order,
  also when start fails half-way.

## CLI and Claude Code integration (M2)

- **`keyflap`** (`packages/cli`, bin → `src/main.ts`, run by type stripping; `node:util`
  parseArgs, no framework). `keyflap daemon` = `startDaemon` + `startMcpHttpServer` +
  `TerminalApprover` (approver key `<dataDir>/approver-key.json`, as the dev runner).
  Passphrase from `KEYFLAP_PASSPHRASE` (deleted from `process.env` before anything is spawned,
  so the signer and Chromium don't inherit it; e2e-tested via `/proc`), else a no-echo
  raw-mode prompt on the TTY (asked twice when no key store exists yet). The prompt reads
  only up to Enter and `unshift`s anything typed after it, so the approver's later
  readline on the same stdin loses nothing. No TTY and no env → refuses to start. The
  daemon's own initial environment still holds `KEYFLAP_PASSPHRASE` if it was set (same-uid
  readable via `/proc`), so the integration doc says to prefer the prompt. The core dev
  runner (`pnpm --filter @aab/core dev`) is unchanged and still has no MCP.
- **`keyflap agent add|list|revoke`** open `broker.sqlite` directly while the daemon may run.
  Two small core changes make that safe: `openDb` sets `busy_timeout = 2000` (wait for the
  other process's write lock instead of SQLITE_BUSY), and `AuditLog.append` runs in
  `BEGIN IMMEDIATE` so two processes can't both build on the same chain head (before, the
  loser would have failed on the `seq` primary key; the chain could not fork). The CLI
  audits `agent.added {agentId, name}` and `agent.revoked {agentId}`.
- **Cross-process revocation.** The daemon looks agents up per request, so a CLI revoke
  stops the token (MCP 401, intent 404, port refuses) immediately (e2e-tested). The
  daemon's `onRevoke` listener does not fire for another process's revoke, so that agent's
  browser context stays open, unreachable, until the daemon restarts. In service mode
  `sudo keyflap agent revoke` goes through the daemon's admin socket, so the context closes at
  once; dev mode keeps the direct-SQLite behaviour.
- **`keyflap hook claude-code`** imports nothing from core (runs on every prompt). It
  replaces `process.stdout.write` with a no-op, exits 0 on every path (including bad
  arguments, uncaught errors, and a 10 s hard stop), uses a 3 s request timeout, and logs
  one stderr line on failure built only from fixed text and errno codes (JSON parse
  errors can quote input, so they're never passed through). It applies the daemon's own
  host-token checks (regular file, 0600, owned by us, 43-char b64url). Prompts > 8000
  UTF-16 units are not recorded (never truncated).
- **Hook input, verified against code.claude.com/docs/en/hooks.md (2026-10):** the
  current docs list no `prompt_type` field. If present, `user_input` and `slash_command`
  are forwarded and anything else is skipped; input with `agent_id` (subagent) or a
  `hook_event_name` other than `UserPromptSubmit` is skipped. Slash commands are
  forwarded verbatim because they are the user's typed words, and the prompt shows
  exactly that text.
- **Known limit (invariants 4/5) — accepted for v1 (owner, 2026-10-12):** Claude Code also fires
  `UserPromptSubmit` for scheduled tasks/`/loop`, background-subagent reports and
  cross-session messages, with no documented field to tell them from typed prompts. The
  last two are model-written text that could become a live intent and appear as "You
  said". The hook skips prompts starting with `<task-notification>` (undocumented, best
  effort); the integration doc tells users not to combine those features with the broker
  and to deny prompts whose text they didn't type. A real fix needs a source field from
  Claude Code (or an intent channel that only typed input reaches). v1 ships with the
  best-effort skip, the doc warning and human review of the "You said" text; revisit
  after v1 (candidate: an intent channel only the user types into).
- **The Claude desktop app's host context (2026-10-30):** the desktop app puts a
  `<system-reminder>…</system-reminder>` block (about 4,000 characters of its own
  instructions) in front of the typed words in the hook's `prompt`. Recorded whole, it filled
  the phone card's "You said" with app text (seen on the test Mac). The hook now drops
  complete `<system-reminder>` blocks at the very start and records what follows; a prompt that
  is only such blocks records no intent, and a block anywhere else, or one left open, stays in
  the text. The block is the app's, not the model's or a page's, so dropping it shows the
  owner less text that isn't theirs, never more.
- **Model isolation for the host token** is configuration, not code: Claude Code's sandbox
  `denyRead`/`denyWrite` on the data dir plus `Read`/`Edit` deny rules,
  `allowUnsandboxedCommands: false`, `failIfUnavailable: true` (see
  `docs/integrations/claude-code.md`). `keyflap agent add` prints these. Unverified: whether
  `denyRead` on the directory blocks `connect()` to `run/intent.sock` (the token is still
  required).

## Passwords and TOTP (M3)

- **Signer items.** The key store file gains `items` (domain, password, optional TOTP
  params); older files load with none. `store_item` and `delete_item` need no approval:
  they release nothing, and only the holder of the channel key can call them.
  `release_secret(itemId, field, approval)` returns the password or the **current TOTP code**;
  the seed never leaves the signer. Passwords must be 4..1024 characters without U+0000
  (shorter values can't be scrubbed from agent output by literal match, below). TOTP: SHA1 /
  SHA256 / SHA512, 6-8 digits, 15-120 s period, seed ≥ 80 bits.
- **Fill approvals.** Same statement as passkeys with `kind: 'fill'`, `rpId` = the item's
  registrable domain, `credentialId` = item id, and `clientDataHash` = SHA-256 of the fill
  scope `aab-fill-v1\n<fields>` (`password`, `totp`, or both). The signer releases only
  fields in the scope, each **once per approval** (so one approval covers password + the
  following TOTP step, and nothing more), and requires the approved origin's host to be
  the domain or a subdomain, with the domain never a public suffix (the signer's own PSL,
  "Public suffix list in the signer" below). A fill approval can't be used for a passkey or vice versa
  (kind check, and a spent requestId is spent for both).
- **Binding (invariant 3 for passwords).** An item is offered only when the verified
  origin's registrable domain (PSL, private section included) equals the item's domain.
  Several items for one domain → deny `ambiguous_credential`, as for passkeys. Revisit with
  a user-set label in the prompt.
- **Method choice in `auth_login`:** a passkey ceremony in flight (or ended unclaimed in
  the last 60 s) on the page wins; else a detectable login step + a matching item → fill;
  else a matching passkey → wait for the page's ceremony. A password item but no
  detectable form → `unsupported/not_eligible`.
- **Field detection** (`core/src/fill.ts`, locators in Playwright's utility world, main
  frame only): exactly one visible `input[type=password]` that isn't
  `autocomplete=new-password` (username: in its form, `autocomplete=username`, then email,
  then a lone text input); else exactly one visible `autocomplete=one-time-code` input; else
  exactly one visible username/email input (identifier-first). More than one → no step.
  Known gaps, to revisit when validating on real sites: OTP fields without
  `autocomplete=one-time-code`, split one-digit-per-box OTP inputs, login forms in iframes.
- **Form target check.** Relative targets resolve against the document's base URL (the
  first `<base href>`, as the browser does), not the page URL. The owning form's `action`,
  every `formaction` in it, and every `formaction` on an element with a `form` attribute
  anywhere on the page must be http(s) on the item's registrable domain. A field with its
  own `form` attribute (owner picked by id) is refused outright. Any of these → no step,
  audited as `request` + `denied {reason: form_targets_other_site | ambiguous_form}` and
  answered `unsupported/not_eligible` (M3_PLAN said "deny"; the agent sees `not_eligible`
  because nothing was asked). Script-submitted forms can post anywhere; that's the site's
  own same-origin script, which could read the field anyway.
- **Filling.** After approval: take the port's exclusive lock. Every other tool call of
  that agent finishes first and new ones wait; a call waiting for its own turn leaves the
  in-flight set, and the holder re-reads that set on every change, so two fills can't
  deadlock (an earlier version waited on a snapshot and did; tested now). The wait is
  capped at 20 s (`exclusiveWaitMs`) and then denies, well inside the approval's 60 s.
  Then re-detect the same first step, re-check the main frame is
  on the approved origin, resolve fields to ElementHandles (bound to their document: a
  navigation makes `fill` fail instead of retargeting), and get each secret from the
  signer right before typing it, re-checking the origin before each. Submit = Enter in the
  last filled field. Later steps (identifier → password → one-time code, each at most
  once) must be on the **same origin**; a site that moves to another subdomain for its 2FA
  step needs a second `auth_login` (and approval).
- **Outcome.** `success` once the filled fields are gone (navigation or hidden) with no
  further step; `failed` when the form is still there after `fillStepTimeoutMs` (10 s),
  the site shows a step again (wrong password), or it asks for a one-time code the item
  has no seed for. Known limit: an SPA that hides the form for more than 750 ms and then
  shows it again with an error reads as `success`; `denied` for any policy, approval or signer
  refusal, and for any error once the approval is in hand.
- **Post-fill verification.** Whatever the outcome, every filled field still holding a
  released secret, and every `input`/`textarea` in the main frame (up to 200) whose value
  contains one, is cleared — including on the page the form led to.
- **Output scrubbing.** The agent's session remembers every value the broker filled (in
  core memory, until the context closes) and `AgentPort` scrubs every string of every tool
  result: raw, JSON-escaped, `encodeURIComponent`, form-encoded and `encodeURI` spellings,
  the browser URL parser's query/path/fragment spellings, and whitespace-collapsed copies
  (aria snapshots normalize whitespace); percent-escapes match case-insensitively, all
  forms of all secrets are replaced longest first, and any whitespace-free token that
  still percent-decodes to a secret is redacted whole. Snapshots are scrubbed before the
  200 000-character cut, and a trailing prefix of a secret at the cut is dropped. This covers "show password" toggles, pages echoing
  the value as text or title, and GET forms putting it in the URL (all tested). Known limits:
  transformed copies (upper-cased, base64, split across elements) aren't caught; the
  usernames the broker types are not secrets and aren't scrubbed. Scrubbing is also an
  oracle: an agent can type a full guess into a text field and see whether it comes back
  `[redacted]`, which tells it no more than trying that password on the site would.
  Operator note: Playwright's
  `DEBUG=pw:api` logging prints `fill()` arguments, so never run the daemon with it.
- **Audit.** `request {kind: 'password.fill'}`, `approval`, `fill.released {requestId,
  itemId, field}`, `fill.completed {requestId, agentId, verifiedOrigin, itemId, outcome,
  fields}`, `denied`; `credential.added` / `credential.removed` from the CLI. Never values.
- **CLI.** `keyflap password add <site> [--username U] [--totp]` reads the password (and the
  TOTP secret or `otpauth://totp/` URI) without echo on a TTY, else one per line from stdin;
  never argv or env. `add`/`remove` spawn their own signer on the key store, so the daemon
  must be stopped (the single-instance lock refuses otherwise, and the CLI says so). A
  running daemon's signer holds its own decrypted snapshot of the store, so it couldn't see
  a new item anyway. `list` reads only SQLite. In service mode `sudo keyflap password add|remove`
  go through the admin socket to the running daemon's signer instead (usable at once).
- **Import** (2026-10-22, for password managers that give other apps no way in).
  `keyflap password import <file.csv> [--site S]... [--all] [--expect F]` (`cli/src/password-import.ts`)
  reads a CSV export and stores each chosen login exactly as `password add` would: one offline
  signer for the batch in dev mode (daemon stopped), `password.add` per login over the admin
  socket in service mode. Recognised by header: Apple Passwords (`Title,URL,Username,Password,
  Notes,OTPAuth`), Google Password Manager / Chrome (`name,url,username,password[,note]`), and
  by column name Firefox, 1Password and Bitwarden (first of several URIs). Decisions:
  - **Nothing is stored unless named.** Without `--site`/`--all` it only previews (domain,
    username, TOTP yes/no) and needs no passphrase. Owners should import only the sites their
    agents need, not their whole vault; `--all` exists but the preview steers to `--site`.
  - **Fail closed per row.** Rows without a website address (an `http(s)://` URL or a bare
    domain such as `example.com`; Android app entries, other schemes, Wi-Fi and IP addresses are
    skipped), with a password the signer would refuse (< 4 or > 1024 chars), a non-printable
    username, or a TOTP cell `parseTotpInput` rejects are skipped, never stored half (no
    password without its TOTP).
  - **A one-time code column it can't read refuses the whole file.** The TOTP column is found
    by name (`otpauth`, `login_totp`, `totp`, `otp`, Dashlane's `otpSecret`, …). Any other
    header column that looks like one (`otp`, `2fa`, `mfa`, `one-time`, `authenticator`) would
    otherwise be dropped and its logins stored as password-only, so import stops with an
    error naming the column (review of #24). Rows for the same domain and username merge if identical and are all skipped if
    they disagree. A login already stored for that domain and username is left alone.
  - **No secrets in output.** Rows are reported by line, domain and username; skip and failure
    reasons are fixed strings (a caught error's text is never shown). Notes columns are parsed
    over and dropped. The output ends by telling the owner to delete the plaintext export.
  - Service mode reads the file as root (sudo), so the core sees each secret on its way to the
    signer, the same path `sudo keyflap password add` already takes.
  - **What is stored is what the preview showed** (security review of #24–#27). Preview and
    store are separate runs, so a same-user process could rewrite the export in between (say,
    swap in a login for an account it controls). The preview prints a fingerprint (first 16 hex
    digits of the SHA-256 of the file's text) and suggests commands with `--expect <it>`; a run
    with `--expect` refuses a file that no longer matches. Each run reads the file once and
    parses those bytes only. `--expect` is optional: a run without it never showed the owner
    anything to rely on, and its report lists exactly what was stored.

## Usernames in the terminal (security review, 2026-10-27)

Usernames come from places the owner didn't type: CSV exports, Proton Pass and 1Password
vaults. They print in `password list` and the import report, in root's terminal under `sudo`
in service mode. A username carrying escape sequences could rewrite that output, set the
window title or, on some terminals, write the clipboard (OSC 52).
- **One rule for names and usernames** (`core/src/display-text.ts`): `hasUnsafeText` refuses C0
  and C1 controls, DEL, the bidi marks, embeddings, overrides and isolates, U+061C and the line
  and paragraph separators. Agent names used it already (minus U+061C/U+2028/U+2029, now
  added); usernames refused only C0 and DEL. `password add`, import and source sync now all use
  it. Source sync keeps the login and drops just the username, as before.
- **Escape on the way out too.** `printable` writes each such character as a visible `\uXXXX`.
  The import prints every username and the file name through it (a row skipped *because* of its
  username used to print it raw), and `password list` does for rows stored before this check.
  `--json` output is left to `JSON.stringify` (C0 escaped; it is for programs, not terminals).
- Tests: `core/test/display-text.test.ts`, the "terminal safety and the file fingerprint" block
  of `cli/test/password-import.test.ts`, `cli/test/password.test.ts` (list output),
  `core/test/source-sync.test.ts`.

## External credential sources (M3 phase 2)

- **Where the CLI runs: the signer.** `packages/sources` holds the adapters (node built-ins
  only, like the signer, which now depends on it as a workspace package; still no npm
  dependencies). The core never runs `pass-cli`: it gets metadata through the signer op
  `list_source_items` (ref, hosts, username, TOTP yes/no; rebuilt field by field so
  nothing else an adapter returns gets out) and secrets only through `release_secret`
  under a fill approval, as for native items. In service mode only the signer's user
  would need a `pass-cli` session. Same-user mode (`--unprotected`) protects nothing from
  a local process anyway, and a token shared with other tools (above) is readable by
  them too.
- **Refs and rows.** An item's ref is `proton-pass:<share id>:<item id>` (both base64url,
  checked). The core keeps one `credentials` row per registrable domain (PSL) of the
  item's http(s) or scheme-less URLs (other schemes, IPs and dotless hosts are skipped),
  id `<ref>@<domain>`, `source = 'proton-pass'`, `signer_ref = <ref>`, username = the
  item's username, else its email. A fill approval's `credentialId` is now the row's
  `signer_ref` (equal to the id for native items). Two items for one domain, or a native
  and a vault item, → `ambiguous_credential` as before.
- **Binding (invariant 3) at release.** A native item's domain is stored in the signer; an
  external item has none there. So the approval names it (the core picked it with the
  PSL), the signer requires it to be exactly the approved origin's registrable domain by
  its own PSL, spends the field, then **reads the live item and requires one of its URL
  hosts to have that registrable domain** (`item_not_for_domain` otherwise). Every live
  host also counts for the high-risk tier. A vault item edited or deleted since the last
  sync can't be filled where it no longer points (tested). Before 2026-10-22 the signer
  only required a dot, so a compromised core could name `co.uk` and release another
  site's item under the approval of a plain one (review finding M1; "Public suffix list
  in the signer" below).
- **Sync.** `SourceSync` (core) re-reads the vault at daemon start (in the background:
  a failure doesn't stop the daemon), every 5 minutes, and when `auth_status` /
  `auth_login` finds no credential for a page (at most every 30 s), so a login saved in
  Proton Pass is found without a restart. The adapter caches item metadata by
  `modify_time`: only new or changed items are viewed again. Row changes are applied in
  one transaction and audited (`credential.added/removed/updated` with `source`), and a
  failure keeps the rows (the signer re-checks anyway) and is audited once per distinct
  reason (`source.sync_failed`, then `source.sync_ok`).
- **pass-cli facts (2.3.3, verified by hand against a real vault).** `item list` has no URLs or
  secrets, and agent sessions can't use `--show-secrets`, so matching needs one `item
  view` per login (~1.4 s each, run 6 at a time). Ids can start with `-`, so every id
  goes as `--flag=value` (a separate argument is rejected as an unknown option; the fake
  does the same). Item reads in an agent session need `PROTON_PASS_AGENT_REASON`; the
  broker says "Keyflap broker: matching saved logins to sites" or "Keyflap broker: approved
  sign-in on <origin>". TOTP: the signer reads `totp_uri` and computes the code itself
  (no item had a seed to check `pass-cli item totp`'s output against).
- **Environment.** pass-cli gets PATH plus HOME, XDG_RUNTIME_DIR / XDG_DATA_HOME /
  XDG_CONFIG_HOME, DBUS_SESSION_BUS_ADDRESS, PROTON_PASS_KEY_PROVIDER and
  PROTON_PASS_SESSION_DIR from the daemon's environment (never
  PROTON_PASS_PERSONAL_ACCESS_TOKEN: the broker uses an existing session, it doesn't log
  in), plus `PROTON_PASS_NO_UPDATE_CHECK=1`. Gotcha: when pass-cli can't find its local
  key (a different key provider than the one used at login, e.g. no D-Bus), it **logs
  the session out**. Every process sharing the session must use the same provider.
- **Errors.** The adapter maps failures to fixed reasons (`source_unavailable`,
  `source_not_logged_in`, `source_timeout` (20 s per call), `source_item_not_found`,
  `source_item_inactive`, `source_not_a_login`, `source_bad_output`,
  `source_vault_not_found`); pass-cli's output never goes into an error or a log.
- **Signer concurrency.** Source ops are asynchronous (`SignerHandler.dispatch`); the socket
  server answers each request when it's done (responses carry their seq). All other ops
  stay synchronous (`handle`). A fill field is marked spent before the slow read, so two
  concurrent releases with one approval read the item once (tested).
- **CLI.** `keyflap daemon --password-source proton-pass [--proton-pass-vault NAME]
  [--proton-pass-bin PATH]`. `keyflap password list` shows a SOURCE column; `keyflap password
  remove` refuses vault rows (edit the item in Proton Pass instead).
- **Not done:** the native store was not refactored behind `CredentialSource` (it already
  worked and is tested; only external sources use the interface). No admin command to
  force a sync: restart the daemon or let a lookup miss trigger one.

### 1Password (2026-10-22)

Same shape as Proton Pass: `@aab/sources` `OnePasswordSource` (`src/one-password.ts`, node
built-ins only), run only by the signer; core, sync, release and binding checks unchanged.

- **Auth: a service account only.** The signer runs as `keyflap-signer` in service mode and
  can't reach a desktop app's unlock prompt, so `op` gets `OP_SERVICE_ACCOUNT_TOKEN` and the
  adapter always sets `OP_BIOMETRIC_UNLOCK_ENABLED=false` (no app integration) and
  `OP_CACHE=false` (no cache daemon left running from the signer). Env allow-list as for
  pass-cli: PATH plus the configured env; never `OP_CONNECT_*` (they take precedence over the
  token) or `OP_SESSION_*`. The token is never in argv.
  - Dev mode: `keyflap daemon` takes the token from its environment, **deletes it** there
    (Playwright passes the daemon's env to Chromium) and hands it to the spawned signer on
    stdin with the rest of its config. No token → the daemon refuses to start.
  - Service mode: the token is the systemd credential `op-service-account-token`, sealed by
    `install.sh` (`--op-token-file FILE` or a no-echo prompt; kept on upgrade) and loaded only
    by the signer through a drop-in (`keyflap-signer.service.d/1password.conf`). The signer
    adds it to op's env at start (`withServiceSecrets`). `signer.json` (0644) refuses any
    `OP_*` in `sources.onePassword.env`, and `sources` now refuses unknown keys. A missing
    credential doesn't stop the signer; every read then fails `source_not_logged_in`.
- **Refs.** `1password:<vault id>:<item id>`, both exactly 26 ASCII letters/digits (op: "a
  string of 26 numbers and letters"); anything else is `bad_ref` and runs nothing. Ids never
  start with `-`; flags are passed as `--flag=value` anyway.
- **Commands** (docs for op 2.x, current stable 2.41.1; service accounts need >= 2.18.0;
  JSON shapes from 1Password's op-js types; **not run against a real account**):
  `op vault list --format=json`, `op item list --vault=<id> --categories=Login
  --format=json`, `op item get <item> --vault=<vault> --format=json [--reveal]`.
  Matching uses `item get` *without* `--reveal` (op conceals sensitive values unless asked);
  only `fetch` (after a fill approval) reveals. Username = the field with purpose USERNAME,
  password = purpose PASSWORD, TOTP = the one field of type OTP, whose `value` is the
  otpauth URI; its `totp` property (the current code) is never read.
- **Matching reads each item once.** `item list` may carry `urls` (op-js types them as
  optional), but it has no username field and no TOTP presence, so the adapter reads each
  item with `item get` and caches it by `version|updated_at`, like pass-cli's
  `modify_time`. It never relies on list output for hosts.
- **Request limits** (decision). Service accounts are limited per hour (1,000 reads below
  Business) and per day per account (1,000 on individual/family plans), and each sync costs
  about three requests. So for `1password` the core re-reads every 30 min (Proton: 5) and a
  lookup miss triggers a sync at most every 5 min (Proton: 30 s) (`sourceIntervals`). Hitting
  a limit is `source_rate_limited` (new reason), which fails closed like any other.
- **Fail closed, more strictly than pass-cli.** The answer must be for the vault and item
  asked for (`id`, `vault.id`), category `LOGIN`, exactly one PASSWORD field; an item with a
  `state` other than `ACTIVE` (archived items can still be fetched by id) is
  `source_item_inactive`. Two OTP fields → no TOTP offered (which one is a guess). Two
  vaults with the configured name → `source_vault_ambiguous` (new reason). op's stderr is
  only classified, never kept.
- **One source at a time**, as before: `--password-source proton-pass|1password`; the
  service config refuses both. Flags: `--1password-vault NAME`, `--op-bin PATH` (dev and
  `install.sh`), plus `install.sh --op-token-file FILE`.
- **Tool trust (rebased onto #21, 2026-10-22).** `op` launches through `ToolLauncher` like
  pass-cli (`OP_TOOL`, `/opt/keyflap/tools/op/`): install.sh finds it only in root locations,
  install-config pins its SHA-256 in `sources.onePassword.sha256`, the signer re-checks every
  launch, `password-source trust op` re-pins, doctor and setup apply the same check. With
  1Password the signer keeps network (no `no-network.conf`); the token drop-in is
  `keyflap-signer.service.d/1password.conf`.
- **Setup.** Step 5 offers 1Password next to Proton Pass. Dev mode: the token (prompted
  without echo, or `$OP_SERVICE_ACCOUNT_TOKEN`) goes to `op vault list` in its environment
  only, to check it and list vaults; setup.json records kind, vault and bin, never the token.
  A daemon started by that same setup run gets it in memory (`secretEnv`); every later start
  reads `OP_SERVICE_ACCOUNT_TOKEN`. Choosing one source when the other is set asks first.
  Service mode: install-time choice; setup only shows the signer's tool check.
- Unverified against a live account: the exact stderr wording op uses for
  sign-in / not-found / rate-limit errors (the classifier matches the documented and commonly
  reported phrasings; anything else is `source_failed`, still a denial), and whether
  archived items carry `state: "ARCHIVED"` (if not, an item archived since the last sync can
  still be filled on its own site until the next sync, which lists without the archive,
  drops its rows).
- Tests: `sources/test/one-password.test.ts` (fake `op`, `@aab/sources/testing` `fakeOp`),
  `core/test/inv8-1password.e2e.test.ts` (invariants 1, 3, 8 through MCP, incl. the token),
  `signer/test/systemd.test.ts`, `cli/test/service-config.test.ts`, `cli/test/args.test.ts`.

## First real service-mode install (2026-10-27)

The owner installed a release-candidate tarball on a real Arch machine (systemd 262), paired
an iPhone and signed in through Claude Code: huggingface.co (password from Proton Pass, its
human check after submit solved in the phone's live view), a denial, a revocation. Audit chain
intact. What it found, besides the credential layout ("Credential file layouts"):

- **Pairing from a phone whose default browser isn't Safari.** The camera opens a scanned
  link in the default browser; Brave dropped the `#code`, and the page then looked like an
  ordinary unpaired page. Fixed in the page (see "Pairing link"); the workaround it shows is
  Copy Link, then Safari.
- **Setup's section titles came out orange.** Over ssh (and under sudo) there is no
  `COLORTERM`, so the 16-colour bright blue was used, and the terminal theme painted it
  orange. `term-style.ts` now uses the fixed 256-colour cube when `TERM` says 256 colours
  (brand README, Terminal, updated first).
- **"Agent name (- to skip this step)"** was answered with `-` by mistake, so no agent was
  made. The agent step now asks "Set up an agent for <host>? [Y/n]" first, then the name.
- **Closing tips** pointed a release install at `pnpm test-rp` in a checkout. Service mode now
  suggests a real first sign-in; the test-RP walkthrough stays for dev mode.
- **The credentials menu came back after Proton Pass was set up**, inviting a second set-up and
  a second restart. Setting up a password source (Proton Pass or 1Password) now ends the step;
  a failed one offers the menu again, and native passwords still ask "Add another credential?".
- **Switching password source left the old source's rows.** After Proton Pass -> 1Password the
  18 Proton rows stayed in `credentials`: still offered for sign-in (the fetch then fails
  closed, the signer no longer runs pass-cli), and a site in both would be
  `ambiguous_credential` once 1Password synced it. The CLI rightly can't remove source rows.
  The core now drops rows of any source other than the configured one at startup, before the
  first sync (`dropUnconfiguredSourceRows`, audited `credential.removed` with
  `reason: source_not_configured`); native rows always stay. Switching back re-syncs them.
- **A submit button enabled only by key presses.** On namecheap.com the right fields were
  filled, but "Sign in" stayed disabled: the page takes values from key events, and
  Playwright's `fill()` sends one `input` event. Enter then does nothing (implicit
  submission skips a disabled default button) and the click fallback can't click it. The
  driver now types each value key by key (`ElementHandle.type`, after clearing the field);
  if the field ends up holding something else (an input mask), it falls back to `fill()`.
  Origin checks unchanged. inv8-fill covers a keyup-gated button.
- **The username went into a newsletter box.** namecheap.com wraps its whole page in one
  form (ASP.NET style). The login step picked the username field from that form by selector
  order (autocomplete=username, then any email box, then text), so the newsletter's
  `type=email` box at the bottom won over the plain-text username field: the form posted
  without a username and stayed. Now: exactly one `autocomplete="username"` field still wins;
  otherwise the nearest visible email (in a form, or text) field *before* the password
  field, by Playwright's own document order (`.and(preceding::input)`). inv8-fill covers a
  page-wide form with a search box above and a newsletter box below.
- **Phone notifications stopped, with nothing to show for it.** On the first install, pushes
  stopped arriving on the iPhone while the broker logged none rejected (Apple's push service
  kept answering 201), the app showed no "turn on notifications" button (the broker still
  had a subscription) and iOS settings were fine. The page only ever asked the broker
  whether it had a subscription, never the phone whether that subscription was still the
  live one. Now, once per page load with permission granted, the page sends the phone's
  current subscription again (`getSubscription()`, or a new one), so a subscription iOS
  replaced or dropped is repaired by opening the app. inv6-phone-approval covers it.
- **An upgrade dropped the agent tokens.** install.sh recreates `/var/lib/keyflap/hook` on
  every run (so no user-made symlink is followed) and re-issues the host token. Setup also
  keeps each agent's token there (`agent-<id>.token`, read by `keyflap mcp-headers`), so after
  the rc3 -> rc4 upgrade Claude Code got 401 from the MCP server, never had the Keyflap
  tools, and went looking for a Hugging Face CLI instead. Agent tokens are shown once and
  can't be re-issued; the installer now carries them over: read and written back as the
  user (runuser), only well-formed names and tokens, only when the old dir was this user's.
  Isolation test: the upgrade keeps the token (0600, the user's) and drops a planted symlink
  to a root-only file and a malformed file.
- **A step that ignores Enter.** accounts.x.ai's email step has no form and moves on only
  when "Next" is clicked; the fill driver only pressed Enter, so it saw the same step for
  10 s and ended `failed`. Now, if the step is still there 1.5 s after Enter, the driver
  clicks its one submit button, once: the owning form's only visible submit button, else
  (no form) the page's only visible button named like a submit (Next, Continue, Sign in,
  Log in, Submit, Verify). None or several: no click, `failed` as before. Still main frame
  only, on the approved origin (re-checked right before the click); form targets are
  checked as before. Test RP `/password/login-id-script` (with a "Go back" and a cookie
  banner that must not be clicked) and an ambiguous page in inv8-fill.

## Real-site validation (2026-10-12)

First run against a real, password-only site (huggingface.co) with a real Proton Pass vault
(owner-authorized, low stakes). A scripted approver stood in for the owner and approved
only that origin.

- **Worked end to end:** the vault sync matched the vault's logins to sites; `auth_status`
  offered a password on `https://huggingface.co`; the approval display was exactly the
  owner's words, the verified origin, the agent name and `password`; the signer read the
  item through `pass-cli` and released the password once (`fill.released`); the fill
  driver found the username/password form, filled and submitted it; audit chain intact.
- **Headless is blocked by bot walls.** With the default headless browser, Hugging Face's
  CloudFront edge answers "The request could not be satisfied": the user agent says
  `HeadlessChrome`. Section 4 forbids disguising automation, so no UA spoofing. A headed
  browser (`keyflap daemon --headed`) on a virtual display (Xvfb, `DISPLAY=:99`) loads the
  real page with Chrome's normal UA. Expect this on many sites: run headed for real use
  (on the desktop, or Xvfb for a headless box; service mode gets an Xvfb option).
- **CAPTCHA after submit reads as `success`.** After the password submit, Hugging Face
  showed a "Human Verification" page at the same URL. The form was gone, so the fill
  reported `success` (the outcome means "submitted, and the login form went away"). The
  agent sees the challenge in its next snapshot. Solving it is out of scope (section 3);
  the owner has to complete it in a headed browser. **Fixed (sessions plan P1):** known
  providers' structured signals now make it `challenge` ("Human-check detection").
- **pass-cli force logout reproduced.** A second environment (a container) sharing the
  host's session dir without its keyring key logged the host session out. Re-login with
  the PAT fixed it. The same PAT can hold several sessions at once, so the clean setup is
  one `PROTON_PASS_SESSION_DIR` per environment (with `PROTON_PASS_KEY_PROVIDER=fs` where
  there's no keyring), never a shared one.
- **Headed Chromium on a Wayland desktop** died when windows closed during the
  run; under Xvfb the same code is fine (closing the last page doesn't end the browser).
  Not a broker bug as far as we can tell; use Xvfb for unattended runs.
- **Xvfb under a systemd user unit (2026-10-13):** the user manager's environment carries the
  desktop's `WAYLAND_DISPLAY` and `OZONE_PLATFORM`, so a headed Chromium started from a
  `systemd-run --user` unit with `DISPLAY=:99` tried Wayland instead, and `chromium.launch`
  never returned. Unset the Wayland/ozone variables (`env -u WAYLAND_DISPLAY -u OZONE_PLATFORM
  …`) for the daemon. Service mode is unaffected (system units don't inherit a desktop session).
- **Second run, phone approver (2026-10-13):** the full path worked from a phone over a
  TLS-terminating proxy (typed intent → Web Push → Face ID approval → Proton Pass fill), and Hugging Face
  again answered with its AWS WAF "Let's confirm you are human" page. Follow-up:
  `SESSIONS_PLAN.md` (honest `challenge` outcome, persistent browser state, human handoff).

## Phone approval (M4)

- **The phone's passkey is the approver key** (owner's preferred design, adopted as is).
  A `WebAuthnApproval` carries the statement plus the phone's raw assertion
  (`authenticatorData`, `clientDataJSON`, `signature`); `approverKeyId` is the passkey's
  credential id. The signer verifies it with node:crypto: clientData type `webauthn.get`,
  challenge = b64url(SHA-256(`approvalSigningBytes(statement)`)), origin = the approver
  origin recorded at pairing, no `crossOrigin`/`topOrigin`; authData 37 bytes, rpIdHash of
  the approver rpId, UP and **UV required**, no AT/ED; ES256 (DER) signature; counter must
  increase when either side is non-zero (persisted in the key store). The statement must
  say `userVerified: true`. The core never verifies-and-re-signs.
- **Trusted approvers live in the signer's key store** (`approvers`, public halves), not in
  core config: they are trust decisions. Ops `list_approvers`, `add_approver`,
  `remove_approver`. The first `add_approver` is **trust on first use**; after that, adding
  another needs an `approver.add` approval from an already-paired phone over
  `approverDescriptor(key)` (the new phone can't approve itself).
- **Phone-mode latch.** Adding the first approver sets `phoneLatched` in the store. While it
  is set, first use is closed and Ed25519 keys are ignored **even with no approvers left**,
  and the daemon's signer refuses to remove the last approver (`last_approver_needs_admin`).
  Without this, a core bug could remove the user's phone and pair its own key as "first use"
  (found in review; `inv6-user-verification.test.ts` covers it). Only the offline admin
  signer that `keyflap approver remove` spawns (daemon stopped, `approverAdmin` in its spawn
  config) may remove the last one, which clears the latch. Removing a non-last approver needs
  no approval (it only reduces trust).
- **No replay across restarts.** Single use is tracked in signer memory, and synced passkeys
  report signCount 0, so the signer refuses any approval issued before it started
  (`issued_before_signer_start`).
- **One assertion, several fill fields (fix, 2026-10-13).** A password + TOTP fill is one
  phone approval, but the core releases each field with its own `release_secret`, so the
  signer verifies the same assertion once per field. With an authenticator that counts
  (security keys, Chromium's virtual authenticator) the first field stored the counter and
  the second was refused as `sign_count_regressed` (the core audited it as
  `denied {reason: internal_error}` after `fill.released {field: password}`). Now, after a
  field is released under a phone approval, the signer remembers in memory
  `requestId → SHA-256(approverKeyId, authenticatorData, clientDataJSON, signature,
  requestId)` until the approval's `expiresAt`. A later field skips **only the counter
  check**, and only if it presents that exact assertion for a `fill` statement with
  the same requestId. Everything else still runs (signature, challenge = the statement, origin, rpId hash,
  UP/UV, freshness, `issued_before_signer_start`, item/domain/scope bindings, high-risk,
  each field at most once). Any other assertion still has to move the counter: another
  fill, a re-signed copy of the same statement (ECDSA is randomized, so its digest
  differs), and anything after a signer restart (the memory is gone and the counter is
  persisted). The stored counter now only ever rises (`setApproverSignCount`), so an
  earlier fill's second field can't lower it after a later fill raised it. Tests:
  `signer/test/inv6-fill-counter.test.ts`, `core/test/inv6-phone-fill-counter.e2e.test.ts`
  (phone harness, item with TOTP, two sign-ins).
- **Second-phone pairing check code.** Both the new phone (while it waits) and the
  already-paired phone (on the approval card) show a 12-hex-digit code derived from the new
  key's descriptor; the user approves only if they match. So whoever else redeemed the link
  first (it's single-holder: a second ceremony gets 409 and an explicit "don't approve"
  message) can't be mistaken for the user's phone. The code is also logged.
- If phones are paired only at another approver origin (the origin changed), pairing is
  refused with a message pointing at `keyflap approver remove` instead of failing obscurely.
- **High-risk tier (invariant 6; the rest of section 9 is M5, below).** `@aab/signer/risk`:
  a built-in list (government suffixes such as `gov`, `gov.uk`; major email and identity
  providers; payment, banking, brokerage and crypto sites) plus `highRiskDomains` from
  config, given to both broker and signer. Entries match the host or any subdomain, on
  label boundaries; an empty or unparseable host counts as high-risk. Hosts come from the
  URL parser (lower-case, punycode), so IDN spellings are compared as punycode. For a
  high-risk rpId / item domain / origin host:
  - the broker tags the request `policy: {tier: 'ask-strong'}` and refuses any approval
    that isn't a phone assertion (`user_verification_required`);
  - the terminal approver denies without prompting (`user_verification_unavailable`);
  - the signer independently requires a webauthn approval (so UV) with a lifetime ≤ 60 s.
  The list is incomplete by nature; users extend it with `--high-risk`.
- **Statement freshness.** The phone page asks for the challenge when the user taps
  Approve; the statement (issuedAt = now, 60 s lifetime) is fixed then, so the approval is
  fresh whatever the time spent unlocking the phone. Unanswered requests deny after 120 s
  in the approver; the broker's own approval timeout (90 s) usually ends them first.
- **Reachability (open question 6), decided for v1:** no relay of ours. The approver page is
  served by the daemon on an HTTPS origin the user provides: their own certificate, or a
  loopback listener behind a TLS-terminating proxy (`tailscale serve` is the documented
  path). Without TLS options the approver refuses non-loopback listeners (whatever the origin);
  origins must be `https:` (`http://*.localhost` only for tests). Behind a loopback proxy the Host check also
  accepts `127.0.0.1:<port>`/`localhost:<port>` (the proxy may rewrite Host); the Origin check
  on every POST is unchanged.
- **Push:** standard Web Push (VAPID ES256 JWT, `aes128gcm` per RFC 8291, tested against its
  appendix A vector) on node:crypto. The browser vendor's push service is a third party that
  relays ciphertext and sees timing and the endpoint; the payload is `{"t":"approval"}` and
  the notification text is fixed, so it learns nothing about the request. Push endpoints
  must be https, default port, on a known push service (FCM, Apple, Mozilla, WNS), so a
  paired device can't make the daemon POST to internal hosts. Optional: an open page polls every 2 s.
- **Pairing link** `<origin>/pair#<256-bit code>`, valid 10 minutes, single use, code in the
  fragment (not in Referer or server logs). Written to the daemon's stderr and to
  `<dataDir>/approver/pairing-url` (0600): only the broker's own account can read either once
  the broker runs as a service account. No TTY is involved anywhere in phone mode. Whoever
  redeems the first code becomes the approver; that is the TOFU step.
  The page takes the code out of the address bar at once and keeps it in that tab's
  `sessionStorage` until pairing succeeds, so a reload doesn't lose it (2026-10-27). A `/pair`
  page with no code anywhere shows "This link lost its pairing code" and how to open the link
  in Safari, instead of the ordinary unpaired page. The code stays in the fragment (owner
  decision 2026-10-27): Brave on iPhone drops it when it opens a camera-scanned link, and the
  fix is to say so, not to send the code to the server.
- **Device cookie** `__Host-aab_device` (Secure, HttpOnly, SameSite=Strict, a year),
  stored as a SHA-256 hash in `approver/devices.json` (0600). It lets a paired device list
  and deny pending requests, nothing more; approving always needs the passkey. Every
  request a device cookie authenticates asks the signer whether that device's key is still
  trusted (no cache; security review L1): a removed phone is dropped from `devices.json`
  on its next request (401), any live view it controls ends (`cancelled`), and
  `approver.device_untrusted` is audited. A signer that can't answer is a 503 with nothing
  shown (fail closed). Other devices aren't pruned on that path, to stay clear of a pairing
  that is just being recorded; those still drop at start.
- **Page hardening:** Host check (DNS rebinding), `Origin` = approver origin and
  `Sec-Fetch-Site: same-origin` (when sent) on every POST, JSON only, 16 KiB bodies; CSP
  `default-src 'none'` with self-only script/style/connect, `frame-ancestors 'none'` and
  XFO DENY (an Approve button must not be clickjackable), no-store, no-referrer. Display
  fields are written with `textContent`, after the terminal prompt's control/bidi
  replacement.
- **Registration parsing** uses `@simplewebauthn/server` in `@aab/approver` (already in the
  workspace for the test RP; the signer stays dependency-free). ES256 only, UV required,
  attestation `none`. The signer re-validates the key (point on curve, origin within rpId,
  https unless `*.localhost`).
- **Known limit (inherent to Phase B), closed 2026-10-20:** the approver page and the
  display fields were served by the broker process, and the page signed whatever challenge
  the core handed it. A fully compromised core could therefore show one thing and ask the
  phone to sign a statement for another of the user's accounts (one UV gesture, one
  short-lived request each). Now the page checks the statement against its card and
  computes the challenge itself, and in service mode the page's code comes from a separate
  service the core can't change: see "Approver integrity". A compromised core can still
  deny everything, and still show made-up "You said" words or agent name (not in the
  statement).
- **Known limit (dev mode):** the data dir and the daemon's log are readable by the agent's
  OS user, so an agent with shell access could redeem an open pairing link before the user
  does. Pair before giving the agent shell access, or use service mode, where the link is
  never logged and only `sudo keyflap approver pair` returns it.
- `keyflap approver list|remove` spawn their own signer, so the daemon must be stopped (as for
  `keyflap password`).
- Tests: the "phone" is a separate Chromium (never the managed browser) with a CDP virtual
  authenticator (test only, like test-rp's own passkey test), on `http://approver.localhost`.

## Approver integrity (web approver, 2026-10-20)

Plan: `APPROVER_INTEGRITY_PLAN.md`. Closes M4's known limit without the native app.

- **The page signs only what its card shows (all modes).** `page/approval-check.js` (a
  classic script loaded before `app.js` / `handoff.js`) holds the signer's canonical JSON,
  WebCrypto SHA-256, `approvalChallenge`, `handoffStartChallenge`, `checkCode`, and
  `checkStatement`. `/api/challenge` now also returns `statement` and `descriptor`;
  `/api/state` returns the broker's `now`; `/api/handoff/challenge` returns its `nonce`.
  The page never uses the server's `challenge` field (kept for other clients and tests).
- **`checkStatement`** is the iOS app's `StatementCheck` plus what only the web card has:
  request id, `userVerified`, lifetime (≤ 5 min, ≤ 60 s `strong`), freshness against the
  broker clock, unknown statement fields refused, site (`verifiedOrigin` equal to the card's,
  its host within `rpId` on a label boundary), kind × action × credential type (fill:
  `clientDataHash` = hash of the shown type's fill scope), allow-for signed exactly as shown
  and never on `strong`, `keepSignedIn` exactly when ticked (same site, `strong` only), P3b
  (`handoff` id, `clientDataHash` = `handoffSignInClientDataHash(id)` for a passkey, the
  single-use grant's window as shown), and for "add a phone" the descriptor (hash, check
  code, key id, this origin, passkey vs app). A mismatch is a `Mismatch`: the page denies
  the request and says so ("Something on the broker is not as it should be").
- **Not bound:** the agent's name and the "You said" words. The statement has no agent
  name, and `intentHash` is the core's own hash of an intent record the core holds, so a
  check would prove nothing against a compromised core. They stay display-only (invariant
  5's sources are unchanged); AGENT_ADMIN_PLAN decision 2 would add `agentId`.
- **Service mode: the page from its own service.** `keyflap-approver.service` (user `keyflap-web`,
  `packages/cli/src/service/approver-main.ts` → `@aab/approver/front`) serves the page files,
  read once from the root-owned install, and forwards `/api/*` to the core over
  `/run/keyflap-approver/api.sock` (`keyflap-core-approver.socket`, root:keyflap-web 0660, directory
  root:keyflap-web 0750; the core gets it as fd `approver-api` and runs `PhoneApprover` with
  `apiOnly`). `keyflap-approver.socket` holds the approver's TCP listener (default
  `127.0.0.1:8766`) in PID 1 for as long as the unit is enabled, so the core's uid can't bind
  it even while the front restarts (isolation-tested, `EADDRINUSE` on 127.0.0.1 and
  0.0.0.0). The front's sandbox: `RestrictAddressFamilies=AF_UNIX` (it accepts on the
  inherited socket and connects to the core's Unix socket, nothing else), no state.
- **What the front lets through from the core:** 2xx/4xx/5xx status; `content-type` exactly
  `application/json; charset=utf-8` with a body that parses (or `image/jpeg` on a 200 for
  `GET /api/handoff/frame`); at most one `set-cookie`, the device cookie in exactly the form
  phone.ts sets; 256 KiB JSON / 8 MiB frame. Anything else is a 502 with no core bytes. All
  other response headers, and the security headers (CSP `script-src 'self'`, `nosniff`, …),
  are the front's. So the core can't put a document, a script, a foreign cookie or a service
  worker on the page's origin. Requests: only `/api/*` with GET/POST, Host checked by the
  front and forwarded as the origin's host, request headers limited to `content-type`,
  `content-length`, `cookie`, `origin`, `sec-fetch-site`, `authorization`, bodies ≤ 16 KiB.
- **TLS moved to the front.** `--tls-cert/--tls-key` credentials load into
  `keyflap-approver.service.d/tls.conf`; `core.json` has `approver.front` and `tls: false`
  (the parser refuses both together). `/etc/keyflap/approver.json` is the front's config.
- **Dev mode unchanged** apart from the page check: one process serves page and API (the
  agent's own uid could edit either anyway, docs/ISOLATION_PLAN.md).
- **Upgrades:** `install.sh` stops `keyflap-approver` too, and restarts the socket units, so the
  listener moves from an old core to `keyflap-approver.socket`. `--approver-listen` must be an IP
  literal in service mode (systemd binds it).

## Native iOS approver (Phase C)

*Parked 2026-10-20 (see Status). Everything below is built and tested on Linux; the app
target has never been compiled or run on a device.*

- **The approver key lives in the iPhone's Secure Enclave** (`ios/`, CryptoKit
  `SecureEnclave.P256.Signing.PrivateKey`), one per paired broker, access control
  `.privateKeyUsage` + `.biometryCurrentSet`: every signature needs a fresh Face ID /
  Touch ID match (new LAContext each time, no reuse window, no passcode fallback; enrolling
  new biometrics retires the key). The key never leaves the chip; the app keeps its opaque
  handle and the broker's bearer token in the Keychain (this device only).
- **Native approval** (`NativeApproval` in `@aab/signer/approval`): `{statement,
  approverKeyId, native: {signature}}`. The signature is **ECDSA P-256 / SHA-256, DER**
  (CryptoKit's `derRepresentation`; Node verifies with `dsaEncoding: 'der'`; raw r||s is
  refused, tested) over `nativeApprovalSigningBytes(statement)` =
  `"aab-native-approval-v1\n" + canonicalJson(statement)`: the same canonical statement
  as `approvalSigningBytes`, under its own domain prefix so a native signature can't stand
  for anything else. The key id is derived, `b64url(SHA-256(04||X||Y))`, so nobody picks
  it. No signature counter (the Secure Enclave keeps none); replay is covered as for
  passkeys: single use per requestId, `issued_before_signer_start`, expiry. An approval
  carrying both `native` and `webauthn` is refused (`bad_approval`).
- **Pairing rules are M4's, unchanged.** New signer op `add_native_approver {key: {x, y,
  origin, userVerification: 'biometry'}, proof, approval?}`: the first phone of either
  kind is trust on first use (one-time code); later ones need an `approver.add` approval
  (with UV: passkey or native) from an existing phone over
  `nativeApproverDescriptor(key)`; passkey phones and app keys vouch for each other. The
  latch covers both kinds (Ed25519 ignored once any phone is paired; only `keyflap approver
  remove`, daemon stopped, removes the last phone). `proof` is the app's signature over
  `"aab-native-pair-v1\n" + descriptor`: it holds the key, and making it is the first
  Face ID. Keys stored under `nativeApprovers` in the encrypted key store.
- **Invariant 6 decision: native approvals count as user-verified, including for
  high-risk / `strong` statements.** The signer can't attest that the key really requires
  biometry; it relies on the app's declaration at pairing (`userVerification: 'biometry'`,
  the only value it accepts) and on the pairing being the owner's act (the one-time code,
  or an existing phone's UV approval showing the check code). That is the same trust the
  M4 path already places in a passkey: with attestation `none`, the UV flag is also the
  authenticator's own unverifiable claim, made on every assertion by software we never
  vetted. The native key is, if anything, stronger: device-bound and non-exportable (an
  iCloud Keychain passkey syncs to every device on the Apple ID, and its UV may be a
  device passcode), biometry-only, and the code that shows the request and builds the
  signed bytes is the app's, not the broker's. Upgrade path: App Attest (paid account)
  would let the signer verify that a key was made by the genuine app on a genuine device;
  not done. If the owner prefers high-risk to stay passkey-only, the change is one line in
  `isUserVerifiedMethod`.
- **What the app checks before it signs** (`StatementCheck` in the Swift core; the
  signer re-checks its own rules): request id, `userVerified`, lifetime (≤ 5 min, ≤ 60 s
  when `strong`), freshness against the broker's clock (offset from each state answer),
  `verifiedOrigin` equal to the origin shown and within `rpId`, kind consistent with what
  was shown (`webauthn.get`/`.create` vs sign-in/register passkey, `fill` with
  `clientDataHash` = hash of the fill scope of the credential type shown), M5 grants (a
  shown allow-for window must be signed exactly, `until - issuedAt`, and vice versa; none
  on `strong`), and for "add a phone" the descriptor (its hash is the statement's
  `clientDataHash`, its key id the `credentialId`, its origin this broker, its check code
  the one shown). **Statement fields the app doesn't know are refused** (the user must
  have seen everything the signature covers); unknown display fields from a newer broker
  are shown generically. This closes M4's known limit of the broker serving the page that
  shows the request.
- **Canonical encoding across languages.** The Swift core re-implements `canonicalJson`
  (keys sorted by UTF-16 code units, `JSON.stringify` string escaping, integers only within
  ±(2^53−1); a strict parser refuses floats, duplicate keys and lone surrogates), plus
  SHA-256 (no CryptoKit on Linux), the descriptors, fill scopes and check codes. Fixtures
  in both directions (`ios/KeyflapApproverCore/Fixtures/`).
- **The app's API** (`/api/native/*` on the phone approver server): `pair`,
  `pair/status`, `state`, `challenge`, `decide`, `apns`, `unpair`. Bearer token (a
  native device in `devices.json`, hashed like the cookie; a cookie never works as a
  bearer token or vice versa), JSON only, 16 KiB, Host check; no Origin needed (no ambient
  credential, so no CSRF), but a browser Origin other than the approver's is refused.
  `state` returns only the display fields (invariant 5), the request's expiry and the
  broker's clock; `challenge` returns the statement (fixed then, as for passkeys) and, for
  "add a phone", the new key's descriptor. A device can approve only with its own key.
  Deny needs only the token: **a forged deny is a denial of service, never a sign-in**, so
  the lock-screen Deny works without unlocking or Face ID. `unpair` drops the device and
  untrusts its key unless it is the last phone (`last_approver_needs_admin`, as before).
- **Push: APNs** (`packages/approver/src/apns.ts`, node:http2 + node:crypto): token auth
  with the owner's .p8 (ES256 JWT, `kid` + `iss` + `iat`, cached 50 min, dropped on
  `ExpiredProviderToken`), topic = bundle id, sandbox or production per device (the app
  reports it; `--apns-sandbox` sets the default), `apns-expiration` = the request's
  remaining time, collapse id = request id; 410 / BadDeviceToken / DeviceTokenNotForTopic
  drop the token. Optional: without `--apns-*` nothing is sent and the app polls every 2 s
  while open. **Payload: the request id and the verified site's host** ("Approve sign-in to
  github.com?"), never the user's words, agent or anything secret; Apple sees it, so
  `--apns-generic` sends fixed text instead. (A Notification Service Extension could fetch
  the text on the phone instead; not done.) Tested against a local fake APNs (h2c).
- **Lock-screen Approve** is `.foreground` + `.authenticationRequired`: it opens the
  request sheet with all its details and then starts Face ID for the signature; it never
  approves from the notification text alone.
- **Pairing QR**: `packages/approver/src/qr.ts`, a dependency-free encoder (byte mode,
  level M, versions 1-10), checked once with zbar for every version and mask; the daemon
  prints it under the pairing link when stderr is a terminal, `keyflap approver qr` on demand.
  The QR holds the same `https://<origin>/pair#<code>` link the web page uses.
- **Build layout**: `ios/KeyflapApproverCore` (Foundation only; Linux + macOS tests),
  `ios/` (xtool package: one library product with `@main`, `xtool.yml`, Info.plist,
  entitlements with `aps-environment`), `ios/xcode/project.yml` (XcodeGen, same shape as
  xtool's generated project) for CI and TestFlight. The CI workflows are in `ios/ci/`
  because this machine's token can't push `.github/workflows/` (needs the `workflow`
  scope); the owner copies them (docs/integrations/ios-app.md). The XcodeGen spec was
  generated on Linux (XcodeGen built in a swift container); the app's Swift was reviewed but
  never compiled here.

## Policy and sessions (M5)

- **Rules.** `policies(origin_pattern, agent_id, mode, allow_for_ms, session_ttl,
  updated_at)`; `allow_for_ms` is added to section 10's table (migration for older
  databases). Pattern: an exact origin (`https://app.example.com`, `http://` only on
  `*.localhost`) or a domain (`example.com` = the host and every subdomain, on label
  boundaries). Domains must have a registrable domain (PSL, private section included): no
  public suffixes (`com`, `co.uk`, `github.io`), no IPs, no wildcards, no `*` pattern (a
  global deny would switch the broker off, a global allow-for is a footgun). Agent: an
  active agent id (checked by the CLI) or `*`. Mode `none` = a TTL-only rule. Ranges:
  allow-for 1 s .. 24 h, session TTL 1 s .. 30 days. A row with a mode the broker doesn't
  know (hand-edited) resolves as `deny` for what it covers (fail closed).
- **Resolution: every matching rule applies; the strictest wins** (deny > ask-strong > ask >
  allow-for with the shortest window > default ask; the shortest TTL). Deviation from the
  suggested "most specific wins, agent-specific beats all-agents": with specificity, a
  narrower or agent-specific `allow-for` could weaken a broader `ask-strong`, and the
  outcome depends on precedence rules users would have to get right. With strictest-wins,
  `deny` always wins (the denylist can't be undone by a narrower rule), a rule can only
  tighten, and a narrower `ask` carves an exception out of a broader `allow-for`. The cost:
  you can't make one subdomain *less* strict than its domain's rule; remove or narrow the
  broad rule instead. The high-risk list is applied on top and only raises to `ask-strong`.
- **Read per request.** `PolicyStore.resolve` queries SQLite on every request (no cache), so
  `keyflap policy` edits made while the daemon runs apply to the next request (e2e-tested with
  the real CLI process). Agents never see or set policy: no MCP tool takes it, and the only
  agent-facing effect is `denied`.
- **Order in the broker:** verified origin → policy (`deny`: `denied {reason: policy_deny}`,
  before any credential lookup, intent check or prompt) → rpId / credential → live intent
  (always, inside allow-for windows too) → approval or grant → signer. A `policy {requestId,
  agentId, verifiedOrigin, mode, allowForMs?, rules}` event is audited whenever a rule
  matched. The denylist stops credential operations, not browsing.
- **`ask-strong` reaches the signer as a signed statement field.** `buildStatement` adds
  `strong: true` when the request's tier is `ask-strong` (policy or high-risk); the signer then
  requires a phone (webauthn, so UV) approval with a lifetime ≤ 60 s and refuses any grant,
  exactly as for its own high-risk list, and the broker refuses an approval for an
  `ask-strong` request whose statement lacks it (`strong_not_signed`). Rejected: handing the
  signer the DB's ask-strong domains at start. That list would go stale as soon as `keyflap
  policy` edits SQLite under a running daemon, and in service mode the signer's config is
  root-provisioned. The policy source is the core's database either way, so a compromised
  core could drop the flag; that's the same trust as the policy itself. The signer's own
  high-risk list stays the independent floor (invariant 6). In phone mode every approval is
  already UV + 60 s, so `ask-strong` there mostly means "never allow-for"; with the terminal
  approver it means "denied".
- **allow-for grants (signer-enforced).** The statement the user signs gains `grant:
  {agentId, until}` (`until = issuedAt + window`, built by the approver from
  `binding.grant` when the statement is fixed). The user's own approval authorizes the
  window. The signer:
  - refuses the whole operation (`grant_not_allowed`) if the statement is `strong`, the
    rpId/item domain or origin is high-risk, the kind isn't `webauthn.get` / `fill` (a
    registration always asks), the window is > 24 h or not after `issuedAt`, or the
    grant is malformed;
  - records `{agentId, kind, exact origin, rpId, credential, fill scope, until}` **in
    memory** when it consumes that approval (a restart drops every grant; at most 256,
    oldest dropped first);
  - accepts a `GrantedApproval {statement, grantId, agentId}` only if that grant exists, is
    open, and agent, kind, origin, rpId and credential match exactly (fill: the requested
    scope is a non-empty subset of the granted one). The statement is the core's, so it
    gets every usual check: ≤ 5 min lifetime, fresh, clientData hash and origin, single use
    per requestId (the granting requestId stays spent), each fill field once. It may not
    claim UV, `strong` or a grant of its own, and high-risk origins refuse it whatever it
    says.

  What a compromised core can do with a grant: sign in again to the same origin, with the
  same credential, as the same agent, until the window ends (what the user approved). What
  it can't do: get a grant without the user's signed approval; widen one (another origin,
  credential, kind, longer window, high-risk site); claim UV; outlive a signer restart. The
  core also keeps its own copy and uses a grant only while the policy still says allow-for
  for that agent and origin (re-read per request), capped by the policy's *current*
  window, so narrowing a rule takes effect at once. Every use is a full request with its own
  trail (`request`, `policy`, `grant.used {requestId, grantId}`, outcome) and no prompt;
  `grant.created` when the signer accepted the first use; a grant the signer refuses (e.g.
  after a restart) denies that request (`grant_refused`, `grant.dropped {reason}`), is
  forgotten, and the next login asks. Revoking an agent drops its grants in the core, and
  the broker refuses every request of an agent the agents table doesn't hold as active
  (`agent_revoked`, read per request and again before each signer operation, so a revoke
  from another process counts too; "Security review: origin and policy fixes").
- **Display.** `display.allowForMs` (broker-authored, from the user's own policy; precedent:
  `action`, `intentAt`) renders as "approving also lets this agent sign in here again
  without asking, for N minutes" in the terminal prompt and on the phone card (same
  wording, `textContent`). It must equal `binding.grant.durationMs`, and an `ask-strong`
  request can't carry a grant. Approvers deny inconsistent requests unseen
  (`inconsistent_request`). Phase B's known limit applies: the phone renders what the
  broker serves, so a compromised core could show 10 minutes and have the statement say
  more. The signer's 24 h cap bounds that. (Closed 2026-10-20: the page checks the signed
  statement itself; see "Approver integrity".)
- **UV inside a window is off.** A grant use sets UV = 0 in authenticatorData (the user
  verified once, not for this login). Sites that require UV reject those logins; use `ask`
  for them. Grants are per exact origin even when the rule is a domain, so each origin
  under it asks once.
- **Session TTL.** After a broker login succeeds (passkey signed, or a fill whose form went
  away), `SessionTtl` records (agent, origin, time); a new login restarts the clock. A sweep
  (every 30 s, `sessionSweepMs`) re-reads the policy for each entry, so TTLs set later
  apply to existing sessions. When the TTL has passed it ends the session on that **site**
  (registrable domain) in the agent's context and audits `session.cleared {agentId, origin,
  ttlMs, cookies, pages}`:
  - closes the agent's pages on the site (in-memory state and sessionStorage go with
    them; the agent's next `browser_open` gets a fresh page);
  - clears every cookie whose domain is the site or under it (`context.clearCookies`);
  - clears the storage of every origin on the site the context used (the origin, every
    closed page's origin, every origin a frame of the context showed, every origin in the
    last saved snapshot; local storage, IndexedDB, cache storage, service workers...) with
    CDP `Storage.clearDataForOrigin`. (Before the review fix it was only the origin and the
    open pages' origins, review M3.)
    Playwright has no API for that. The session is opened on a **throwaway page of the
    core's own**, never one the agent drives. It is closed right away (which ends the
    session; the "detaching resets the tab's WebAuthn environment" caveat only touches
    that page), and the agent's session never tracks it (pages that appear while it opens
    are held back and only tracked if they aren't it).

  A cleanup that fails is audited (`session.clear_failed`) and retried on the next two
  sweeps. Only logins the broker performed are tracked. ~~Contexts aren't persistent, so
  nothing survives a daemon restart.~~ **Superseded by sessions plan P2:** contexts persist
  and so do the clocks (`session_clocks`); restore fails closed ("Persistent browser
  state"). `session.cleared` gained `via: 'ttl' | 'restore' | 'admin'`.
- **CLI.** `keyflap policy set <site> [--deny|--ask|--ask-strong|--allow-for DUR] [--agent ID]
  [--session-ttl DUR|off]` (upsert: given fields overwrite, others kept; a rule left with
  neither mode nor TTL is removed), `keyflap policy list [--agent ID] [--json]`, `keyflap policy
  remove <site> [--agent ID]`; audited `policy.set` / `policy.removed`. `keyflap status [--json]`
  (agents, credential counts, rules, audit chain check, last 10 entries) and `keyflap audit
  verify` (exit 1 if broken) / `keyflap audit tail [--limit N] [--json]`. All SQLite only, so
  they work while the daemon runs. `args.ts` doesn't import core (the hook path stays
  light), so it has its own duration parser; ranges are checked by `PolicyStore`.
- **Not done in M5:** an admin socket in dev mode (service mode has one). ~~Cross-process
  revoke still leaves the revoked agent's context open until restart.~~ Fixed: the broker
  refuses the agent at once and the daemon closes its context within 2 s (review L3). No per-grant
  use limit inside a window (P3b added single-use grants, for its combined approval only); removing an allow-for rule stops the core using the grant at
  once, but the signer's copy lives until it expires or the signer restarts.

## Human-check detection (sessions plan P1)

- **Why.** A password fill reported `success` whenever the form went away, so a WAF or
  CAPTCHA page in its place read as a sign-in (Hugging Face, 2026-10-13). Now
  `auth_login` answers `challenge`, and `auth_status` / `browser_snapshot` carry
  `humanCheck: boolean`. The broker never solves, clicks or answers a check (section 3).
- **Signals (`core/src/challenge.ts`): structured, trusted side only, never page text.**
  A `ChallengeWatch` per page (attached in `AgentSession.track`, Playwright
  `request` / `response` / `framenavigated` events, no CDP session) records the main-frame
  document response and the challenge hosts requested since the last navigation.
  `detectHumanCheck` is positive when the *current* main document came with
  `x-amzn-waf-action: captcha|challenge` or `cf-mitigated: challenge` (same URL, fragment
  ignored), or a frame on a known challenge host is an interactive widget whose `<iframe>`
  element is visible and at least 60×60 CSS px (`frameElement()`, `isVisible()`,
  `boundingBox()`, on Playwright's own page session). Hosts match on label boundaries
  (`x.captcha.awswaf.com.evil.localhost` is not one). Interactive: Turnstile frames,
  hCaptcha `#frame=checkbox|challenge`, reCAPTCHA `api2|enterprise` `/anchor` without
  `size=invisible` and `/bframe`, Arkose, DataDome, HUMAN, `captcha.awswaf.com`; not
  `token.awswaf.com` (silent script). A script host alone never counts. A whole scan is
  capped at 3 s and anything unreadable counts as "no".
- **Fill outcome (`fill.ts`).** A check that stays at least 750 ms over a form that is still
  there (a popup) ends the fill as `challenge`; when the form went away (or the page left
  the origin) the driver waits up to 2 s for `load` and checks once. Post-fill clearing
  runs as before. `fill.completed` gains `humanCheck: <provider>` (audit only; the agent
  gets the outcome and a boolean). No session-TTL clock starts for a `challenge`. The
  passkey path is unchanged (the ceremony did complete; the agent sees `humanCheck` next).
- **Spoofing.** A page can fake a signal (send the header, frame a lookalike URL). That
  only ever produces `challenge` / `humanCheck: true`: never a credential operation, never
  page text in broker output.
- **Agent text.** OUTCOME_HELP says the broker will not solve it and the agent must not
  try; since P3 it says to call `browser_handoff` so the user completes it on their phone,
  then continue (`browser_snapshot` says the same for `humanCheck`).
- **Tests only:** `DaemonOptions.challengeHosts` adds frame hosts (as `launchArgs` does);
  automated tests use `captcha.localhost`, never the providers' hosts. The test RP gained
  `challenge: 'aws-waf' | 'cloudflare' | 'frame' | 'text-only'`, `invisibleWidget`,
  `POST /challenge/solve` (clearance cookie) and a request log.
- **Test gotcha:** a page served by `route.fulfill` has no network address, so Chromium's
  private-network rules block a *loopback* subframe in it (`chrome-error://`); fulfil the
  subframe through a route too. Give routed pages `charset=utf-8`, or forms post non-ASCII
  in windows-1252.
- **Known limits:** detection is a known-provider list; a site's own home-made check reads
  as `success`. Turnstile and others may refuse automated browsers even after a human
  passes (section 4 forbids disguise; a correct outcome, not a bug).

## Persistent browser state (sessions plan P2)

- **What.** Each agent's cookies, localStorage and IndexedDB survive a daemon restart.
  Still one browser per broker: Playwright `context.storageState({indexedDB: true})` to
  save, `browser.newContext({storageState})` to restore (shim `newContext(handler,
  {storageState})`). Both run in Playwright's utility world or on its own hidden page,
  whose every request is fulfilled locally with `<html></html>` (no network, no site
  script; tested against the RP's request log), and which is never emitted to the client.
  The restore happens inside `newContext`, before `block.cover()` and the binding. Not
  persisted: sessionStorage, cache, history, service workers, permissions.
  `launchPersistentContext` was rejected (one browser per agent; it persists Chromium's
  whole profile, password store included).
- **At rest (invariant 1).** `<dataDir>/browser-state/` (0700, must be a real directory
  owned by us), `<agentId>.state` (0600), written to `.tmp-<random>` with
  `O_CREAT|O_EXCL|O_NOFOLLOW`, fsync, rename, directory fsync; opened `O_NOFOLLOW`, must be
  a regular file owned by us, size-capped. Agent ids must be UUIDs before they touch a path.
  Service mode: `/var/lib/keyflap/core/browser-state` (under `StateDirectory`, so no installer
  change; `uninstall.sh --purge` removes it). The isolation suite checks EACCES for the
  user uid.
- **Encryption (decision 2: option B).** New signer op `browser_state_key` (no approval,
  like `store_item`; reachable only over the authenticated channel, invariant 9 tested):
  32 random bytes created once in the encrypted key store (`stateKeys.browser`), so it
  survives a passphrase or KEK change. The core fetches it once at start and keeps it in
  memory. AES-256-GCM, a fresh 12-byte IV per write, AAD `"aab-browser-state-v1\n" +
  agentId`; file `{v: 1, iv, tag, ct}`. Without the key (signer error) persistence is off
  for that run: nothing restored or saved, files kept, `browser_state.unavailable`
  audited. The signer stays dependency-free (`randomBytes`).
- **Save filters (run on every save and at restore):**
  - *secrets (invariant 8):* a cookie whose name or value, or an origin whose
    localStorage / IndexedDB (each string and the whole JSON) holds any `scrub.ts` spelling
    of a value in `AgentSession.secrets()` is dropped; for storage the whole origin goes
    (fail closed). The test is "scrubbing would change it", so it matches exactly what
    output scrubbing catches. Never written to disk, so it can't come back after a restart
    when the scrub list is empty;
  - *denylist (decision 4):* a site (registrable domain) is dropped if any known origin
    resolves `deny` for the agent (state origins, origins the agent's pages showed, clock
    origins, `https://<site>`, `https://<cookie domain>`);
  - *high-risk (decision 3 as decided):* not persisted unless the owner opted in for that
    agent and site (below);
  - *session TTL:* a site with a TTL needs a live clock, at save and at restore;
  - *queued clears*;
  - *size:* 16 MiB of plaintext per agent; IndexedDB of the largest origins goes first,
    then localStorage; cookies are never trimmed (`browser_state.trimmed`).
  Anything the verdict can't decide (an error) drops the site.
- **Schedule (`AgentSessions`).** Full saves after a broker login, after a site clear, every
  10 minutes while dirty, and on shutdown (5 s per agent, 10 s overall, before
  `browser.close()`); cheap saves (cookies only, merged into the last full snapshot's
  origins) every 60 s while dirty and the cookie hash changed. Every tool call and login
  marks the session dirty. One save at a time per agent; a crash loses at most ~60 s of
  cookies.
  **The shutdown save needs `KillMode=mixed`** (found 2026-10-13 on the owner's demo
  restarts, which audited `browser_state.save_failed` every time): systemd's default
  `control-group` sends SIGTERM to Chromium together with the core, so the last save found
  the browser gone. `keyflap-core.service` now has `KillMode=mixed` (SIGTERM to the core only;
  leftovers are killed after it exits) and `TimeoutStopSec=30`; `inv1-isolation` asserts no
  `save_failed` across a `systemctl restart keyflap-core`. A dev daemon run under a
  `systemd-run --user` unit needs `-p KillMode=mixed` too. Routine saves aren't audited; failures are, once per distinct reason
  (`browser_state.save_failed`, then `save_ok`); secret drops are
  (`browser_state.filtered {agentId, secret: {cookies, origins}}`).
- **Revoke.** Checked before every write and again after the rename (unlink if revoked
  meanwhile), so a dev-mode CLI revoke racing a save leaves nothing. The daemon's own
  revoke (service mode, admin socket) discards the context **without saving** and deletes
  the file, clocks, index rows and the agent's opt-ins (`browser_state.deleted {reason:
  'revoked'}`). `keyflap agent revoke` in dev mode deletes the file and rows itself; the
  daemon's context stays open until restart but is never saved again (e2e-tested with the
  real CLI process). At start, files and rows of inactive or unknown agents are deleted
  (`reason: 'agent_inactive'`).
- **Restore (first tool call).** Load and decrypt (undecryptable, malformed, too large, not
  a regular file → deleted, `browser_state.discarded {reason}`); apply queued clears; run
  the filters plus the TTL rule; write the filtered state back at once if anything was
  dropped (so a crash can't bring a dropped site back); create the context with it (if
  that throws: an empty context, `discarded {reason: 'restore_failed'}`); audit
  `browser_state.restored {agentId, sites, cookies, origins, dropped: {ttl, deny, highRisk,
  cleared, secret}}`, sites and counts only.
- **TTL clocks persist** (`session_clocks`): `record()` upserts; the policy is re-read each
  sweep, so the deadline is `started_at + current TTL`. A clock is deleted only when it
  expires or its agent is inactive (M5 deleted clocks of agents with no loaded context).
  An expired clock of a loaded agent clears the live site and saves; of an unloaded agent,
  its file is rewritten without the site, no browser involved. At restore, a site with a
  TTL and no live clock (expired, or the row is gone) is cleared before the context exists
  (`session.cleared {via: 'restore', pages: 0}`). Decision 12 (a completed handoff starts
  the clock) is P3; `SessionTtl.record()` is the entry point.
- **High-risk opt-in (owner decision 3, 2026-10-13).** High-risk sites are still not saved
  by default; the owner can opt in per (agent, site): `persist_optins(agent_id, site,
  created_at, via)`, site = registrable domain, agent `*` = every agent. Written only
  through `PersistOptins.add/remove(agentId, site, via: 'cli' | 'admin' | 'approval')`:
  `keyflap sessions keep|unkeep <site> [--agent ID]` (dev, SQLite) and core admin ops
  `sessions.keep|unkeep` (service). No MCP tool reaches it (tested: every tool refuses
  extra arguments, and the table is unchanged). Audited `session.keep_set` /
  `session.keep_removed {agentId, site, via}`. A removed opt-in drops the site from the
  saved state: at once through the admin op, else on the next sweep (it compares the
  opt-in set between sweeps and refilters the affected agents). An opt-in never overrides
  the denylist. P3's "Keep me signed in on <site>" checkbox on the phone card calls
  `add(..., 'approval')` from the owner's signed approval ("Human handoff (sessions plan
  P3)" below).
- **Admin.** `keyflap sessions list [--agent ID] [--json]` (index, clocks, policy, opt-ins;
  counts and times only, works while the daemon runs), `keyflap sessions clear (--agent ID |
  --all) [--site SITE]` (dev: queued in `session_clear_requests`, one row per agent; the
  daemon applies it on its next sweep, or the next start before restoring; service: admin
  op `sessions.clear` applies it at once), audited `session.clear_requested {agentId|'*',
  site, via}` then `session.cleared {via: 'admin'}`. `keyflap status` shows "Saved sessions: N
  agents, M sites". Off switch (decision 13: on by default): `keyflap daemon
  --ephemeral-browser`, `browser.persist: false` in `/etc/keyflap/core.json`
  (`install.sh --ephemeral-browser`).
- **Known limits.** Transformed copies of a filled secret (base64, upper-cased, a space
  replaced) are not caught by the save filter either, and now outlast a restart (the
  inv8 test keeps exactly the scrub spellings). `cf_clearance`-style cookies are bound to
  the user agent, so switching between headed and headless invalidates them. A deny or TTL
  rule on an exact `http://host:port` origin only matches a cookie-only site through the
  origins the agent's pages showed (cookies carry no port); domain rules always match.

## Human handoff (sessions plan P3)

- **What.** When a site answers the agent with a human check, the agent calls
  `browser_handoff` (decision 9: never automatic). The owner's paired phone gets "Human
  check on <host>"; the owner opens `/handoff`, confirms once with Face ID, sees a live view
  of that one page, taps and types through the check, and taps Done. The agent's call
  returns `done` and it continues with ordinary tools. The broker never solves, clicks or
  answers a check (ARCHITECTURE section 3, now said there explicitly).
- **Core (`core/src/handoff.ts`, `HandoffManager`).** The gate, in the plan's order, each
  refusal audited `handoff.denied {agentId, verifiedOrigin?, reason}` with no push:
  handoff-capable approver (`not_available`); a current page with a verified origin from
  the frame URL (`not_eligible`); policy not `deny` (`policy_deny`); `detectHumanCheck`
  positive (`no_human_check`, decision 7); a live intent (`no_live_intent`, invariant 4);
  no approval waiting for the agent (`approval_pending`, the broker counts approvals in
  flight per agent); at most 2 open (`too_many_open`), 3 pushes per agent per 10 minutes
  (`rate_limited`), 30 s after a cancelled or expired one (`cooldown`); a paired phone
  browser (`not_available`). One open handoff per agent: a second call joins it. A handoff
  is bound to (agent, the Playwright page, its site = registrable domain, the verified
  origin at open) and ends on Done / Cancel (controlling device only), 5 minutes
  (`expired`), the page closing (`page_closed`) or its main frame leaving the site
  (`left_site`, checked on `framenavigated` and again before every frame and input),
  revoke, or daemon stop. `browser_handoff` waits up to `timeoutMs` (1–120 s, default 45 s)
  and answers `pending` while it is open; an outcome a `pending` call missed goes to the
  next call within 60 s. The agent gets a status only (`left_site` / `page_closed` /
  `revoked` / daemon stop read as `cancelled`).
- **While open (invariants 5 and 6).** `Broker.handleWebAuthn` and `Broker.fill` deny every
  operation of that agent with `handoff_open`, right after the policy check and before any
  credential lookup, approver or signer (`Broker.setHandoffCheck`; a throwing check counts
  as open). `AgentPort.call` fails every other tool of the agent with a fixed `ToolError`
  ("a human check is in progress on your page; call browser_handoff to wait for it"), so the
  agent can't act or watch partial input. So no approval card for that agent can sit next
  to the live view, and a page drawing a fake "Approve" in the picture gets only a click on
  itself.
- **Frames (invariant 7).** `page.screenshot({type: 'jpeg', quality: 60, scale: 'css',
  timeout: 5000})` on Playwright's existing page session: no CDP session is attached or
  detached (tested with spies on the context and the browser, and native WebAuthn still
  lands in the empty virtual environment afterwards). Only for the device that started
  the view, only while the main frame is on the handoff's site, at most one capture per
  250 ms (single flight), the latest frame in memory only, never logged or written.
  Served as `GET /api/handoff/frame?id=` (`image/jpeg`, no-store, CORP same-origin, the
  existing `img-src 'self'`).
- **Input.** `POST /api/handoff/input {id, input}`: `click {x, y}` and `drag {from, to}` as
  fractions of the image, mapped onto `page.viewportSize()` (`page.mouse`); `scroll {dy}`
  (integer, |dy| ≤ 5000, `mouse.wheel`); `key` from Enter, Backspace, Tab, Escape and the
  arrows; `text` (1–256 characters, no C0/C1 controls, `keyboard.insertText`). Inputs are
  validated strictly (unknown fields refused), run one at a time, never retried (an error
  is a refusal). Text is refused when the focused element of any frame matches
  `SENSITIVE_FIELDS_CSS` (read in Playwright's utility world; unknown counts as yes),
  audited `handoff.input_refused {handoffId, reason: 'sensitive_field'}`, and the phone
  shows "Use the broker's sign-in for passwords". Text of 4+ characters goes through
  `session.rememberSecret()` **before** insertion (decision 6), so it is scrubbed from all
  agent output and filtered out of saved state (invariant 8, tested end to end).
- **Approver (`approver/src/phone.ts`, `page/handoff.{html,js,css}`).** `/handoff` is its
  own document and script with a steel header band and the picture in a steel bezel (no
  blue; see "Live view restyle: steel, not amber" below); it never calls the
  approvals endpoints and renders no approval card; the approvals page shows an open
  handoff only as a link card from `state.handoffs: [{id, host, agentName}]`. Handoffs are
  never in `pending` (web or native), and the native state has no `handoffs` key, so old
  clients and the iOS app's `.unknown` case never see one. The start check:
  `POST /api/handoff/challenge` returns SHA-256 of `"aab-handoff-start-v1\n" + id + "\n" +
  nonce` (single use, 2 minutes) with `allowCredentials` = this device's own passkey;
  `POST /api/handoff/start` verifies the assertion with `@simplewebauthn/server` against
  the signer's trusted key for that passkey (UV required, no cross-origin / top-origin),
  then the first device to start controls the handoff (`handoff.started {handoffId,
  deviceId}`). An approval assertion can't start a handoff and a start assertion can't
  approve (different domain prefixes; tested both ways). The signer is not involved.
  Chrome is broker-written with `textContent` after `clean()`: verified host, agent
  name, "You said …", "Live view of the website. Nothing in this picture is from the
  broker, and nothing here can approve a sign-in.", "The agent can see this page after you
  tap Done. Don't type passwords here." Same CSP as the approvals page (no `blob:` or
  `data:`), Host / Origin / `Sec-Fetch-Site` / JSON / cookie checks on every endpoint.
- **Fewest taps (the owner's priority).** The Web Push notification opens `/handoff`
  directly (the service worker focuses or navigates an open window); the page tries the
  Face ID start by itself on load and shows **Start live view** only if the browser wants
  a tap first. So: notification → one Face ID → live view → Done.
- **Push.** Web Push payload `{"t": "handoff", "host": "<verified host>"}` (encrypted;
  the push service sees ciphertext). APNs: `kind: 'handoff'`, title "Human check", body
  "Human check on <host>" (fixed "Open Keyflap: a human check is waiting." with
  `--apns-generic`), category `AAB_HANDOFF` with no actions, payload `aab: {v: 1, handoff:
  <id>}` and no `rid`, so an app without a handoff screen never takes it for a request.
- **Ending `done`** starts the session TTL clock first (decision 12; the save filter needs
  a live clock for a site with a TTL) and then saves the state (`AgentSessions.save
  ('full')`).
- **Audit:** `handoff.requested {handoffId, agentId, verifiedOrigin, provider}`,
  `handoff.denied`, `handoff.started`, `handoff.input_refused`, `handoff.ended {handoffId,
  agentId, verifiedOrigin, outcome, durationMs, inputs: {clicks, scrolls, drags, keys,
  texts}}`, `denied {reason: 'handoff_open'}`. Never text, keys, coordinates or frames
  (inv10 checks the field names and that no typed text, page text or cookie name appears).
- **"Keep me signed in on <site>" (decision 3).** For high-risk sign-ins (passkey
  `webauthn.get` or a fill whose rpId / item domain or origin is high-risk), when
  persistence is on and the site isn't kept already, the broker adds the broker-authored
  `display.keepSignedInSite` (the registrable domain of the verified origin). The phone
  card shows an unticked checkbox; ticked, the page sends `keepSignedIn: true` to
  `/api/challenge` and the statement the phone signs gains `keepSignedIn: {site}`
  (`buildStatement`; refused where it wasn't offered: `keep_not_offered`). The approvers
  accept the offer only on an `ask-strong` sign-in without a grant, for the origin's host or
  a parent domain. The core accepts the field only for exactly the offered site
  (`unexpected_keep` otherwise, before the signer) and records `PersistOptins.add(agentId,
  site, 'approval')` (audited `session.keep_set {via: 'approval'}`) only after the signer
  accepted that approval (with the first released secret or the signature), the same way
  as a grant. The signer checks the field's shape and refuses it on a grant use; its
  signature covers it, so an approval altered after the phone signed is refused (tested).
  No MCP tool takes it (schemas are strict). The native app can't offer it yet: the native
  state drops the offer, native statements never carry it, and the Swift statement parser
  refuses it as an unknown field (tested in `KeyflapApproverCore`, swift 6.2 container).
- **Known limits.**
  - The live view is JPEG screenshots at up to 4 per second: fine for a checkbox, slider or
    image grid, laggy for anything animated.
  - A page can move focus between the sensitive-field check and the insertion, and a
    home-made password widget (not an `<input type=password>` or one-time-code field) isn't
    recognized. What the owner typed is still scrubbed and kept out of saved state.
  - The picture is the website's, so it can draw anything (a fake "Approve"). The boundary is
    that no approval card for that agent exists while the handoff is open, the view is on
    its own page with broker-written labels, and a tap in the picture is only a click on the
    website.
  - Phase B's limit applies: the broker serves `/handoff` itself, so a compromised core
    could show other pixels; it still can't approve anything (approvals need a UV assertion
    over a statement, which the start assertion can never be).
  - Some providers (Turnstile and others) may refuse an automated browser even after a human
    passed the check; section 4 forbids disguising it. Safari may want a tap before Face ID
    (the Start button).
  - The iOS app has no live view (P4); its users open the web page.
  - Found while building the verify-aab `handoff` recipe (M4 behaviour): a password + TOTP
    fill approved with a phone passkey whose authenticator counts signatures was denied
    after the password. Fixed: see "One assertion, several fill fields" under Phone
    approval (M4).

## One approval for check + sign-in (sessions plan P3b)

- **Why.** On a real site (huggingface.co, 2026-10-13) the AWS WAF check sat in front of the login page,
  so P3 cost the owner two phone interactions: the handoff (Face ID start, solve, Done) and
  then the sign-in approval. Owner decision: one Face ID, at the start, never on Done.
- **Eligibility (`Broker.handoffSignInOffer`, trusted state only).** After the whole P3 gate
  passed: the verified origin from the frame URL; policy `ask` or `allow-for` for the agent
  (not `deny`, `ask-strong`); not high-risk (origin, registrable domain or rpId); a live
  intent; no approval pending; no broker sign-in on that site under the same intent (so a
  check after the password, fill outcome `challenge`, stays a plain handoff); exactly one
  credential: one password item for the registrable domain, else one passkey whose rpId fits
  the host. Anything else (two items, none, an error) is a plain P3 handoff, and
  `handoff.requested` records `signInSkipped: <reason>`. `browser_handoff` still takes only
  `{timeoutMs?}`.
- **The card.** `HandoffManager` sends no handoff push and calls
  `Broker.approveHandoffSignIn`, which re-derives everything (policy, eligibility, the same
  credential, a live intent) and asks the approver with the invariant 5 display fields plus
  the broker-authored `display.handoffSignIn: {withinMs}`. The phone renders "Human check,
  then sign in to <host>?" and "One sign-in within 7 minutes, without asking again.
  Approving opens a live view of the website on this phone." (`render.ts` / `app.js`, same
  wording). It arrives by the ordinary content-free approval push, which opens `/`. While it
  waits, the handoff has no link card on `/`, and `/handoff` shows "Starting the live view
  once you approve it on the approvals page…" and never runs its own start check
  (`/api/handoff/challenge|start` answer 409 `started_by_approval`; `HandoffPort.start`
  answers `approval_only`). The iOS app never sees such a request (native state,
  challenge and APNs skip it): it has no live view yet (P4). The terminal approver refuses it
  (`handoff_unsupported`); it can't arise there anyway (no handoff surface).
- **The statement.** Kind `fill` (clientDataHash = the fill scope) or `webauthn.get`
  (clientDataHash = SHA-256 of `"aab-handoff-signin-v1\n" + handoffId`, never a real
  clientData hash), plus `handoff: {id}` and `grant: {agentId, until, uses: 1}` with `until -
  issuedAt ≤ 7 min` (`HANDOFF_GRANT_MAX_MS`). `statementExtrasOk` requires `handoff` and
  `grant.uses: 1` together. `requestProblem` refuses a request whose `withinMs` differs from
  the grant, that also shows an allow-for window or the keep offer, is `ask-strong`, a
  registration, or lacks the handoff.
- **Only the approving phone, only after the signer.** For a combined request the approver
  offers `allowCredentials` = the device's own passkey only and refuses another passkey on
  `/api/decide`; the decision carries `deviceId`. The core requires a phone (WebAuthn)
  approval with a device, checks every statement field against what it asked (`handoff.id`,
  the single-use grant ≤ 7 min, no `strong` / `keepSignedIn`), then calls the signer's
  `accept_handoff_grant`. Only when that succeeds does the handoff get its controller
  (`handoff.started {deviceId, via: 'approval'}`) and the phone's live view opens. So the
  start is bound to the signer-accepted approval, never to anything the agent or the page
  supplied.
- **Signer (`accept_handoff_grant`, `drop_grant`).** The approval is verified like any other
  (signature, freshness, `issued_before_signer_start`, replay, the counter), must be UV (a
  phone or native key), must not be `strong` or high-risk (refused even when asked for:
  `grant_not_allowed`), names an existing credential (passkey with that rpId; native item on
  that domain with TOTP if the scope has it; or a source item), and the origin must be within
  the rpId. It is consumed by recording the grant (`singleUse`, `handoffId`); nothing is
  signed or released. Every operation path refuses a statement carrying `handoff`
  (`handoff_approval_not_an_operation`), and a grant use may not carry one. A single-use
  grant is spent by the first use's requestId (later fields of that fill pass; any other
  request gets `grant_used`); a use that fails the agent, origin or credential match doesn't
  spend it, one that fails later checks does (fail closed). `drop_grant` only narrows.
- **Core grant lifecycle (`GrantBook`).** Recorded unarmed with its handoff id; `arm` on
  `done`; `dropHandoff` on any other end (`cancelled`, `expired`, `left_site`,
  `page_closed`, `revoked`, `closed`), which also sends `drop_grant` (audited
  `grant.dropped {reason: 'handoff_<outcome>'}`, `grant.drop_failed` if the signer call
  fails). A handoff that ends while the card waits aborts the approval request (the phone
  card goes away; `denied {reason: 'handoff_ended'}`); an approval that lands after the end
  is dropped again. `find` (allow-for) never returns a single-use grant; `takeHandoff` takes
  an armed one out of the book for its one use, in `Broker.authorize`, after the policy
  (`ask` / `allow-for` as read now, never `ask-strong` or high-risk), handoff, credential and
  live-intent checks. Audited `grant.used {singleUse: true, handoffId}`. A refusal by the
  signer denies the request (`grant_refused`) and the next sign-in asks.
- **Invariant 6 and CLAUDE.md's policy rule.** The fill is authorized by the owner's own
  signed approval of exactly this sign-in (agent, origin, credential, one use, 7 minutes),
  recorded by the signer: the prompt isn't skipped, it happened at the start. The same
  limits as M5 grants hold (never `ask-strong` / high-risk, never without a live intent, no
  MCP input). Invariant 5: the card holds only the four fields plus broker text; the live
  view never coexists with an approval card for that agent (the card is decided before the
  view starts, and while the handoff is open every other credential operation of the agent
  is still denied `handoff_open`).
- **Residual (fail closed).** A drop that never reaches the signer (core crash, lost message,
  a core restart in service mode where the signer keeps running) leaves the signer's copy
  usable until its expiry, at most 7 minutes after the approval, once, for that agent,
  origin and credential. The core forgets it, so only a compromised core could present it,
  and only for what the owner approved. A signer restart drops it.
- **Known limits.** The grant is per exact origin: a site whose login form is on another
  origin than its check (`auth.example.com` after a check on `example.com`) asks again. A
  passkey grant use signs with UV = 0, like M5 grants. A page with both a password item and a
  passkey combines with the password. The handoff still ends 5 minutes after it opened, the
  approval time included.
- **Test RP.** `challengeAt: 'login-page'` puts the check in front of `/login`,
  `/password/login`, `/password/login-id` and `/password/login-pw` until `rp_clearance` is
  set; "I'm human" returns to that page (a hidden `next` from a fixed allowlist, else
  `/account`).

## Service mode (isolation plan S2–S4, Linux)

Design and owner decisions D1–D6: `ISOLATION_PLAN.md`. How to install and run it:
`docs/integrations/service-mode.md`. What was decided while building it:

- **How the core reaches the signer.** The signer is its own unit (`keyflap-signer.service`),
  so the core can't spawn it or hand it a key over stdin. `keyflap-signer.socket` creates
  `/run/keyflap-signer/signer.sock` as `keyflap-signer:keyflap-core 0660` inside `/run/keyflap-signer`
  (`root:keyflap-core 0750`, tmpfiles.d) and passes the listening fd to the signer; the core
  connects (`connectSigner`). The HMAC channel is unchanged; its key is a 32-byte random
  credential sealed at install and loaded into both units with `LoadCredentialEncrypted=`
  (systemd decrypts it into each unit's private credentials dir, so it's readable by the
  two service users and nobody else, not even through a shared file). If the connection
  drops, the core stops cleanly and exits 1 for systemd to restart it, rather than run
  without a signer. Dev mode keeps spawning exactly as before.
- **Signer configuration.** `main.ts --service --config /etc/keyflap/signer.json`: a root-owned
  file (refused if group/other-writable or owned by anyone but root/us), strict keys, no
  Ed25519 approver keys at all (D5: phone approvals only), plus the KEK and channel key from
  `$CREDENTIALS_DIRECTORY`. The signer never reads stdin in this mode.
- **Credential file layouts (2026-10-27, found on the first real install).** systemd hands a
  credential over in one of two layouts. On ramfs (no ACLs; systemd 255 in the isolation
  container) the file is owned by the service user, 0400. On tmpfs (Arch, systemd 262) it is
  `root:root 0440` with an ACL entry `user:<service>:r--`, and the group bits are the ACL
  mask. The old check (`mode & 0o077` must be 0) refused the second layout, so both
  services crash-looped on a real host. `credentialPrivate` (`signer/src/systemd.ts`) now
  takes group read only on a `root:root` file (only root can add ACL entries to one), and
  never other bits or group write. Node can't read ACLs, so it can't rule out a non-root
  member of group `root` (an admin-level setup anyway). Test: `signer/test/systemd.test.ts`
  (on stat values: root-owned files can't be made in a test). Gap: the isolation container
  still only exercises the ramfs layout.
- **Unlock (D1).** The installer generates a 32-byte KEK and seals it with `systemd-creds
  encrypt --with-key=auto` (TPM2 + host key when a TPM is present, else the host key). The
  signer passes its b64url form to `KeyStore.open` in place of the passphrase; `keystore.ts`
  is unchanged (scrypt over 256 random bits is wasted work, but harmless). The KEK is never
  regenerated by a re-install; `uninstall.sh --purge` deletes it with the store. Without a
  TPM, disk-theft protection is the disk encryption's job.
- **Admin sockets (D3): socket activation, not a peer-credential check.** Node has no
  `SO_PEERCRED`. `keyflap-core-admin.socket` and `keyflap-signer-admin.socket` are `root:root 0600`,
  created by PID 1 before any broker code runs, and the listening fds are passed in: only
  root can `connect()`, the services never own the paths, and there is no window where a
  socket exists with looser modes. Rejected: a `0700` directory owned by the service (works,
  but root + the service uid can connect, and the service could loosen its own directory)
  and a user group (the agent is in it, as the plan says). Measured: Node marks fds it
  inherits close-on-exec, so Chromium and `pass-cli` don't inherit the listeners (checked
  with `/proc/<pid>/fd` of a child). The wire is one JSON line each way with a dispatch table
  of named ops (`AdminOps`, `@aab/signer/admin-wire`), so later commands register an op.
  Requests are audited as `admin.request {op}`, written before the request runs, and
  `admin.result {op, ok}`, written after, never with params (see "Audit failures stop admin
  requests and pairing").
- **What goes where.** Core admin socket: `agent add|list|revoke`, `password
  add|list|remove`, `approver pair`, `status`, and M5's `policy set|list|remove`,
  `status.report`, `audit verify|tail` (the core runs M5's CLI functions on its own DB
  connection and returns their text: root must not open `broker.sqlite` itself, since
  SQLite would leave root-owned WAL files the core can't open). Signer admin socket:
  `approver list|remove|status`. Removing the last phone needs the signer's admin socket,
  which is what "offline admin signer" meant in dev mode: the core's channel still gets
  `last_approver_needs_admin`.
- **The CLI's mode** comes from the installed wrapper (`/usr/local/bin/keyflap` sets
  `KEYFLAP_MODE=service`); a checkout run (`pnpm keyflap`) is dev mode and unchanged. In service mode
  `--data-dir` and `keyflap daemon` are refused, and a permission error says to use sudo.
- **Intent socket.** `keyflap-core-intent.socket` makes `/run/keyflap/intent.sock` owned by the
  installing user, 0600: only that uid can connect, before the host token is even checked.
  The host token is generated per install, sealed for the core, and copied in plain to
  `/var/lib/keyflap/hook/host-token` (the user, 0600; the directory is recreated by root on
  each install so no user-made symlink is followed). The hook gets `--service` for these
  paths. Same-user agents can still read that copy: invariants 4/5 limit as before.
- **Pairing link (D5).** Service mode requires an approver origin (the core config parser
  and the installer refuse otherwise). The link is never logged: on Arch and others,
  `wheel`/`adm` members can read the whole journal, and that includes the user's agents.
  `sudo keyflap approver pair` starts pairing and prints it.
- **Installer (S4).** `build-bundle.sh` (as the user) stages sources and production
  `node_modules` (pnpm `--prod --offline --ignore-scripts`); `install.sh` (root) copies it
  into `/opt/keyflap/app` with fresh root-owned inodes (refusing symlinks that leave the app,
  clearing setuid bits), installs Node 22.23.3 from nodejs.org with a pinned SHA-256 (or
  `--node-dir`/`--node-tarball`), Chromium 1194 via Playwright's installer run as root from
  the root-owned copy (or `--browsers-dir`). `pass-cli` is no longer copied (security review
  H3, below): the signer runs it in place from a root-only path. Users via `systemd-sysusers`. Configs are written by
  `install-config.ts` through the services' own parsers. Units: `ProtectSystem=strict`,
  `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `PrivateDevices=yes`,
  `ProtectKernel*`, `ProtectProc=invisible`, `RestrictNamespaces=yes`, empty capability
  set, `UMask=0077`, `StateDirectory=` 0700; the signer adds `SystemCallFilter=@system-
  service`. No `MemoryDenyWriteExecute` (V8 JITs).
- **Proton Pass in service mode.** `pass-cli` runs as `keyflap-signer` with `HOME` and
  `PROTON_PASS_SESSION_DIR` under `/var/lib/keyflap/signer` and `PROTON_PASS_KEY_PROVIDER=fs`
  (no keyring or D-Bus in a system service); the owner logs that session in once with
  `sudo -u keyflap-signer env … pass-cli login`. Not tested against the real vault (tests never
  touch it).
- **Headed Chromium on a private display (`--xvfb`).** Real sites' bot walls refuse headless
  Chromium (2026-10-12 validation), and section 4 rules out disguising it. The core starts
  Xvfb as its own child with `-nolisten tcp -nolisten local` (no abstract socket: those
  ignore file permissions) and `-auth` with a fresh cookie in a `keyflap-core`-only file; the
  only listener is `/tmp/.X11-unix/X99` inside the unit's `PrivateTmp`. Readiness is polled
  on the socket (`xvfb-run`'s signal hangs in containers). Headed on Xvfb is the default
  since the release installer (below); `--headless` opts out.
- **Isolation tests.** `pnpm test:isolation` builds an Ubuntu 24.04 image with systemd,
  starts it (rootless podman with `--cap-add SYS_ADMIN`, or privileged docker in CI), runs
  the real `install.sh --xvfb`, starts the test RP and a "phone" (separate Chromium with a
  virtual authenticator), pairs it with `sudo keyflap approver pair`, adds an agent, then probes
  as `agentuser` (the installing user, an ordinary uid): see `ISOLATION_PLAN.md` "Tests".
  Each memory/ptrace denial has a control on the probe's own child, and the environ/fd reads
  are `PTRACE_MODE_READ` checks Yama doesn't touch, so the denials show the uid boundary
  rather than Yama. The suite was mutation-checked once by hand (admin socket 0666, signer
  state dir 0755, Xvfb without `-nolisten local`: each fails the expected test). Container
  gotcha: systemd mounts credentials in a child mount namespace, which only propagates when
  `/` is shared; the harness runs `mount --make-rshared /` after boot (real machines are
  already shared). About 40 s locally once the image exists.
- **Release tarballs (2026-10-22).** `build-bundle.sh --release OUT [--version V] [--arch
  x64|arm64|all]` writes `keyflap-V-linux-ARCH.tar.xz` plus `SHA256SUMS`. Each holds
  `keyflap-V-linux-ARCH/`: `install.sh`, `uninstall.sh`, units and configs,
  `runtime-pins.sh` (Node version and SHA-256s, Chromium revision, now shared by the
  installer and the build), `bundle/` (the same bundle as before) and the official
  `node-v22.23.3-linux-ARCH.tar.xz`, checked against the pin at build and again by
  `install.sh` (which now copies a tarball into its root-owned stage before checking and
  unpacking it, so the extracted dir can't swap it in between). The bundle is
  architecture-independent (no native modules), so arm64 is the same bundle with the
  arm64 Node tarball, built on x64. Chromium is **not** in the tarball: Playwright's
  installer fetches the host-arch build at install time (it would add about 150 MB per
  arch, and arm64 Chromium can't be fetched on an x64 builder). That download isn't
  checksum-pinned (as before); `--browsers-dir` avoids it. arm64 is built but has never
  been installed on arm64 hardware.
- **Reproducibility.** Sorted entries, owner 0:0 numeric, modes normalised
  (`u+rwX,go+rX,go-w`), hard links dereferenced, every mtime `SOURCE_DATE_EPOCH` (default:
  the commit time), GNU tar format, `xz -T1 -6`. pnpm's `.modules.yaml` (store path, prune
  time), `.pnpm-workspace-state-v1.json` (build paths, time) and `node_modules/.bin` shims
  (absolute build paths) are dropped from every bundle: nothing in `/opt/keyflap` runs pnpm
  or a shim (the installer calls Playwright's `cli.js` directly). Two builds of the same tree
  from different `TMPDIR`s gave identical SHA-256s. Limits: same pnpm (pinned by
  `packageManager`) and same xz version needed for identical `.xz` bytes; the tar stream
  inside only needs the same commit and lockfile. `REVISION` gets `-dirty` when the tree had
  uncommitted changes. The build also refuses a bundle whose Playwright expects another
  Chromium revision than the pin.
- **Release workflow and signing.** `.github/workflows/release.yml`, tags `v*` only: tag
  format check, `pnpm check`, clean-tree check, build both arches, attest, `gh release
  create --draft --verify-tag`. Actions pinned by commit SHA (checkout v7.0.1, pnpm
  action-setup v6.1.0, setup-node v7.1.0, attest v4.2.2); `permissions: {}` at the top,
  the job gets `contents: write`, `id-token: write`, `attestations: write` only; no
  dependency caches (a cache written by another run must not reach a signed build);
  `persist-credentials: false`; the tag reaches shell only through `env`. Signing is
  **GitHub artifact attestations** (`actions/attest`; `attest-build-provenance` v4 is
  now a wrapper around it): keyless Sigstore signing with the workflow's
  OIDC identity, a SLSA provenance predicate naming repo, workflow, ref and commit, logged
  in the public Rekor log; users check it with one command (`gh attestation verify FILE
  --repo … --signer-workflow …`), with no key to distribute or rotate. Chosen over
  `cosign sign-blob` because the verify step is simpler for users and binds the workflow
  file too, not just "some run in this repo". Caveat: attestations need a **public**
  repository (or GitHub Enterprise Cloud for private ones); while the repo is private the
  attest step fails and no draft release is created (fail closed). The workflow was linted
  with actionlint 1.7.12 (+ shellcheck 0.11) but has never run; the same build command was
  run locally. Pushing it needs a token with the `workflow` scope.
- **Installer changes (release).** `install.sh` finds `bundle/` and the Node tarball next to
  itself, so a release needs no `--bundle`/`--node-tarball`; `--bundle` still works. All
  machine checks run first and are reported together, before anything changes:
  architecture (and that a release tarball's `RELEASE` arch matches), systemd as PID 1 and
  ≥ 250, `systemd-creds`/`systemd-sysusers`/`systemd-tmpfiles`, `xz` and `tar` (unless
  `--node-dir`), `curl` only when Node has to be downloaded, Xvfb, `pass-cli`, a full
  `chromium-1194` in `--browsers-dir` when headed. Xvfb missing names the packages for
  Debian/Ubuntu (`xvfb`), Fedora (`xorg-x11-server-Xvfb`) and Arch (`xorg-server-xvfb`) and
  the `--headless` way out; no silent fallback. An existing `/opt/keyflap/browsers` is
  reused only if both the full Chromium and the headless shell are there. Upgrades print
  old and new version, note a headless-to-headed switch, and end with a different summary;
  fresh installs end with `sudo keyflap setup` (built elsewhere) and the manual
  `approver pair` / `agent add` path. **Upgrade bug fixed:** the installer stopped only
  the services, so an open phone page socket-activated `keyflap-approver` again
  mid-upgrade and the old process kept the approver port; restarting the socket then
  failed with "Address already in use". It now stops the sockets with the services.
  The isolation suite found this. The three scripts are now executable in git.
- **Isolation suite (release).** The setup builds a release tarball (host arch, version
  `0.0.0-isolation`, Node tarball cached in `~/.cache/keyflap/node`, downloaded once) and a
  source bundle; in the container it copies the tarball to a root-only dir, runs `sha256sum
  -c`, extracts as root, first runs `install.sh` with `/usr/bin/Xvfb` moved away (must fail
  in preflight with the package names and leave no `/opt/keyflap`, `/etc/keyflap` or users),
  then for real with no `--bundle`/`--node-*`/`--xvfb` (only `--browsers-dir`, to avoid the
  Chromium download). After pairing and `agent add` it re-runs `install.sh --bundle` over
  the live install and checks KEK and channel key unchanged, new service pids, agent and
  phone kept (`release-install.test.ts`). The inv1/5/7/9 tests then run against that
  upgraded machine. About 115 s locally (was about 60 s).
- **Known limits.** Root is out of scope. The hook's token copy is readable by the user's
  agents (invariants 4/5, as accepted). `sudo` can be aliased by a same-user agent (D3
  residual). The installer trusts the checkout it bundles. Chromium runs without its own
  sandbox (Playwright's default), contained by the unit and the uid. A signer restart drops
  M5 allow-for grants (they live in its memory). Upgrades re-issue the host token. (macOS was
  built on 2026-10-29, without a `.pkg`: see "Service mode on macOS (S5)".)

## Deviations in the sessions plan (P1, P2, P3)

- `FillTarget.perform` returns `{outcome, humanCheck?}` instead of a bare string, so the
  provider reaches the audit without extra state on the target.
- Test RP mode is spelled `text-only` (the plan says `textOnly`).
- `sessions.list` in service mode is a CLI admin op (`cli/src/service/admin-cli-ops.ts`,
  same pattern as `policy.list`); `sessions.clear` / `keep` / `unkeep` are core admin ops.
- `keyflap sessions clear --all` queues one row per active agent rather than a `*` row, so each
  agent's restore and the sweeper consume exactly their own.
- The saved plaintext also records `visited` (origins the agent's pages showed), used as
  known origins for the deny/TTL verdicts; the TTL rule applies at save as well as at
  restore (stricter than the plan, same outcome).
- Owner decision 3 changed after the plan: high-risk sites can be kept per site by owner
  opt-in (`keyflap sessions keep`), not "never".
- Isolation suite: the setup opts the agent in for `rp.localhost` (`sudo keyflap sessions
  keep`), since it installs with `--high-risk rp.localhost`; `pids()` is looked up live
  because the new test restarts `keyflap-core`.
- `pnpm lint` failed on main (the verify-aab skill scripts); `biome.json` now allows
  `console` in `.claude/skills/*/scripts`.
- P3: the agent surface goes from seven tools to eight (`browser_handoff`, schema
  `{timeoutMs?}` only); ARCHITECTURE 6.5 lists it with the `challenge` outcome and
  `humanCheck` (decision 11), section 3 says a handoff is not CAPTCHA solving, section 10
  lists the P2 tables. The tests that pin the list changed with it.
- P3: the handoff's host is the verified origin's host name without the port (the
  notification says "Human check on rp.localhost"); the TTL clock and the audit keep the
  full origin.
- P3: the start challenge is for the device's own passkey only (`allowCredentials` = the
  passkey it paired with, and the assertion must come from it), stricter than "the
  signer's trusted approver keys".
- P3: endpoints beyond the plan's frame and input: `GET /api/handoff/state` (broker fields
  plus `started` / `mine`), `POST /api/handoff/{challenge,start,finish}`. `HandoffView`
  also carries `openedAt` / `expiresAt` (broker-written).
- P3: "a paired device exists" counts paired phone browsers only; with only the iOS app
  paired (no live view until P4) `browser_handoff` answers `unsupported/not_available`.
  The iOS app still gets the APNs alert when a phone browser is paired too.
- P3: the rate limits check the push window before the 30 s cool-down (both deny the same
  way).
- P3: an outcome a `pending` call missed is handed to the next `browser_handoff` call
  within 60 s, so "re-call on pending" never opens a second handoff for a finished one.
- P3: the "Keep me signed in" opt-in is recorded when the signer accepts the approval
  (first secret released or signature made), not when the site later shows a signed-in
  page; it is the owner's signed decision either way.
- P3b: new signer ops `accept_handoff_grant` and `drop_grant`; new statement fields
  `handoff: {id}` and `grant.uses: 1` (only together); `ApprovalRequest.display.handoffSignIn`,
  `binding.handoff`, `binding.grant.uses`; `ApprovalDecision.deviceId`;
  `HandoffView.withSignIn`; `HandoffStartResult` `approval_only`; `/api/handoff/state` gains
  `withSignIn`. ARCHITECTURE is unchanged (section 5 untouched).
- P3b: a handoff whose sign-in was already done under the same intent stays plain (the
  broker remembers, in memory, the intent of its last sign-in per agent and site), so a
  check after the password never asks twice. After a daemon restart that memory is empty,
  so such a check would be combined (one approval instead of the Face ID start: no extra
  interaction).
- P3b: `handoff.requested` gains `withSignIn: true` or `signInSkipped: <reason>`;
  `handoff.started` gains `via: 'approval'` for a combined handoff.
- P3b: the approval timeout (90 s) ends a combined handoff `expired`; a denial ends it
  `cancelled`.
- P3b: the existing inv5 handoff test sets `ask-strong` for `rp.localhost` to keep testing the
  plain path (its registered passkey would otherwise make the handoff combined); the
  combined card has its own inv5 test.

## Naming: Replay (2026-10-22)

Before the first public release the user-facing name became **Replay** everywhere (owner
decision). Renamed:

- The command `aab` → `replay` (bin, `pnpm replay`, usage and error prefixes, `replay hook
  claude-code`, `/usr/local/bin/replay` and the installed wrapper `replay-wrapper.sh`).
- Product strings "agent-auth-broker" → "Replay"/`replay`: the MCP server name and the
  `.mcp.json` server key `agent add` prints, the terminal approval banner, the phone
  passkey's RP display name ("Replay approver"), the approver page title and manifest name,
  the web push notification tags (`replay-approval`, `replay-handoff`; local to the service
  worker).
- Environment variables `AAB_*` → `REPLAY_*` (`REPLAY_PASSPHRASE`, `REPLAY_AGENT_TOKEN`,
  `REPLAY_DEV_PASSPHRASE`, `REPLAY_MODE`, the test-only `REPLAY_ISOLATION_*`).
  `AAB_PASSPHRASE` is still read when `REPLAY_PASSPHRASE` is unset, with a deprecation line
  on stderr, and is removed from the environment like the new name. No other fallback.
- Dev-mode data dir default `~/.aab` → `~/.replay`. If `~/.replay` doesn't exist and `~/.aab`
  does, the CLI (and the hook, so both agree) uses `~/.aab`; admin commands print one stderr
  line saying how to move it (`mv ~/.aab ~/.replay`, and change `~/.aab` to `~/.replay` in the
  Claude Code deny rules at the same time, which otherwise would stop protecting it). The
  hook prints nothing. `agent add` omits `--data-dir` from the hook command whenever the dir
  is the resolved default, so the hook follows the move. An explicit `--data-dir` is used as
  given, without the notice. Test: `packages/cli/test/data-dir.test.ts` (temp HOME).
- Service mode: users and groups `replay-core`/`replay-signer`/`replay-web`, `/opt/replay`,
  `/etc/replay`, `/var/lib/replay`, `/run/replay{,-signer,-approver}`, units
  `replay-*.service`/`.socket`, `/etc/{sysusers,tmpfiles}.d/replay.conf`. No install existed,
  so there is no migration; an old `aab` install would have to be uninstalled first.
- Docs, CLAUDE.md and the verify skill's commands and paths (the skill keeps its directory
  and `name: verify-aab`, and its own `/tmp/aabv-*` and `~/.local/state/verify/aab` paths).

Deliberately not renamed:

- **Protocol and cryptographic domain-separation tags**: `aab-approval-v1`,
  `aab-native-approval-v1`, `aab-fill-v1`, `aab-handoff-start-v1`, `aab-handoff-signin-v1`,
  `aab-approver-add-v1`, `aab-native-approver-add-v1`, `aab-native-pair-v1` (signed or
  hashed statements and descriptors, in the signer, the approver page's own check and the iOS
  core), `aab-keystore-v1` (key-store AES-GCM AAD) and `aab-browser-state-v1` (saved-state
  AAD). Changing any of them breaks existing signatures, pairings, the encrypted key store
  and saved sessions, and the cross-language iOS vectors (`ios/ReplayApproverCore/Fixtures`).
- **Wire and credential formats with existing state**: the agent token prefix `aab_agent_`
  (tokens are stored as hashes of the whole token and validated by the prefix, so existing
  agents would stop working), the phone's device cookie `__Host-aab_device` (paired phones
  would be signed out), and the APNs payload the iOS app parses (key `aab`, categories and
  actions `AAB_APPROVAL`/`AAB_HANDOFF`/`AAB_APPROVE`/`AAB_DENY`, thread-ids `aab-approvals`/
  `aab-handoffs`).
- **Internal names nobody sees**: workspace packages `@aab/*`, directory names, the page
  binding `__aabWebAuthn`, test temp-dir prefixes such as `aabc-`.
- **History**: the plan docs (`docs/*_PLAN.md`) and git history keep `aab`.

## Naming: Keyflap (2026-10-22)

Later the same day the product was renamed again, **Replay → Keyflap** (owner decision:
"Replay" collides with Replay.io, which makes AI coding-agent tooling, and with the REPLAY
fashion trademarks; the owner holds keyflap.com). The split-flap brand is unchanged apart from
the name and the logo letter. The section above stays as the record of the first rename; what
it lists under `replay` now reads `keyflap`:

- The command `replay` → `keyflap` (bin, `pnpm keyflap`, usage and error prefixes, the
  hooks `keyflap hook claude-code|hermes|codex`, `/usr/local/bin/keyflap`,
  `keyflap-wrapper.sh`), and the root package name.
- Environment variables `REPLAY_*` → `KEYFLAP_*` (`KEYFLAP_PASSPHRASE`, `KEYFLAP_AGENT_TOKEN`,
  `KEYFLAP_DEV_PASSPHRASE`, `KEYFLAP_MODE`, `KEYFLAP_SETUP_PAIRING_TIMEOUT_MS`, the test-only
  `KEYFLAP_ISOLATION_*`, `KEYFLAP_TEST_*`, `KEYFLAP_DEMO_MCP_PORT`). `REPLAY_*` is **not** read:
  no release shipped under that name. The deprecated `AAB_PASSPHRASE` fallback and the `~/.aab`
  data-dir fallback from the first rename are kept as they were, now pointing at the new names.
- Dev-mode data dir `~/.replay` → `~/.keyflap`. There is no fallback to `~/.replay`: anyone
  with dev data there moves it by hand with the daemon stopped (`mv ~/.replay ~/.keyflap`) and
  changes `~/.replay` to `~/.keyflap` in their agent sandbox and deny rules (Claude Code
  `permissions.deny`, the Codex `keyflap-protected` profile), or those rules stop protecting it.
- Product strings: the MCP server name and config key (`keyflap`), the terminal header
  (`KEYFLAP · approval requested`, a blue **K** tile), the phone passkey's RP display name
  ("Keyflap approver"), the approver page title and manifest ("Keyflap approvals"), web push
  tags (`keyflap-approval`, `keyflap-handoff`), the Proton Pass reason strings, the APNs alert
  text, the Hermes plugin (`keyflap-intent`), the Codex profile (`keyflap-protected`).
- Service mode: users and groups `keyflap-core`/`keyflap-signer`/`keyflap-web`, `/opt/keyflap`,
  `/etc/keyflap`, `/var/lib/keyflap`, `/run/keyflap{,-signer,-approver}`, units
  `keyflap-*.service`/`.socket`, `/etc/{sysusers,tmpfiles}.d/keyflap.conf`, release tarballs
  `keyflap-<version>-linux-<arch>.tar.xz`, the demo image `keyflap-demo`. No install exists,
  so there is no migration.
- iOS (parked): `KeyflapApprover`, `KeyflapApproverCore`, their directories and entitlements.
- Docs, CLAUDE.md, the verify skill's commands (the skill keeps `name: verify-aab`).

Deliberately not renamed:

- Everything the first rename kept: the `aab-…-v1` domain-separation tags, `aab_agent_`,
  `__Host-aab_device`, the APNs payload keys, `@aab/*`, `__aabWebAuthn`, temp-dir prefixes.
  None of the tags ever said "replay", so no signature, pairing, key store or saved session
  changes.
- **"replay" as security vocabulary**: `approval_replayed`, "no replay across restarts",
  replayed frames and approvals in tests and docs. That is the attack, not the product.
- The brand repo is now `keyflap-site` (`../keyflap-site`, renamed from `replay-site`); its
  `scripts/sync-app-assets.sh` refreshed the approver page's logo and icons to the K tile.
- **History**: the plan docs (`docs/*_PLAN.md`), the section above, and git history.

## License: Apache-2.0, no contributor agreement (2026-10-22)

Before the first public release the license briefly changed to AGPL-3.0-only with a
contributor license agreement, then went back to **Apache-2.0** (owner decision). Nothing
was ever released under the AGPL. Reasons: wide use matters more than restricting
commercial users, many companies can't use AGPL code at all, and Apache-2.0 takes
contributions under the same license (section 5) with no agreement to sign.

- `LICENSE` is the Apache License 2.0 text, unmodified. The root and every
  `packages/*/package.json` say `"license": "Apache-2.0"`. No per-file headers.
- No CLA and no trademark policy: "Keyflap" is a crowded name in software, and Apache-2.0
  section 6 already grants no rights to the name or logo.
- Liability: the license's warranty disclaimer and limitation of liability (sections 7 and
  8), plus a use-at-your-own-risk notice at the top of the README.

## Flow decisions

- **Several broker credentials for one rpId → deny (`ambiguous_credential`).** Choosing
  needs an account name, which is site-supplied text and can't appear in the prompt
  (invariant 5). Revisit with a broker-side account label the user sets.
- `excludeCredentials` matching one of ours returns `InvalidStateError` without a prompt.
  Real authenticators ask for user presence first; skipping it lets that rpId's page learn
  the broker holds one of the IDs *it* listed. Low risk; noted.
- The verified origin is read from `frame.url()` when the binding fires. Playwright tracks
  it from browser navigation events. A request racing a cross-origin navigation is
  theoretical (the old document's context is destroyed); not specifically tested. Since the
  review, the document's security origin must equal it too ("Security review: origin and
  policy fixes").
- Requests from any non-top-level frame are denied, including same-origin iframes.
- Allowed origins: `https:`, or `http:` on `localhost` / `*.localhost`. No IP hosts, no
  non-canonical hosts (trailing dot, upper case, empty labels).
- rpIds are never public suffixes, even when the rpId equals the host (`com`, `co.uk`,
  `github.io`). That's stricter than HTML's "is a registrable domain suffix of or is equal
  to", which accepts the equal case. Plain `localhost` is the only exception.
- The approval timeout (default 90 s) denies; the terminal approver also times out (60 s).

## Testing notes

- E2E uses `rp.localhost`, `evil.localhost`, `login.rp.localhost` on one local server;
  hostile pages are served with `page.route()` at a chosen origin.
- The test RP's own passkey test uses Chromium's CDP virtual authenticator. That's the
  only place it appears: it holds keys in the browser, so it must never be used for real
  credentials (section 6.3). It's there to separate RP bugs from shim bugs.
- The invariant checks were mutation-tested once by hand (disabling the rpId check, the
  top-frame check, and the signer's rpId check each makes tests fail). The M2 invariant
  tests were mutation-tested the same way (e.g. no-intent passes, expiry ignored, rp.name in
  the display, an extra `browser_evaluate` tool, `--remote-debugging-port`, observer
  receiving arguments, audit trigger dropped).
- Invariant 7's OS-level checks read `/proc` on Linux: the managed
  Chromium's command line, its fds 3/4 (Node creates `pipe` stdio as unnamed, connected
  unix socketpairs), its user-data dir (no `DevToolsActivePort`), and listening TCP sockets
  of its process tree. A Chromium launched with `--remote-debugging-port=0` is the control.
  On macOS the same checks except fds 3/4 run through `ps` and `lsof` (see "macOS: dev mode
  and tests").
- Playwright's `route.fetch()` resolves hosts in Node, which doesn't resolve `*.localhost`
  here; tap RP traffic with `context.on('request' | 'response')` instead.

## Demo container (2026-10-22)

`demo/` is a try-it-first container (dev mode, terminal approver, test RP, Chromium). No
package code changed for it; the decisions:

- **Test site only, without policy.** Section 9 policy can't express "deny everything
  except X": the strictest matching rule wins, there are no wildcards, and a pattern needs a
  registrable domain (bare `localhost` has none). So the demo closes the browser's egress
  instead: the image sets `http_proxy`/`https_proxy`/`all_proxy` to a dead port, which
  Chromium on Linux honours, and Chromium always goes direct to loopback (`localhost`,
  `*.localhost`). Non-test sites fail with `ERR_PROXY_CONNECTION_FAILED`. The only stored
  credentials are the test RP's public fixtures.
- **MCP through a port forward.** The MCP server still binds to loopback only, with its Host
  and Origin checks unchanged. `demo/mcp-relay.ts` relays raw TCP from the container's
  non-loopback interfaces to `127.0.0.1:8765`, without touching requests, so a client on the
  host (`-p 127.0.0.1:8765:8765`, same port both sides) passes the checks as a local
  client would. Rootless podman with pasta splices loopback directly; docker and podman bridge
  networks need the relay.
- **Intent.** `say` (demo/say.ts) runs the Claude Code hook code with the user's words as
  its input, over the existing intent socket and host token inside the container; or
  `say --claude-code-hook` as a host-side Claude Code hook through `podman exec -i`. No new
  path from the agent. The demo is documented as not a security boundary: an agent with a
  shell as the user can run `podman exec` itself.

## Brand and the phone approver's look (2026-10-22)

The owner made the website's design language the product's: the brand (tokens, faces,
logo, icons, rules) is the source of truth for everything a person sees. It lives in the
private `keyflap-site` repo, apart from the app (see "Brand and website: a separate repo").
The phone approver (`packages/approver/src/page/`) now uses it. Decisions:

- **CSP gains `font-src 'self'`** (`page-files.ts`). The page loads three brand fonts from
  its own origin. Same-origin font files can't run code; `default-src 'none'` still covers
  everything else, and `script-src`/`connect-src` are unchanged.
- **New static files** under `/brand/` (fonts, mark, icons), listed in `STATIC` like every
  other page file and read once at start from the install. They are copies of the brand's files
  (`keyflap-site/scripts/sync-app-assets.sh` refreshes them); `test/brand-assets.test.ts`
  checks they're served only as fonts or images.
- **What the card shows is unchanged** (invariant 5): same fields, same order, same
  template. Only colour, type and control shapes changed. Deny is an outlined button, not
  red (the brand has no red); errors are said in words on an inverted paper strip. The
  buttons became round icons on 2026-10-29: see "Approval cards are swipe cards".
- **The live view kept an amber header and dashed frame**, then a deliberate exception to
  the one-blue palette so it could never be mistaken for an approval screen. Superseded on
  2026-10-27: see "Live view restyle: steel, not amber".
- `test-rp` stays unbranded on purpose: it stands in for a third-party site.

## Live view restyle: steel, not amber (2026-10-27)

The owner saw the amber live view on their iPhone during a service-mode install test and
asked for it in the Keyflap scheme. The amber existed for one reason: a person must never
mistake the live view for an approval screen. That property is kept inside the brand, which
was extended first (`keyflap-site` `brand/README.md`, "Live view (not an approval)";
`DESIGN.md`, "The Live Steel Rule"). Decisions:

- **No blue anywhere on `/handoff`.** On the phone blue means approve (the Approve button,
  the K tile, blue-ruled guidance). The live view is ink, steel and paper only, including
  focus rings and selection.
- **Different framing, in the brand's own vocabulary for "live".** A steel header band with
  a paper `LIVE` flap tag (the approvals header is ink with a blue K tile), and the picture
  inside the steel bezel the brand already reserves for anything live. The dashed frame is
  gone.
- **Controls:** outlined steel; Start and Done are paper buttons on ink (ink on paper).
  There is still no approve control and no control styled like one.
- **Wording kept, one line added.** Every warning stays ("This is not an approval screen.
  Nothing here can approve a sign-in.", "Nothing in this picture is from the broker…",
  "Don't type passwords here."); the header now leads with "You are controlling the site."
  The page title and `h1` are unchanged.
- **The approvals page's link card** to a waiting live view drops its amber rule for a
  steel one with the same paper `LIVE` tag; its text is unchanged.
- **Both schemes.** Dark first (ink ground); light is a paper ground with ink text. The
  steel band and bezel are the same in both. No brand assets changed, so
  `sync-app-assets.sh` had nothing to copy.

## Live view zoom and pan (2026-10-27)

The owner found the check hard to see on their iPhone: the live view draws a 1280×720 page
about 340 CSS px wide. It now zooms and pans. Decisions:

- **Gestures: pinch zooms, two fingers pan, one finger is always the site's.** Some checks
  need a one-finger drag (sliders, puzzle pieces), so a one-finger drag can't become a pan;
  this is the iOS photo convention. A two-finger gesture lasts until every finger is up, so
  the finger lifted last is never a tap; once a second finger lands, the first finger's
  touch is dropped. **+**, **−** and **Fit** buttons zoom on the centre for one-handed use.
  Zoom is 1× to 4×; the view never shows past the page's edge.
- **Every tap goes through the view.** `page/handoff-zoom.js` (pure functions, a classic
  script like `approval-check.js`) maps a point in the zoom window to a fraction of the page
  through the same transform the picture is drawn with, clamped to 0..1, so input stays
  inside the page and the server's input shape is unchanged. `test/handoff-zoom.test.ts`
  checks the round trip at every zoom and pan, pinch, + / −, and the clamping.
- **Sharper zoomed frames: a clipped, higher-quality screenshot of the region on screen.**
  While zoomed the page asks `/api/handoff/frame?…&clip=x,y,w,h` (fractions, 4 decimals,
  inside the page, at least 5% each way; anything else is 400) for the visible region plus
  a 5% margin, and lays it over the same place on the page; the whole page still comes every
  fourth frame so panning shows fresh edges. The core captures just that rectangle with
  `page.screenshot({clip})` at JPEG quality 85 (the whole page stays at 60), clamped to the
  viewport, under the same gates as a frame: the controlling device only, only while the
  handoff is open and the page is on its site, cached 250 ms, dropped after each input.
  Still no CDP session (invariant 7) and nothing new reaches the agent: frames go only to
  the phone, and the audit gets no coordinates.
- **Not done: a higher device scale factor.** The managed browser renders at 1×, so a
  region has no more pixels than the page has; on a 3× iPhone a 3× zoom upscales. Raising
  the agent contexts' `deviceScaleFactor` would make every frame and every page render
  heavier and change the browser the sites see, for a live view used a few times. Quality
  85 on a small region removes the JPEG smear that made small text hard to read, which was
  the visible problem.

## Audit failures stop admin requests and pairing (2026-10-29)

The owner's rule, in his word, is "fail closed" (`DECISIONS.md`, "A missing audit row stops
owner actions"). If the audit row for an admin request to the core, or for pairing a phone, cannot
be written, the action is refused. Before this change both were best effort: the core
swallowed a failed `admin.request` append, and the setup wizard swallowed a failed append of
the approver's pairing events.

**The row goes first.** A row written after the action cannot stop it. Refusing only the
answer would tell the owner "no" about a request that already ran. So the row is the
write-ahead record: it is appended before the action, and a throw from the append is the refusal.

- **Admin requests.** `AuditedAdminOps` (`cli/src/service/audited-ops.ts`) extends `AdminOps` and
  appends `admin.request {op}` before it calls the handler. If the append throws, the request
  fails with the fixed message `refused: the audit log could not record this request`. The
  message carries no database text, so a full disk or a path stays out of the owner's terminal
  and out of the reply. The rule covers every op that reaches dispatch, `status` and unknown
  ops included. While the audit log is unwritable, `keyflap status`, `agent list` and every
  other command over the core's admin socket are refused too. The signer's admin socket is a
  separate server and is not affected. Nothing in `signer/` changed: the check sits in a
  subclass in `cli`, and `startAdminServer`'s `onRequest` hook (which runs after the handler)
  is no longer used by the core.
- **The outcome is a second row.** The first version of this change dropped the old `ok` flag,
  because the request row exists before the outcome does (the PR 45 review caught that). The
  subclass now also appends `admin.result {op, ok}` after the handler, best effort: the action
  has already happened, so a failed append cannot undo it and is swallowed. A request refused
  because its own row could not be written gets no result row, so a result never appears
  without its request. A request line that does not parse as JSON, or has no valid op, is
  answered `malformed request` and gets no row at all. It never reaches an op and changes
  nothing.
- **Pairing.** `PhoneApprover` has a required option, `auditBefore`. Right before it asks the
  signer to register a key, it calls `auditBefore('approver.pairing_accepted', {origin,
  credentialId, first, kind})`. That covers the three ways a key gets in: the first web
  phone, the first iOS app key, and any further phone after an existing phone approved it.
  If the call throws, the first phone gets `409 pairing_refused` and a further phone's
  pairing ends as failed. The signer never sees the key, and the approver stores no device.
  The option is required so a new construction site cannot forget it. The row holds the
  approver origin, the public credential id, `first` and `kind`, and no code, challenge,
  signature or key material.
- **`ApproverDeps.auditBefore`.** The `audit` the daemon hands to `makeApprover` does nothing
  until the broker exists, because the approver is built first. A write-ahead row must not
  vanish that way, so `auditBefore` throws until the audit log is open. Dev `keyflap daemon`
  and the service core pass it on to the approver. The setup wizard has no daemon, so it
  passes a function over its own `AuditLog` handle.
- **What stays best effort.** The approver's `onEvent` rows (`approver.pairing_started`,
  `approver.paired`, `approver.pairing_failed`, `approver.unpaired`,
  `approver.device_untrusted`) are markers that follow an action, and
  `approver.pairing_accepted` already recorded the pairing. The wizard still swallows a failed
  marker. The service core and dev `keyflap daemon` still let it throw. If the log breaks
  between `approver.pairing_accepted` and `approver.paired` there, the phone stays paired
  and recorded, the phone's page shows an error, and the owner pairs it again. The wizard's
  `setup.pairing` row was already written before the link opens (it was never swallowed), and
  a test now pins that.
- **Phone wording.** A refused pairing shows the page's existing `pairing_refused` text ("the
  broker refused. Remove old phones…"), which does not name the audit log. A separate code
  and copy would need the brand pass for page text, so it is not part of this change.

Tests: `cli/test/service-mode.e2e.test.ts` ("invariant 10: an admin request is refused…"),
`approver/test/native-api.test.ts` ("invariant 10: a key is registered only after its pairing
row is written"), `cli/test/inv10-setup-pairing-audit.test.ts` (the wizard's backend against
a real signer), `core/test/inv6-phone-approval.e2e.test.ts` (a web phone with a virtual
authenticator) and `core/test/inv10-approver-audit.e2e.test.ts` (`auditBefore` throws until the
audit log is open).

## Brand in the terminal (2026-10-22)

Terminal output follows the brand too: the dev-mode `TerminalApprover` prompt,
`keyflap setup`, `keyflap doctor`, `keyflap status` / `audit verify`, and the daemon's startup
lines. One module, `packages/approver/src/term-style.ts` (exported from `@aab/approver`),
does the translation; the CLI imports it. Decisions:

- **Colours.** OK / approved and section titles: blue text (`#7b91ff` on a dark terminal,
  `#1f3bd1` on a light one, by `COLORFGBG`; dark is the default, as in the brand). Denied /
  failed / broken: an inverted paper flap (reverse video, bold), always with the word. No
  red anywhere. Quiet text dim, section titles bold uppercase, a blue K tile + `KEYFLAP` header.
- **When.** 24-bit only when `COLORTERM` is `truecolor`/`24bit`, else the 16-colour palette.
  No colour when `NO_COLOR` is set (non-empty), `TERM=dumb`, or the stream isn't a TTY;
  `FORCE_COLOR` (0–3) overrides the TTY check but never `NO_COLOR`. Each surface decides from
  the stream it writes to (the approver from its output, the daemon from stderr).
- **Plain output is unchanged** apart from uppercase titles: the prompt header
  (`KEYFLAP · approval requested`), `status`'s `LAST AUDIT ENTRIES`, and setup's step titles.
- **Invariant 5.** `renderPrompt(req, style)` styles the same lines in the same order; every
  displayed field is cleaned (control and bidi characters replaced) before any escape is
  added, so no field can carry or close one. `test/term-style.test.ts` checks that the
  coloured prompt minus its escapes equals the plain prompt line for line (bar the
  broker-authored header line). After an answer the approver echoes `approved` / `DENIED`,
  broker-authored text, written only if the prompt is still open.
- **Setup marks** (`  ✓` / `  ✗` at the start of a line) are coloured in one place,
  `styleMarks` in `cli/src/format.ts`, applied to setup's output stream, rather than at
  each of the step functions' call sites.
- **Not styled:** the Claude Code / Codex / Hermes hooks (never write to stdout) and the MCP
  headersHelper (stdout is JSON). `sudo keyflap status` in service mode stays plain: its text
  is produced by `keyflap-core` and relayed over the admin socket, which can't see the
  owner's terminal.

## Brand and website: a separate repo (2026-10-22)

The brand source (`brand/`), the website (`site/`), the design notes (`DESIGN.md`,
`PRODUCT.md`, `.impeccable/`) and the Pages workflow moved to the private `keyflap-site`
repo, so they don't ship with the app. The app keeps only what it serves: the approver
page's copies of the fonts, mark and icons (`packages/approver/src/page/brand/`) and the
colours in `term-style.ts`. The byte-for-byte check against `brand/` moved with it
(`scripts/sync-app-assets.sh --check`); here the test checks only that those files are
served as fonts or images.

## Security review: signer fixes (2026-10-22)

From the pre-launch review of c8297c3 (findings M1 and L6, plus signer-side Info items).

### Public suffix list in the signer (M1)

- **Problem.** The signer only required an external item's rpId to contain a dot. A
  compromised core could approve `https://www.bbc.co.uk` with rpId `co.uk` and the Barclays
  vault item: the host check passed, the high-risk tier and the grant rules ran on `co.uk`
  (not high-risk), and the item's `www.barclays.co.uk` host is "within" `co.uk`. The bank's
  password came out under an approval of a plain site, with up to a 12 h grant.
- **Decision.** The signer has its own PSL: `packages/signer/src/psl/public_suffix_list.dat`,
  the upstream file verbatim (ICANN and private sections, as the core's tldts with
  `allowPrivateDomains`), read by `src/psl.ts` (built-ins only; the standard algorithm with
  wildcard and exception rules, IDN rules converted with `domainToASCII`). It is a data
  file, not an npm dependency, so the signer's zero-dependency rule holds. The file is
  MPL-2.0 (file-level, unmodified), which is compatible with shipping it in this Apache-2.0
  repo. Refresh with `packages/signer/scripts/update-psl.sh` (downloads from
  publicsuffix.org only, checks the new file with the signer's parser before replacing).
  It lives under `src/` so the service-mode bundle (which copies `packages/*/src`) carries it.
- **Fail closed.** The parser refuses a file without the four section markers, with a bad
  rule, or with fewer than 5000 rules. `SignerHandler` loads it in its constructor, so a
  signer without a usable list doesn't start. Lookups return null for anything that isn't
  a lower-case ASCII host name. The signer's snapshot and the core's tldts snapshot can
  differ for a newly listed suffix; any disagreement is a refusal, never a release.
- **Rules.** Every rpId the signer acts on passes the core's rule with the signer's PSL
  (`rpIdAllowedForHost`: the host or a parent of it, at or below the host's registrable
  domain, never a public suffix; plain `localhost` only for itself): passkey create and
  sign, native item release, P3b handoff grants, phone approver pairing. Native items are
  stored only for an exact registrable domain (`bad_domain`). External items: the rpId must
  be exactly the origin's registrable domain (what source sync picks), the live item must
  have a host of that registrable domain, and **every** live host of the item goes through
  the high-risk and grant checks, since releasing the item releases it for all of them
  (an item for both a plain site and a bank needs UV, at most 60 s, and no grant). The
  grant of an external fill is now recorded only after those checks pass.
- **High-risk.** `isHighRisk` treats a host with no registrable domain (a public suffix
  such as `co.uk` or `github.io`, a malformed name, or the list unavailable) as high-risk;
  plain `localhost` is the exception. That is the same function the core and CLI use, so
  they get the stricter rule too. Entries still match a host and its subdomains; an entry
  below a registrable domain (`bank.example.com`) still covers only itself.
- **Not changed here.** The phone page's own statement check (`approval-check.js`) still has
  only a label-boundary rpId test and doesn't show the rpId when it differs from the host;
  the signer now refuses such statements regardless.
- Tests: `test/inv3-public-suffix.test.ts` (the review's a04 case and its variants),
  `test/psl.test.ts` (snapshot parses, algorithm cases, damaged files refused).

### Key store scrypt parameters (L6)

- **Problem.** `flush()` wrote the current `SCRYPT` constants into the file header while
  the in-memory key had been derived with the file's own parameters. A store with other
  parameters became unreadable after its first write, and header values weren't
  bounds-checked (a damaged header could ask scrypt for gigabytes).
- **Decision.** The instance keeps the parameters its key came from and every write records
  exactly those. Opening a store with non-current parameters migrates it: fresh salt, key
  from the current parameters, the new file written aside (`<path>.migrate`, 0600), read
  back and decrypted with a freshly derived key and compared with the contents, then
  renamed over the old one. Any failure removes the side file and keeps the old file and
  parameters (the store stays usable). Header checks before derivation: scrypt only; N a
  power of two in 2^10..2^20; r 1..32; p 1..16; memory at most 256 MiB; salt 16..64 bytes;
  IV 12 and tag 16 bytes.
- **Existing stores.** `SCRYPT` has been `{N: 2^15, r: 8, p: 1}` since M0, so no store
  written by Keyflap has mismatched parameters and none was bricked; the migration covers
  stores from other writers and any future parameter change. Tests: `test/keystore.test.ts`
  ("key store: scrypt parameters (L6)").

### Other signer items from the review

- The built-in high-risk list gained regional sign-in domains and large regional banks
  (`amazon.co.uk`, `santander.co.uk`, `anz.com.au`, `ing.nl`, …). It stays incomplete by
  nature; owners add their own with `highRiskDomains`.
- ARCHITECTURE 6.4 now says what the signer binds: `intentHash` is only required to be
  present (it is the core's hash of a record the core holds; APPROVER_INTEGRITY_PLAN).
- Test gaps closed: `not_yet_valid` for signed approvals and for grant uses; the channel
  tamper and oversized-frame tests now assert that no frame came back.
- Left for their owners: `LimitCORE=0` and dropping AF_INET/AF_INET6 from the signer unit
  when no password source is configured (install units); a grant's `agentId` is still
  only as good as the core's claim (the signer can't authenticate agents). ~~Signer
  refusals are audited by the core as `internal_error`.~~ Now `signer:<code>`
  ("Security review: origin and policy fixes").

## Runtime pins: Playwright 1.64.1, patched Node (2026-10-22)

Before going public, the browser and runtime were brought up to date. The managed browser
visits arbitrary sites, so a Chromium months behind on security fixes is a real exposure.

- **Playwright 1.56.1 → 1.64.1, Chromium 1194 → 1248 (Chrome 156.0.8078.4).** The old note
  said the pin "matches the cloud image's Chromium". That came from the Claude Code cloud
  session image, which preinstalls a Chromium under `PLAYWRIGHT_BROWSERS_PATH`, and
  `.claude/hooks/session-start.sh` skipped the download whenever any Chromium was present.
  That was a convenience for development sessions, not a product constraint, and it is not a
  reason to ship an old browser. The hook now always runs `playwright install chromium`,
  which does nothing when the exact revision is present. The revision is also pinned in
  `runtime-pins.sh` (`CHROMIUM_REVISION`, which `build-bundle.sh` checks against the bundled
  `playwright-core`), in the demo image digest, and in the isolation tests' `chromium-1248`
  paths. All of these moved together.
- **Chromium's directory moved.** From this revision, Chrome for Testing unpacks into
  `chrome-linux64/` and `chrome-headless-shell-linux64/` (it used to be `chrome-linux/`).
  No product code names those directories (Playwright resolves the executable itself), but
  the isolation tests did. They find the core's Chromium by command line, and inv1 checks
  that the agent user can't reach that binary. Both now use `chrome-linux64/chrome`, and the
  suite passes.
- **Native WebAuthn block (layer A) re-verified, unchanged.** Playwright 1.64 ships its server
  as one `lib/coreBundle.js`, but the objects the hook uses keep the same shape:
  `CRConnection` with `_transport.onmessage`, `_rawSend(sessionId, method, params)`,
  `_sessions`, `rootSession`; the client connection's `toImpl`; `CRPage._targetId`;
  auto-attach with `waitForDebuggerOnStart` and a resume via `Runtime.runIfWaitingForDebugger`.
  The shape checks still pass, the probe page comes out covered, and the inv6/inv7
  native-WebAuthn e2e suite (popups, iframes, the detach reset) passes on 1248. The
  alternatives rejected in "Keeping pages off native WebAuthn" were measured on 1194 and
  not re-measured. The "measured on 1.56.1" note about `ariaSnapshot` showing input values
  wasn't re-measured either; the redaction doesn't depend on it.
- **Node: patched release of each line only.** The October 2026 Node security release
  (CVE-2026-111497, Brotli) fixed 22.23.4, 24.22.1 and 26.12.1. `engines.node` is now
  `^22.23.4 || ^24.22.1 || >=26.12.1`, not the plain `>=22.23.4` that was asked for, because
  that would still admit unpatched 24.x (24.0 to 24.22.0) and 26.x releases. `keyflap
  doctor` and `keyflap setup` enforce the same floor (`MIN_NODE` in `cli/src/doctor.ts`,
  with a test), as does the verify-aab launcher. CI and the isolation CI job pin
  `node-version: 22.23.4` (it was `22`, which could resolve to an older cached 22.x), the
  release workflow pins 22.23.4, and the service-mode bundle and installer pin Node 22.23.4
  with its SHA-256 values from nodejs.org's `SHASUMS256.txt`.
- **Demo image Node.** The Playwright 1.64.1 base image ships Node 24 from nodesource, built
  before the security release. `demo/Containerfile` now installs the checksum-pinned
  official Node 22.23.4 tarball into `/usr/local`, ahead of the image's `/usr/bin/node`.
- **ip-address 10.7.3 → 10.7.4 (GHSA-rxp7-6hxx-x8q5).** It is reached only through
  `@modelcontextprotocol/sdk` → `express-rate-limit`. The patched release is within
  `express-rate-limit`'s `^10.2.0` range, so the lockfile entry was bumped in place with no
  override. (`pnpm update --depth Infinity ip-address` would also have re-resolved unrelated
  dev packages.) `pnpm audit --prod` is clean.

## Security review: origin and policy fixes (2026-10-22)

From the pre-launch review of c8297c3: H1, M3, L2, L3, L4, L8, part of L9, and the Info
items on signer refusal codes and localhost. Every change tightens; none relaxes an
invariant.

### Document origin, not just the frame URL (H1; invariants 2, 3, 8)

- **Problem.** The broker took the origin from `frame.url()` alone. A document with the
  site's URL can have an opaque origin: a user upload served with
  `Content-Security-Policy: sandbox`, a popup opened from one (it inherits the sandbox), an
  `<iframe sandbox>` (already denied as a non-top-level frame). Such a page got the site's
  passkey assertion (after an approval card that showed the site's real origin) and, through
  `auth_login`, its password, typed into a DOM whose script could read it. Native WebAuthn
  and password managers refuse such documents.
- **Decision.** Two trusted-side reads, both required. The origin still comes **only** from
  the frame URL (unchanged rule). In addition, the security origin of the frame's current
  document must equal the URL's origin. Opaque, unknown, unreadable or different: denied
  (`document_origin_mismatch`).
- **Where the document origin comes from.** `@aab/shim` `document-origin.ts` reads CDP
  `Runtime.executionContextCreated` on the connection Playwright already holds, through the
  same transport tap as the native WebAuthn block. No CDP session is attached or detached.
  For a frame's default (main-world) context Chromium reports the window's security origin:
  `https://host[:port]` normally, `://` when opaque (measured on Chromium 1248). Rejected:
  `Page.frameNavigated`'s `securityOrigin`, which is derived from the URL and shows the
  site's origin for a sandboxed document (measured), and `self.origin` from page script
  (the main world is the page's to fake). A frame's record is dropped on `Page.frameNavigated`
  (sent before the new document's context), on context destroy / clear and on detach, so
  between documents the origin is unknown and the request is denied. The tap runs before
  Playwright handles each message, so when Playwright dispatches a binding call or runs a
  locator in a document, that document's record is already in place. `trustedFrame(frame)`
  reads URL and origin together, synchronously.
- **Where it is checked.** Every place a frame's origin authorizes a credential: the WebAuthn
  binding (`verifiedOriginFromFrame`, which now takes `securityOrigin`), `auth_status` /
  `auth_login` (`verifiedOriginOfPage`), the fill driver before every secret release and
  every typed value, and the handoff gate, frames and input. `checkOriginUrl` keeps the URL
  rules for origins the broker re-derives from its own state (an approved fill, a grant);
  it is never used on a request.
- **The navigation gap.** Right after a navigation commits, the new document's origin is
  briefly unknown. Two places must not read that as "left the site": the handoff's
  `framenavigated` listener (it ends the handoff only when the URL's site changes) and the
  fill driver's wait for the next step (it keeps waiting while the URL is still on the
  origin). Neither types, shows frames or accepts input until the document origin checks.
- Tests: `core/test/inv2-opaque-origin.e2e.test.ts` (review a01: CSP sandbox get and create,
  the inherited-sandbox popup on the RP's real login page, a non-sandboxed control),
  `core/test/inv8-opaque-origin-fill.e2e.test.ts` (review a02, plus the page swapping to a
  sandboxed copy while the user approves), rule cases in `origin.test.ts`.

### One canonical host form (L2)

- **Problem.** `https://example.com.` was a verified origin with host `example.com.`; no
  `example.com` rule matched it, so `deny` and `ask-strong` were skipped and the owner was
  prompted.
- **Decision.** `origin.ts` has the one definition: `canonicalHost` (lower case, punycode,
  LDH labels, no empty label, no trailing dot, not an IP). A verified origin with a
  non-canonical host is denied (`non_canonical_host`), so policy, grants, the high-risk list,
  credentials and TTL clocks only ever see canonical hosts. `registrableDomain` returns null
  for a non-canonical host. Input naming a site (CLI site arguments, cookie domains, saved
  state origins) goes through `normalizeHost` / `canonicalOrigin` (drops one trailing and
  one leading dot, case-folds, IDNA), so saved-state filters see `https://EXAMPLE.org.` as
  `example.org`. Tests: `core/test/inv6-canonical-host-revoke.test.ts` (review a07, a07b).

### Revoke from another process (L3)

- **Problem.** A dev-mode `keyflap agent revoke` writes SQLite from its own process; the
  daemon's in-process revoke listeners never fired. MCP calls stopped (tokens are looked up
  per request), but a page left open in the revoked agent's context still signed in, with no
  prompt inside an allow-for grant.
- **Decision.** The broker reads the agents table on every request and again right before
  every signer operation (sign, create, release, P3b grant): an agent that isn't active is
  denied `agent_revoked` and its core grants are dropped. The daemon also polls (every 2 s,
  `revokeWatchMs`) the agents it has contexts or ports for, and runs the revoke listeners
  for any that were revoked elsewhere: context closed without a save, handoff ended, grants
  and opt-ins dropped, saved state deleted. Broker-level tests now register their fixed
  agent identities (`registerAgents` in `test/harness.ts`). Tests:
  `core/test/inv6-canonical-host-revoke.test.ts` (review a08, plus a revoke while the user
  approves), `core/test/inv6-revoke-cross-process.e2e.test.ts` (the daemon closes the context).

### Session TTL over the whole site (M3)

- **Problem.** `clearSite` cleared every cookie of the site but storage only for the clock's
  origin and the pages open at that moment, so a token in `app.example.com`'s local storage
  survived a TTL whose login was on `login.example.com`. And the sweeper resolved the TTL
  only for the clock's origin, so `policy set https://app.example.com --session-ttl 1h`
  never fired while the daemon ran when the login was elsewhere on the site.
- **Decision.** Each agent session records every http(s) origin its frames show (main frames
  and iframes, at most 1000) plus the restored snapshot's origins (`originsOnSite`).
  `clearSite` clears storage for all of them on the site. The sweeper resolves the TTL as the
  shortest over the site's known origins (the clocks', the session's, `https://<site>`), as
  the restore filter's `verdictFor` does, keeps a site while any of its clocks is live, and
  clears it once when all have expired. Tests: `core/test/inv6-session-ttl-site.e2e.test.ts`
  (both cases fail on the old code).

### Smaller items

- **L4, one pending approval per agent.** ARCHITECTURE section 11 promised "rate limits"
  against approval fatigue; only handoff pushes had one. While an approval of an agent waits,
  further requests of that agent are denied `approval_pending` without reaching the approver
  (not queued). Other agents are unaffected. Test: `core/test/inv6-approval-pending.test.ts`.
- **L8, ask-strong sites are not saved.** The owner's `ask-strong` rule now makes a site
  high-risk for saved browser state, as the built-in list does: not persisted unless the
  owner opts in ("Keep me signed in", which strong approval cards now offer for these sites
  too, or `keyflap sessions keep`). Test: `browser-state.test.ts`.
- **L9, audit fail-closed for handoffs.** A handoff is opened (`handoff.requested`) and
  started (`handoff.started`) only once its audit entry is written; if the append fails the
  handoff ends and the request is denied. Refusals and endings stay best effort (the safe
  direction), as do TTL clears and saved-state bookkeeping: a clear that happened but
  couldn't be logged is better than a session kept because the log failed. **Not done here:**
  writing an intent and its `intent.recorded` entry in one transaction (`intent-server.ts`),
  left for the per-session agent identity work that changes intents next.
- **Signer refusals keep their code.** A refusal from the signer is audited as
  `denied {reason: 'signer:<code>'}` (the signer's identifier, e.g. `signer:grant_expired`),
  not `internal_error`.
- **Iframe ceremonies.** Only a main-frame WebAuthn request emits the ceremony events that
  `auth_login` / `auth_enroll_passkey` wait on. An iframe's request (always denied) used to
  end a "ceremony" a later `auth_login` on that page picked up as `denied`.
- **Not changed (Info items, recorded):** passkeys are bound to their rpId, not to the agent
  that enrolled them (any agent with a live intent and an approval can use one; the card
  names the agent). The core has no rule refusing credential operations on the phone
  approver's own origin; the approver passkey lives on the phone, not in the broker, so there
  is nothing there to release.
- **localhost.** `http://localhost` and `*.localhost` are accepted in every mode, not just
  tests (ARCHITECTURE 6.3 now says so). An rpId must still be a suffix of the host, so a page
  there can only use credentials registered for localhost names. No production switch.

## Root-run setup, installer and password tools (security review H2, H3, M4, 2026-10-22)

Fixes for the review's service-mode and installer findings. Attacker D (a process running as
the owner's uid, so any agent with a shell) must not steer anything root runs.

- **`sudo keyflap setup` writes the user's files as the user (H2).** Every read and write
  under the user's home and the user-owned hook dir goes through `cli/src/setup/user-files.ts`:
  as root it drops to the user's uid, gid and groups (`setgroups`/`setegid`/`seteuid` around
  synchronous calls, restored in reverse in `finally`), so the kernel refuses whatever the
  user couldn't do. As a second layer, and for the clear error: a path is walked with `lstat`
  and a symbolic link is followed only through directories only root can change (`/bin` →
  `usr/bin`), never in a user-owned one, and never as the last component; files are opened
  `O_NOFOLLOW` and checked with `fstat` (regular, owned by the user, ≤ 4 MiB); writes go to a
  fresh `O_CREAT|O_EXCL|O_NOFOLLOW` temp file, then `fsync` and `rename`. No `chown` anywhere
  (files are born the user's), and backups are written from the text that was previewed,
  never copied from the path. Refusal applies in dev mode too (fail closed). `keyflap doctor`
  reads the same files the same way and reports a link it refused (`user-files`) instead of
  following it. A refused file is reported per file and the rest of setup goes on.
- **One trusted-tool rule for every external password tool (H3).** `@aab/sources` `tool.ts`:
  an adapter declares only a `ToolSpec` (command, install hint) and runs its binary through
  a `ToolLauncher`, with no default trust (constructing an adapter without one throws). In
  service mode (`{mode: 'system'}`) the configured path must equal its realpath, sit in a
  system bin dir (`/usr/bin`, `/usr/local/bin`, `/usr/sbin`, `/usr/local/sbin`, `/bin`,
  `/sbin`) or `/opt/keyflap/tools/<command>/`, have every component owned by uid 0 with no
  group/other write bit (an ACL's named writer shows in the group bits, which are the mask),
  no setuid/setgid bit, and be executable; and its SHA-256 must equal the pin in
  `signer.json`. Checked before every launch (the hash is cached by dev/ino/size/mtime/ctime).
  A refusal is a `SourceError` (`source_tool_untrusted` / `source_tool_changed`), so the core
  audits `source.sync_failed` with that reason and the signer journals `source_tool_refused`
  (once per distinct cause). Dev mode is `{mode: 'same-user'}`: the signer already runs as
  the user, so a check would protect nothing.
- **Pinning.** The installer always records the hash (install-config.ts re-runs the same
  check and refuses with the fix). `sudo keyflap password-source trust <tool>` re-checks the
  location and rewrites the pin in the root-owned `signer.json` (temp file + rename). On a
  mismatch the signer re-reads `signer.json` and accepts a matching new pin, so a trust needs
  no restart; the signer can read that file but never write it. This is the one signer change
  (tool launch only): `buildSources` takes the trust mode, `parseServiceConfig` validates
  `sha256`.
- **The installer never takes a binary from the user (H3).** `install.sh` no longer looks at
  `$SUDO_USER`'s `PATH` or copies anything: `pass-cli` is found only at
  `/opt/keyflap/tools/pass-cli/pass-cli`, `/usr/local/bin/pass-cli`, `/usr/bin/pass-cli` (or
  `--proton-pass-bin`), checked with the same rules in shell (`tool_problem`) before anything
  changes, and refused with how to install it as root. The old copy in `/opt/keyflap/bin` is
  deleted on upgrade. `/opt/keyflap/tools` is created root 0755 and kept by a plain uninstall.
  `keyflap doctor` (service mode) reports a refused or changed tool with the exact fix, and
  `sudo keyflap setup` checks it before offering the login command.
- **install.sh runs only from root-only places (M4).** First thing after the root check it
  refuses to run if its own directory, any parent, or anything inside isn't root-owned and
  free of group/other write bits, and prints the `/opt/keyflap-release` flow. The same check
  applies to `--bundle`, `--node-tarball`, `--node-dir`, `--browsers-dir`, `--tls-*` and
  `--apns-key`. A guard rail, not the boundary: it closes the edit-between-extract-and-sudo
  window that the README's old quick start left open. The from-source flow copies the
  installer and bundle into `/opt/keyflap-release` first; the isolation harness does the same.
- **Xvfb (L11).** The installer resolves `Xvfb` (realpath) and checks every component like a
  password tool; `keyflap-core` re-checks `cfg.browser.xvfbBin` with `rootOnlyProblem` before
  each start and refuses to run it otherwise.
- **Units (review Info).** `LimitCORE=0` on the signer, core and approver (a dump would hold
  whatever secrets were in memory). With no password tool configured the installer adds a
  signer drop-in that narrows `RestrictAddressFamilies` to `AF_UNIX` (the drop-in dir is
  rebuilt on every run, so adding a source later re-opens the network).
- **Dev-mode hook code (L10).** Claude Code runs the dev hook and `headersHelper` from the
  checkout, outside its sandbox. Documented in claude-code.md "What still defeats it";
  `keyflap doctor` (dev) warns (`hook-code`) when the project it checks, or one setup
  configured, contains the checkout or lies inside it. Not a warning on every dev setup, so a
  healthy one still passes.
- **Docs.** README's quick start and service-mode.md use `/opt/keyflap-release` (root-owned)
  with `--signer-workflow`; service-mode.md's renderer-exploit limit now lists what the
  `keyflap-core` uid holds (saved sessions, released secrets kept for scrubbing, the host
  token); phone-approver.md says removal is immediate.
- **Tests.** `cli/test/inv1-setup-symlink.test.ts`, `cli/test/inv1-password-tool.test.ts`,
  `sources/test/inv1-tool-trust.test.ts`, `approver/test/inv6-removed-device.test.ts`; as real
  root in the container, `isolation/test/inv1-installer-trust-isolation.test.ts` (the
  installed setup code against links `agentuser` planted, the tool check on real root- and
  user-owned files, install.sh preflight refusals, LimitCORE and the signer's address
  families) and the M4 refusal in `release-install.test.ts`. `sudo keyflap setup` itself
  needs a TTY, so the isolation test drives the installed setup functions as root rather
  than the interactive command.
- **Not done here.** The installed tool still shares `keyflap-signer`'s uid with the KEK; the
  review's "better still" (a separate uid for vendor binaries) is a larger change. The pin
  proves the binary is the one the owner installed, not that it is honest.
## macOS: dev mode and tests (2026-10-22)

Step A of macOS support: same-user dev mode (`keyflap daemon --unprotected`) and `pnpm
test` (unit + e2e) on macOS, run by a separate CI workflow. Service mode on macOS
(ISOLATION_PLAN.md S5) was not built yet when this was written; it was on 2026-10-29, see
"Service mode on macOS (S5)". Everything here was
written on Linux. It was first run on a real Mac on 2026-10-29: see "Run on a real Mac" below.

- **Unix socket path length: refused, never truncated (all platforms).** `sun_path` holds
  108 usable bytes on Linux and 103 on macOS/BSD. Measured on Node 22.23.4 and 26.7 (Linux):
  a 108-byte path binds and connects under its full name (Linux needs no terminating NUL);
  a longer one is **silently truncated**: `listen()` succeeds on the shorter path and
  `connect()` goes to it too. (The first version allowed 107 on Linux, refusing a 108-byte
  path that had worked; raised to 108 after review. macOS stays at 103 until 104 is checked
  on a Mac.) On macOS `os.tmpdir()` is a ~50-byte `/var/folders/…/T` path, so deep data
  dirs get close. Every socket the broker binds or connects to now goes through
  `@aab/signer/platform` (`assertUnixSocketPath` / `unixSocketPathProblem`, node built-ins
  only, so the signer stays dependency-free): the signer server, `spawnSigner` (before
  spawning) and `SignerClient`, the admin wire (listen and `adminCall`, which rejects as
  `unreachable`), the core's `listenUnix` (intent socket), `PhoneApprover` and
  `ApproverFront` paths, the Claude Code / Codex / Hermes hook (`HookFailure` on stderr,
  still exit 0 and no stdout), setup's `connectUnix` probe (false), and `startDaemon`, which
  checks both sockets before it creates or starts anything. `keyflap daemon` checks them
  before the passphrase prompt and exits 1 with the path, its length and the limit. Linux
  behaviour is unchanged except that a too-long path is now an error instead of a socket
  somewhere else. Tests: `signer/test/platform.test.ts`, `core/test/socket-path.test.ts`,
  `cli/test/daemon-socket-path.test.ts`.
- **Tests use `/private/tmp` on macOS.** `vitest.setup.ts` (both projects) sets
  `TMPDIR=/private/tmp` on darwin, so test data dirs and sockets stay short there; spawned
  daemons and signers inherit it. Not `/tmp`: on macOS that is a symbolic link to
  `/private/tmp`, and the root-only path checks (Tailscale's LocalAPI directory, the
  `localapi_problem` shell check) refuse a path with a link on the way before they look at
  owners and modes, so tests of those checks would see the wrong refusal. Linux is untouched. The product never shortens a path itself. Budget check
  without the override: the whole suite passed on Linux with a 58-byte `TMPDIR` (against
  Linux's 108 bytes, about as tight as a 54-byte tmpdir against macOS's 103; macOS's is ~50).
- **Service mode refuses to start off Linux.** `serviceModeUnsupported()` in
  `@aab/signer/platform` is checked by the signer's `main.ts --service`, the core and
  approver-front unit entry points (`cli/src/service/core-main.ts`, `approver-main.ts`
  `main()`), and the CLI when `KEYFLAP_MODE=service` (before setup/doctor and every admin
  command): exit 1 with "service mode needs Linux with systemd … use keyflap daemon
  --unprotected". The library functions (`runCoreService`, `runSignerService`) are not
  gated, so S5 can reuse them. `signer/test/service-mode.test.ts` and
  `cli/test/service-mode.e2e.test.ts` run on Linux only; off Linux the signer test instead
  checks that `--service` refuses. The Linux service paths (`/run`, `/var/lib/keyflap`) are
  unchanged; the hook's `--service` flag on a Mac just fails to find them (stderr, exit 0).
- **Invariant 7 on macOS.** `core/test/inv7-no-cdp.e2e.test.ts` gained a darwin block: the
  managed Chromium (found with `ps -A -ww -o pid=,ppid=,command=` under the test process)
  has `--remote-debugging-pipe` and no `--remote-debugging-port`/`-address` anywhere in its
  tree, wrote no `DevToolsActivePort`, and no process of its tree holds a listening TCP
  socket (`/usr/sbin/lsof -nP -a -p … -iTCP -sTCP:LISTEN`; a missing `lsof` fails the test,
  it never passes vacuously). Same control as Linux: a Chromium with
  `--remote-debugging-port=0` must be flagged, and the test process's own MCP listener must
  be found. The fd 3/4 socketpair check stays Linux-only. The `ps` half was run on Linux by
  temporarily enabling the block (it passed); the `lsof` half could not be run here.
- **`keyflap setup`.** `System` gained `platform`. The `--headed` question defaults to yes
  on macOS unless `SSH_CONNECTION` is set (a desktop is there; `DISPLAY`/`WAYLAND_DISPLAY`
  as before elsewhere). Dev-mode setup only runs `systemctl list-unit-files` on Linux (it
  looks for an installed service mode). The Claude Code hint now says the macOS sandbox is
  built in (Linux: bubblewrap + socat).
- **Test helpers.** `cli/test/pty.ts` drives a pty with util-linux `script -qfec` on Linux and
  BSD `script -q /dev/null` on macOS (no Python: on a Mac without the Xcode Command Line Tools
  `/usr/bin/python3` is a stub). BSD `script` exits with `tcgetattr/ioctl: Operation not
  supported on socket` when stdin is the socketpair Node makes for `stdio: 'pipe'`, so the
  macOS branch runs it under `/bin/bash` with stdin fed through `/bin/cat` (absolute paths:
  the test's `PATH` has no `/usr/bin`) and `PtySession` destroys the child's stdin on exit so
  that `cat` goes away. `setup.e2e.test.ts` points
  `PLAYWRIGHT_BROWSERS_PATH` at `~/Library/Caches/ms-playwright` on macOS and accepts either
  default on the `--headed` prompt.
- **Audited and left as is.** `/proc` reads in tests were already gated
  (`daemon-cli.e2e` environ check, `inv9-channel` cmdline/environ, inv7 Linux block). File
  mode checks (`mode & 0o077`, 0700 dirs, 0600 files) and uid checks behave the same on APFS;
  new files in `/tmp` get group `wheel` there, and nothing checks gids. Signals (SIGINT,
  SIGTERM, SIGHUP), `node:sqlite`, Playwright launch options (no platform flags) and the
  native-WebAuthn block (Playwright/CDP internals only, no OS code) have no platform branch.
  No `fs.watch`, no abstract sockets outside service-mode Xvfb, no file names that differ
  only by case. `*.localhost` resolves to loopback inside Chromium on every platform. The
  dev data dir stays `~/.keyflap` (no XDG); Proton Pass in dev mode passes the user's env
  through, so `pass-cli` uses its own macOS key provider (not tested: tests use the fake).
  The Claude Code sandbox on macOS blocks unix sockets unless listed (claude-code.md); the
  hook runs outside the sandbox, so nothing changes.
- **What only a Mac can confirm.** That the whole e2e suite passes on Chromium 1248 for
  macOS (headless shell) and the layer A native-WebAuthn block holds there (on a Mac a
  native request could otherwise reach Touch ID / iCloud Keychain, so this is the platform
  where layer A matters most); `lsof` output
  parsing in the inv7 block; and headed mode on a real desktop (not covered by CI).
- **Run on a real Mac (2026-10-29).** Apple silicon, macOS 26, origin/main
  `4b2da9d`, run by hand on the owner's test Mac. The full test suite passed, with one
  catch: `setup.e2e` needed a working `/usr/bin/python3`, which on a Mac without the Xcode
  Command Line Tools is a stub, and `pty.ts` hardcoded that path. Fixed: `pty.ts` now uses BSD
  `script` (see Test helpers), and `setup.e2e` passes on that Mac with the stub python3. Dev mode
  with Claude Code as the agent: a password and one-time-code sign-in with a real phone approval
  succeeded; passkey enrollment and passkey sign-in succeeded; denying on the phone was
  refused as it should be. Service mode was not built yet (it was later the same day: see
  "Service mode on macOS (S5)" below).
- **CI.** `.github/workflows/macos.yml`: `macos-15` (Apple silicon), Node 22.23.4, pnpm from
  `packageManager`, `playwright install chromium` (no `--with-deps`, which is for Linux
  packages), then typecheck, lint, `test:unit`, `test:e2e`. Separate from `ci.yml` so a
  macOS failure doesn't block Linux; push to main and manual runs, not pull requests, with
  in-progress runs cancelled per ref.

## Service mode on macOS (S5): the platform layer (2026-10-29)

Unit M1 of `docs/MAC_PLAN.md`, built and tested on Linux. It is the TypeScript ground the Mac
installer (M3) stands on. When this was written nothing had run on a Mac yet; the M0 spike and
the M3 install ran on the test Mac later (see the sections below).
The Linux service-mode tests are unchanged except where this section says so.

- **The gate is a platform lookup.** `servicePlatform()` and `servicePlatformProblem()` in
  `@aab/signer/platform` replace `serviceModeUnsupported()`: `SERVICE_PLATFORMS` names `linux`
  (systemd) and `darwin` (launchd), and anything else gets "service mode needs Linux with systemd
  or macOS with launchd; it is not built for <platform>". The same four places check it (the
  signer's `--service`, the core and approver unit entries, the CLI under `KEYFLAP_MODE=service`),
  so darwin now passes. `signer/test/service-mode.test.ts` and `cli/test/service-mode.e2e.test.ts`
  run wherever the lookup says yes (so on the macOS workflow too) and the
  refusal test runs everywhere else. The "refuses off Linux" wording above and in
  ISOLATION_PLAN.md S5 is superseded.
- **`SERVICE_PATHS` is a table per platform** (`cli/src/service/paths.ts`): `LINUX_SERVICE_PATHS`
  byte for byte as before, `DARWIN_SERVICE_PATHS` as MAC_PLAN's "Shape on macOS" table (prefix
  `/opt/keyflap`, `/Library/Keyflap/{etc,data,hook,run/<service>}`, wrapper `/usr/local/bin/keyflap`).
  `paths.ts` imports nothing (the hook's import boundary), so it keys on `process.platform` itself
  and `service-paths.test.ts` ties its keys to `SERVICE_PLATFORMS` so the two cannot drift. An
  unsupported platform gets the Linux table, as before; the gate refuses first. Both tables have
  the same keys: nothing macOS-only (log dir, plist dir, credentials dirs) was added to
  `ServicePaths`; the two the code needs live in `manager.ts` (`DARWIN_LOG_DIR`,
  `DARWIN_LAUNCH_DAEMONS`) and the credentials layout stays M3's. The strings that spelled Linux
  paths by hand (`--data-dir` refusal, hook help, unit-entry usage lines, doctor's tool-bin fixes)
  read the table now. `service-paths-installer.test.ts` pins the Linux table against
  `packages/install/linux` explicitly; `service-paths.test.ts` pins the macOS table, the
  no-`/etc`-`/var`-`/tmp` and no-space rules and the 103-byte socket limit, and fails the moment
  `packages/install/macos` exists without a darwin twin of the installer test (M3 writes it).
- **User lookup goes through `System`** (`cli/src/setup/users.ts`, `lookupUser(sys, {uid} | {name})`).
  Linux still reads `/etc/passwd`. darwin runs `/usr/bin/id -P <uid|name>` (absolute path: macOS
  sudo has no `secure_path`, so an agent could put an `id` earlier on PATH) and parses the 10-field
  BSD passwd line; home is the field before the shell, so one parser serves both. A uid answer
  must carry that uid, and a name must look like one (no leading `-`), so nothing reaches `id`
  as an option. `id -P` was chosen over `dscl` because it answers name, uid, gid and home in one
  line and resolves either RecordName of a service user. The fakes drive both branches.
- **Service user names.** The code uses the prefixed names on darwin (`_keyflap-core`,
  `_keyflap-signer`, `_keyflap-web`): the primary RecordName is what `ps`, `ls -l`, `id -P` and
  launchd print, so checks and messages match what the owner sees. The un-prefixed alias that
  MAC_PLAN gives each user is for humans typing `id keyflap-core`.
- **A service-manager seam** (`cli/src/service/manager.ts`, `serviceManager(platform)`) holds
  what setup, doctor, the service CLI and the help text knew about systemd by name: unit names,
  users, the is-active and installed probes, and the status, log, restart and socket-repair
  hints. The systemd entry reproduces the old strings word for word (pinned in
  `service-manager.test.ts`). The launchd entry: LaunchDaemons `com.keyflap.{signer,core,approver}`,
  state from `launchctl print system/<label>` (`state = running` is active; a non-zero exit is
  "not loaded"), installed when `/Library/LaunchDaemons/com.keyflap.core.plist` exists, restart as
  `launchctl kickstart -k system/<label>` (one command per service, so setup offers two), sockets
  repaired with `bootout` + `bootstrap`, logs as `sudo tail -n 50 /Library/Keyflap/log/<service>.log`.
  Doctor's mode line says `service mode (launchd)`; its socket checks are the same as on Linux
  (intent socket owned by the hook-dir owner 0600, admin sockets root 0600) because launchd
  creates the sockets as root with `SockPathOwner`/`SockPathMode` and `keyflap-launch` hands them
  over (MAC_PLAN). Setup's pass-cli step looks the signer user up by the platform's name and runs
  pass-cli with the table's `signerData` as `HOME`, `PROTON_PASS_KEY_PROVIDER=fs` as on Linux.
- **The browser is the full Chromium in new headless mode.** `launchManagedBrowser` and
  `startDaemon` take `channel: 'chromium'` (`browserChannel` on the daemon), which Playwright 1.64.1
  runs as the full browser with `--headless` instead of the headless shell. Measured on Linux with
  the pinned Chromium (`shim/test/browser-channel.e2e.test.ts`): `Browser.getVersion` reports
  `Chrome/…` with the channel and `HeadlessChrome/…` without, but the user agent says
  `HeadlessChrome` either way, so the bot-wall cost of headless is not avoided by the channel; what
  it buys is the full browser's features. The core config carries it as `browser: { mode:
  'headless', channel: 'chromium' }`; `buildServiceConfigs` (so `install-config.ts`) sets it on
  darwin and refuses `--xvfb` there, and `parseCoreConfig` refuses `mode: xvfb` on darwin. Doctor's
  headed check under launchd reports headless as the design (human checks go to the phone's live
  view) instead of asking for `--xvfb`. Dev mode and the Linux configs are unchanged: Linux
  `--headless` installs still run the headless shell.
- **What M3 must match.** The darwin paths table; the labels and plist paths above; the users
  `_keyflap-{core,signer,web}` with the un-prefixed alias; `StandardErrorPath`
  `/Library/Keyflap/log/{signer,core,approver}.log` in a root-only dir; `core.json` from
  `install-config.ts` run on the Mac (it writes the `chromium` channel by itself); only
  `chromium-1248` (not the headless shell) needs to be in the prefix; `CREDENTIALS_DIRECTORY` per
  plist; and the darwin twin of `service-paths-installer.test.ts`.
- **Not verified on a Mac.** The `id -P` line shape and that it resolves the alias RecordName;
  the `launchctl print` output and `kickstart -k` semantics; whether the signer and core
  service-mode tests pass on darwin now that they run there.

## High-risk list: socials removed (2026-10-29)

- **Deviation from the list as first shipped.** `facebook.com`, `meta.com`, `x.com` and
  `twitter.com` are no longer in `BUILTIN_HIGH_RISK` (`packages/signer/src/risk.ts`). The owner's
  decision, in `DECISIONS.md` under "High-stakes sites stay gated; socials leave the default
  list". An agent on a social site is much harder to turn into spent money than one on a bank,
  Google or Amazon, so a fresh phone tap with no saved login is more friction than the risk
  earns. Everything else on the list stays.
- **Invariant 6 is unchanged.** High-risk origins still always require fresh user verification.
  ARCHITECTURE section 9 never named social sites in the `ask-strong` default (financial,
  government, email, identity provider), so only the shipped list moves.
- **What the four sites now get.** The same treatment as any site off the list. The signer asks
  for no user verification and no 60 s lifetime cap on their approvals, so the terminal approver
  can approve them (phone approvals are still user-verified and 60 s). `allow-for` grants can
  be recorded for them. Their agent's browser state is saved across restarts unless the owner
  starts the daemon with `--ephemeral-browser` or sets the site `ask-strong`. The default `ask`
  rule (a tap every time) and the audit log still apply.
- **Owners can put them back.** `--high-risk facebook.com` (or `highRiskDomains`) matches the
  host and its subdomains, as for any entry.
- Test: `packages/signer/test/inv6-high-risk-list.test.ts` checks that the four domains and a
  subdomain of each are not high-risk, that a sample from every other category still is, and
  that an owner entry still gates a social site.

## Saved-login window: cap raised from 12 h to 24 h (2026-10-29)

- **Decision.** The owner, 2026-10-29 (`DECISIONS.md`, "Saved-login window"): 12 hours is too short for
  low-stakes sites, so the longest allow-for window is 24 hours. ARCHITECTURE section 9 gives no
  figure. The 12 h limit was an M5 implementation choice, so this changes `M5_PLAN.md` and the
  M5 notes above, not the contract. No invariant in section 5 changes.
- **Where the number lives.** Four independent copies hold it and they must agree; the fifth is derived. `MAX_GRANT_MS` in
  `packages/signer/src/approval.ts` is the authority: the signer refuses a longer grant with
  `grant_not_allowed`, and the terminal approver's `requestProblem` imports it.
  `ALLOW_FOR_MAX_MS` in `packages/core/src/policy.ts` is the range check behind `keyflap policy
  set` and the policy store; it is defined as `MAX_GRANT_MS`, so it cannot drift. `packages/approver/src/page/approval-check.js` keeps its own copy
  because it is plain browser JS that cannot import: the phone page refuses to sign a longer
  window. `StatementCheck.maxGrantMs` is the same check in the parked iOS app, changed without a
  Swift build or test run. The `--allow-for` help in `packages/cli/src/args.ts` states the limit.
- **Unchanged.** A grant never applies to a high-risk or `ask-strong` origin. A `strong`
  statement still needs a phone approval that lives at most 60 s
  (`STRONG_APPROVAL_MAX_LIFETIME_MS`). Grants still need the user's own signed approval, stay in
  the signer's memory (a restart drops them), and bind one agent, one exact origin and one
  credential. The default policy is still `ask`, so nothing lasts longer until the owner sets an
  `allow-for` rule. The single-use human-check sign-in window stays at 7 minutes.
- **What the longer cap costs.** A compromised core holding a grant can sign in again, as that
  agent, to that origin, with that credential, for up to 24 h instead of 12 h. It still cannot
  widen the origin, credential, kind or agent, claim user verification, or get a grant the user
  did not sign. A phone that shows a shorter window than the statement carries is caught by the
  page's own check.
- **Tests.** The boundary is pinned with literal 24 h values so a drift in either direction
  fails. `signer/test/inv6-policy-grants.test.ts` accepts exactly 24 h, uses the grant until the
  window ends, and refuses 24 h plus 1 ms. `core/test/policy.test.ts` and
  `cli/test/policy.test.ts` accept `24h`, refuse 24 h plus 1 ms or 1 s, and check the message
  names 24h. `approver/test/inv5-approval-check.test.ts` and `approver/test/approver.test.ts`
  hold the phone page and the terminal approver to the same line.
  `core/test/inv6-policy-broker.test.ts` runs a 24 h window through the policy, the approver and
  the real signer.
- **Not built.** The cap is still a constant. Letting the owner change it is queued for its own
  design (where the number lives, who may raise it, and how the signer stays the authority).
  "Keep forever" is not wanted: the owner, "Forever doesn't exist" (`DECISIONS.md`).
  `docs/AGENT_ADMIN_PLAN.md` still lists 12 h for agent-requested windows. That design is not
  built, so it is unchanged, and so is the 2026-10-22 review finding above that mentions "up to
  a 12 h grant", which records what was true then.

## Approval cards are swipe cards (2026-10-29)

- **Decision.** The owner asked for Duo-style cards in the Keyflap brand ("almost like a tinder swipe
  card") and chose a blue circle with a check mark over words, and a white card over black on
  black (`DECISIONS.md`, "Approval cards are swipe cards"). The brand rules are in the
  `keyflap-site` brand README, "Approval card (phone)". No invariant changes and the card shows
  the same fields as before (invariant 5); the one new line of text is the static hint "Swipe
  right to approve, left to deny".
- **A swipe is never an approval.** `app.js` builds one `approve` function per card
  (challenge, `AabCheck.checkStatement`, `AabCheck.approvalChallenge`, `navigator.credentials.get`
  with `userVerification: 'required'`, then `/api/decide`). The Approve button's click handler
  and a drag right past 35% of the card's width both call it through `exclusively(approve)`.
  The gesture code (`attachSwipe`) only moves the card and reports a direction; it knows nothing
  about the request. A mismatch still posts a deny and says so in words; a cancelled Face ID or a
  refused approval leaves the card in place with "Not approved: ...". The card flies off only after
  `/api/decide` answered 200 (never, under `prefers-reduced-motion`: it changes at once). A drag
  left posts `deny` once.
- **One decision in flight.** `exclusively` returns at once while another decision is running, so a
  tap during a swipe, a second drag and a drag that ends after the button was tapped do nothing;
  `pointerdown` also refuses to start a drag meanwhile. The flag is page-wide, so a Face ID prompt
  never has a second one beside it.
- **The poll never rebuilds a card.** `refresh()` still reconciles by request id: it adds cards it
  has not seen and removes cards the broker no longer lists. A card that is flying off is skipped
  by the removal until its own `leave` removes it. The first pending request is the front card
  (the broker sorts by creation time); the others are `inert` and `pointer-events: none`.
- **Page structure.** `#requests .card` is still one element per request, front card first, and
  still holds `.approve`, `.deny`, `.error`, `.keep`, `.keep-box`, `.title`, `.said`, `.site`,
  `.agent`, `.credential` and `.allow`, so the simulated phone, the isolation probe and the verify
  skill's `drive.mjs` needed no locator change. `.card` is now an invisible slot: the paper `.face`
  moves and tilts, the error strip sits under it, and the round buttons stay put under the stack.
  The slots share one grid (`grid-template-rows: subgrid`), so every face has the height of the
  tallest. At most three show; the fourth and later are `display: none`.
- **Under the CSP.** The page runs under `style-src 'self'` and `default-src 'none'`: no `style`
  attributes, no `innerHTML` (a test bans it). Motion is set through `element.style`
  (CSSOM, allowed); the icons are `<symbol>`s in a zero-size sprite in `app.html` used by
  `<use href="#icon-check">`, same-document references that need no extra directive. The e2e file
  fails if Chromium logs a CSP violation.
- **Look.** The site is uppercase Barlow Condensed in blue. Only weight 700 is self-hosted, so it
  is 700, not the brand's 800 for the site name; the app's copy of the fonts is refreshed from the
  brand repo, which this change did not touch. Row labels keep small caps rather than
  `text-transform`, because tests read `card.innerText()` and look for "Allow-for". The site's
  size steps down for longer origins (`data-size`) so a typical origin fits on one line.
  Under reduced motion there is no tilt and no fly-off; the card still follows the finger.
- **Deny now says when it fails.** A deny the broker did not accept (`/api/decide` not 200, or the
  network down) leaves the card and shows "Not denied: ...", where it used to be ignored.
- **Tests.** `core/test/swipe-approval.e2e.test.ts` drives the real page in Chromium against a
  real daemon and signer with a virtual authenticator: swipe approves through the signer, a short
  drag does nothing, swipe left denies once, a lying core is denied on a swipe as on the button, a
  cancelled Face ID or a refused approval keeps the card, a drag from the checkbox does not move
  it, a poll and a new request mid-drag leave the card alone, tilt is capped at 10 degrees and
  absent under reduced motion, stamps fade in on the right corner and pop past the threshold, one
  decision at a time, a finger (touch events) works, and the buttons keep their accessible names
  and carry no words. Mutation-checked: threshold 0, no `checkStatement`, no in-flight guard and
  no `pointerdown` guard each fail a named test.
- **Not built.** The iOS app (parked) keeps its own Approve and Deny. The brand's "denied" flap
  after a decision (a big cross over the card) in the prototype is not built: the card simply
  leaves. A swipe has no keyboard form; the buttons are the keyboard and screen-reader path.

## CI runs only on GitHub-hosted runners (2026-10-31)

The repository is public. A pull request from a fork runs the workflow file the fork carries,
so a self-hosted runner registered to a public repository can be made to run anyone's code.
No self-hosted runner is ever registered to this repository, and no workflow names one.

- **Pinned.** `packages/cli/test/workflow-runner-guard.test.ts`: every `runs-on` in every
  workflow is a GitHub-hosted label (no expressions), and no workflow's code says
  `self-hosted`. The Linux job installs Chromium with `--with-deps`.
- **Not covered.** A runner registered in the repository's settings is outside the files;
  nothing in the repository can check it.


## keyflap-launch: launchd socket handover (Mac M2, 2026-10-29)

MAC_PLAN.md "keyflap-launch". launchd creates each service socket (owner, group, mode, the
approver's TCP port) and keeps it, and `keyflap-launch` hands them to Node the way systemd does,
so every entry point keeps its `listenFds` path (`signer/src/systemd.ts`) unchanged.

- **What it does.** `keyflap-launch --socket NAME [--socket NAME]... -- /abs/program [args]`.
  It refuses to run when the real or effective uid or gid is 0, then checks the arguments (names
  match the credential-name regex `listenFds` uses, no name twice, 1 to 64 of them, an absolute
  program). For each name, in order, it calls `launch_activate_socket(3)` and needs exactly one
  fd: a name missing from the plist's `Sockets` fails, and so does one that yields two (a
  `localhost` listener gives IPv4 and IPv6, so plists use an IP literal and `SockFamily`, as
  the Linux installer already insists on an IP literal). It moves them to fds 3.., clears
  close-on-exec, sets `LISTEN_PID` (its own pid, which `execv` keeps), `LISTEN_FDS` and
  `LISTEN_FDNAMES`, and `execv`s the program: no `PATH` search. Every failure is one stderr line
  and exit 1, and the program never runs. It does not drop privileges: the plist's `UserName`
  does, and the uid check makes a plist without one fail instead of running Node as root.
- **Source and build.** `packages/install/macos/launcher/keyflap-launch.c`, about 100 lines, no
  headers: it declares the 14 libSystem functions it calls, and `libSystem.tbd` lists exactly
  those for the linker, plus the two stack-protector symbols the compiler adds. `build.sh OUT_DIR` cross-compiles it on Linux in
  `debian:trixie-slim` pinned by digest, with `clang-19` and `lld-19` at `1:19.1.7-3+b1` from
  snapshot.debian.org `20261027T000000Z`; lld signs it ad hoc (arm64 macOS refuses unsigned
  code). It uses no Apple SDK, whose licence allows use only on Apple hardware. The output
  depends only on the two files: three builds (two from the worktree, one from a copy elsewhere,
  podman) gave `10556eeb31f2f280f90fc58b504c34370c0f40ac87e8fbdbbd9776cce8eb5f1a`. So the
  release job can build it on the Linux runner, and nobody pays for macOS minutes.
- **Tested on the Mac** (macOS 26, Apple silicon), the binary from `build.sh`:
  `packages/install/test/keyflap-launch.e2e.test.ts`, 8 tests, all passing. In a per-user domain
  (`gui/502`), with Node reading the fds through the real `listenFds`: names map to the right
  fds; a connection made while the job is not running is accepted by launchd at once and
  answered once the program is up (1 s later); after the program exits, launchd still holds the
  TCP port (binding it gives `EADDRINUSE`) and the next connection starts a new process; the
  program inherits fds 3 and 4 and nothing else. As root's LaunchDaemon (`UserName nobody`):
  `SockPathOwner`, `SockPathGroup` and `SockPathMode` are applied before the job runs, and a
  root-owned 0600 socket refuses our uid with `EACCES` (so macOS checks the socket file's mode
  on `connect()`, an M0 question); the program runs as `nobody` with the four fds; a LaunchDaemon
  without `UserName` and a process with gid or egid 0 are refused. Mutation-checked: a build
  without the gid checks fails the group-0 test. The same 8 pass with the binary Apple's
  clang 21 builds from the same source (Command Line Tools 26.6, now installed on the test Mac).
  Not yet run as a real `_keyflap-*` service user here: those came with the M3 installer, and
  the plist's `UserName` is the same mechanism as for `nobody`.
- **launchd behaviour M3 must design for** (measured on the Mac):
  - A socket with no `SockPathMode` is 0666. Every plist socket sets one.
  - `SockPathGroup 0` is ignored when `SockPathOwner` is also 0: the socket is `root:daemon`.
    Harmless for the 0600 admin sockets, but don't rely on group 0.
  - `bootout` leaves the socket files. The next `bootstrap` replaces a stale socket, but if a
    regular file sits at the path, `bootstrap` still succeeds and no socket is made. The socket
    directories must be root-owned so nobody else can plant one, and uninstall removes them.
  - `GroupName wheel` for a non-root `UserName` is silently not applied (the job ran as
    `nobody:nobody`), and `GroupName staff` set only the effective gid. The service plists
    rely on each service user's primary group and set no `GroupName`.
- **How to rerun.** On a Mac: `KEYFLAP_LAUNCH=/path/to/keyflap-launch pnpm vitest run --project
  e2e packages/install/test/keyflap-launch.e2e.test.ts`. Without `KEYFLAP_LAUNCH` it builds
  the source with the Command Line Tools if they are installed, and skips with that reason if
  they are not. `KEYFLAP_LAUNCH_SUDO=1` adds the three LaunchDaemon tests (passwordless `sudo
  -n`); they bootstrap jobs into `system` from a root-owned temp dir and remove them. Off
  macOS, all of it skips ("needs macOS").

## Service mode on macOS (S5): the installer (Mac M3, 2026-10-29)

Unit M3 of `docs/MAC_PLAN.md`: `packages/install/macos/` (`install.sh`, `uninstall.sh`, the
three LaunchDaemon plist templates in `launchd/`, `keyflap-wrapper.sh`), the darwin-arm64
release from `packages/install/linux/build-bundle.sh --os darwin|all`, and the code the Mac
facts of the M0 spike forced. Installed and running on the test Mac (macOS 26, Apple
silicon, FileVault on) from `keyflap-0.0.0-m3-darwin-arm64.tar.xz`: fresh install, two
upgrades in place, uninstall and reinstall over kept data, `--purge` and a fresh install again.
Linux is unchanged except `runtime-pins.sh` (below); `pnpm check` and `pnpm test:isolation`
pass. Every difference from the Linux installer:

- **Users.** `_keyflap-core`, `_keyflap-signer`, `_keyflap-web` through `dscl`: uid = gid, the
  first id in 450..499 that no user or group holds, shell `/usr/bin/false`, password `*`,
  `IsHidden 1`, home = the service's data dir, and the un-prefixed name as a second
  `RecordName` (`id keyflap-core` resolves). Idempotent by adding only missing attributes:
  TCC refuses `dscl -create` of an existing `UniqueID` or `NFSHomeDirectory` even to the same
  value (spike 1b), so a re-run reads them and dies on a mismatch. `uninstall.sh --purge`
  tries `dscl -delete`; from Terminal or ssh that fails with `eDSPermissionError -14120` and
  the script says so with the Full Disk Access fix and keeps the users (hidden, no shell, no
  password). Decision: keep them rather than fail the purge. On the Mac they are 452/453/454.
- **Code and runtime.** Same `/opt/keyflap/{app,node,browsers}` swap, plus
  `/opt/keyflap/libexec/keyflap-launch` (root:wheel 0755). Every copy is a fresh root-owned
  inode and `xattr -r -d com.apple.quarantine` runs on the stage before anything in it
  executes (spike 10b/10c: bsdtar, cp and install all keep the attribute, and a quarantined
  binary that once tried to exec stays blocked). Node is the darwin-arm64 tarball from
  nodejs.org, verified with `shasum -a 256` against `runtime-pins.sh`. Only the full
  `chromium-1248` is fetched (`playwright install --no-shell chromium`); macOS never runs the
  headless shell. The `.app` keeps its internal symlinks (`cp -R`); the setuid sweep uses
  BSD `find -perm -4000 -o -perm -2000`.
- **Credentials.** `/Library/Keyflap/credentials` root:wheel 0711, `credentials/<service>/`
  owned by that service user 0500, files 0400 owned by it: `signer/{kek,channel-key}`,
  `core/{channel-key,host-token}`, optional `signer/op-service-account-token`,
  `core/apns-key`, `approver/{approver-tls-cert,approver-tls-key}`. `CREDENTIALS_DIRECTORY`
  in each plist; `readCredential` accepts the layout unchanged (owner is not checked, mode
  0400 passes `credentialPrivate`). The KEK and the channel key are generated once; the core's
  channel-key copy is rewritten from the signer's on every run so the two stay equal (measured
  equal before and after an upgrade); the host token is reissued each run in both copies;
  optional secrets are removed when their option is absent. At rest they rely on FileVault;
  the installer reports FileVault off and does not refuse.
- **Directories.** `/Library/Keyflap/{etc 0755, data 0711, log 0711, run 0755}`; `data/<svc>`
  and `data/<svc>/tmp` 0700 per service (`HOME` and `TMPDIR` in the plist; the approver front
  gets `data/approver`, where Linux gives it `/`); `log/<svc>/<svc>.log` because launchd opens
  `StandardErrorPath` as the job user and a root 0700 log dir fails the job with EX_CONFIG 78
  (spike 6a/6b); `manager.ts` (`darwinLogFile`) and its tests follow. Socket dirs `run/core`
  root:wheel 0755, `run/signer` root:`_keyflap-core` 0750, `run/approver` root:`_keyflap-web`
  0750, root-made so nobody can plant a regular file where launchd would otherwise create a
  socket (M2). Logs are not rotated yet (a `newsyslog` rule would rotate a file Node keeps
  open; needs a reopen on `kickstart -k`): M7.
- **Plists.** `UserName` only (no `GroupName`, M2), `ProgramArguments` through
  `keyflap-launch --socket NAME… -- /opt/keyflap/node/bin/node … --config …`, `Sockets` with
  `SockPathName/Owner/Group/Mode` (decimal: 384 = 0600, 432 = 0660) for the five unix
  sockets, and for the approver two TCP entries `approver` (`SockNodeName` = the listen IP,
  `SockFamily` IPv4 or IPv6) and `approver6` (`::1`, kept only when the listener is the default
  `127.0.0.1`; the template block is dropped otherwise). `Umask 63`, `RunAtLoad`,
  `KeepAlive {SuccessfulExit false}`, `ThrottleInterval 2`, `ExitTimeOut 30`, `Core 0` hard
  and soft, `EnvironmentVariables` (`CREDENTIALS_DIRECTORY`, `HOME`, `TMPDIR`, `PATH`,
  `PLAYWRIGHT_BROWSERS_PATH` for the core). The installer fills the ids with `sed`, refuses an
  unfilled placeholder, lints with `plutil`, installs root:wheel 0644. Measured on the Mac: the
  admin sockets come out `root:daemon` 0600 (M2: group 0 is ignored with owner 0; harmless),
  the others exactly as the plist says; launchd holds `127.0.0.1:8766` and `[::1]:8766`
  and the front has both as fds 3 and 4; the core's `ps` shows `--headless` and no
  `--no-sandbox`.
- **Start, stop, upgrade.** `launchctl bootstrap system PLIST`, with `launchctl enable` only
  when a bootstrap is refused (its override entry is permanent, spike 11c). Upgrade: `bootout`
  each label, poll `launchctl print` until the job is gone (the core takes up to 30 s to save
  browser state), then `pkill -9 -u <svc>` and `launchctl bootout user/<uid>` for the per-uid
  agents macOS starts for a browser (spike 3c), replace the code, bootstrap. `--no-start`
  writes the plists and skips the bootstrap (launchd loads them at the next boot). Measured:
  `launchctl kill SIGKILL system/com.keyflap.core` is respawned 2 s later (`runs = 2`,
  `last terminating signal = Killed: 9`) and `kickstart -k` restarts it with MCP answering.
- **Stale Chromium.** `cli/src/service/stale-browser.ts`: at start under launchd, the core
  lists its own uid's processes (`/bin/ps -o pid=,command= -u UID`) and SIGKILLs those whose
  command starts with `$PLAYWRIGHT_BROWSERS_PATH/`, never itself. The selector is unit-tested
  (`cli/test/stale-browser.test.ts`) and was run on the Mac against live `ps` output as
  `_keyflap-core` (it picked the browser and its five helpers, not node or the agents). It
  found nothing to kill in the real cases: with Playwright 1.64.1 the Chromium of a
  SIGKILLed core exited within 2 s on its own (its `--remote-debugging-pipe` closes), as did
  one whose Playwright parent was `kill -9`ed; the spike's survivor (3b) was started another
  way. The sweep stays as the guard for a browser that does survive.
- **Chromium sandbox.** The shim takes `sandbox` (Playwright `chromiumSandbox: true`), the
  daemon `browserSandbox`, and `core-main.ts` sets it under launchd (spike 2b: works as a
  hidden user). Linux keeps Playwright's default (`--no-sandbox`; the systemd sandbox contains
  the browser there).
- **Approver port, both families.** `ApproverFront` listens on every fd it is given
  (`listen: { fds: number[] }`; one `http.Server` per fd, the first names `listenUrl`, hosts
  of all are allowed), and `approver-main.ts` passes `approver` and, when present,
  `approver6`. Measured as a third uid: `bind 127.0.0.1:8766` and `bind [::1]:8766` both
  `EADDRINUSE`. Linux units are unchanged (one listener; the spike's 5d note that the v6 twin
  is bindable there too is open for the Linux installer).
- **The wrapper.** `/usr/local/bin/keyflap` is `exec /usr/bin/env -i KEYFLAP_MODE=service
  PATH=/usr/bin:/bin:/usr/sbin:/sbin SUDO_UID SUDO_GID SUDO_USER TERM LANG node … main.ts`:
  macOS sudo has no `secure_path` and keeps `HOME` (spike 7), so nothing from the caller's
  environment reaches the root process. The installer creates `/usr/local/bin` root:wheel 0755
  when missing (it is absent on a fresh Mac) and refuses when `/usr/local` or `/usr/local/bin`
  is not root-only (Intel Homebrew made it user-owned). The installer's own text says `sudo
  /usr/local/bin/keyflap …`; the CLI's `fix:` strings still say `sudo keyflap …` on both
  platforms (a `ServiceManager` field would fix that in one place: M7).
- **Checks before anything changes.** `uname -m` must be `arm64` (Intel: "not supported yet"),
  `RELEASE` must say `os=darwin arch=arm64`, macOS 14 or later (measured on 26 only), the
  macOS tools, the bundle, the launcher (Mach-O magic), every input root-only (`chain_problem`
  walks the parents with BSD `stat -f %u %Lp`; `not_root_only` adds a `find` over a directory),
  `/usr/local[/bin]` and `/opt/keyflap` root-only chains, Node from the release or
  `--node-tarball` or a `curl` download, `--browsers-dir` with `chromium-1248`, and the Linux
  option checks (user, TLS, APNs, password sources). `tool_problem` additionally refuses a
  quarantined `pass-cli`/`op` with the `xattr -d` fix. `--xvfb` and `--headless` are refused
  as Linux-only. There is no systemd-style "stop a running install" for the sockets: `bootout`
  takes the sockets with the job.
- **bash 3.2.** No associative arrays (`runtime-pins.sh` now has plain
  `NODE_SHA256_<os>_<arch>` variables and `node_sha256 OS ARCH`; the Linux scripts use it
  too), no `arr+=()` (an empty array breaks `set -u` in 3.2: index assignment instead),
  parallel arrays for the agent-token carry-over, `sudo -u` for `runuser`, `stat -f` for
  `stat -c`, `shasum -a 256` for `sha256sum`. `packages/install/test/macos-installer-shell.test.ts`
  greps the scripts for the bash 4 and GNU constructs and runs `bash -n`;
  `cli/test/service-paths-installer-darwin.test.ts` pins `DARWIN_SERVICE_PATHS`, the socket
  names, the config paths, the log files, the credential dirs and the wrapper against the
  templates and `install.sh`, the way the Linux twin does.
- **Release.** `build-bundle.sh --os darwin|all [--launcher FILE]` reuses the OS-independent
  bundle, adds the darwin Node tarball (SHA-256 pinned) and `keyflap-launch` (built by
  `packages/install/macos/launcher/build.sh` in the pinned container unless `--launcher` names
  a build; the Mach-O magic is checked), and lists everything in one `SHA256SUMS`. `RELEASE`
  gains `os=`. `release.yml` builds `--os all --arch all` in the Linux job (docker is on the
  runner; no macOS minutes), calls `packages/install/bootstrap/make-bootstrap.sh dist VERSION`
  when M5 has added it, and uploads `dist/*`.
- **Measured on the Mac** (full transcripts in the M3 report). Jobs `state = running` with
  `username = _keyflap-{signer,core,web}`, `ps` shows node and Chromium under those users;
  `doctor` passes every check that can pass before pairing (mode, node, units, sockets,
  signer, agents, mcp, chromium, headed, audit); `agent add mac-test` then MCP `initialize`
  with the token answers 200 and 401 without; a third uid (`_kfspike2`) and the admin user
  cannot read the KEK, host token, key store, database or logs, cannot list `credentials` or
  `data`, cannot write under `/opt/keyflap` or the wrapper, get `EACCES` on all five sockets,
  `EADDRINUSE` on both 8766 binds, and see no environment with `ps eww`. First start after a
  fresh Chromium download took under 20 s here (the spike's 30 s first-exec scan is the
  budget). The admin user (in `staff`, `admin`) can read only its own hook dir, by design.
- **Left for later.** Log rotation (M7); `sudo keyflap` wording in the CLI's fixes (M7); the
  `::1` twin on Linux (spike 5d); `password-source trust` stripping quarantine (M7 or the
  setup unit); the "Background Items Added" notification and a doctor check that the items
  stay allowed (`sfltool dumpbtm`); M4 should probe exactly the list above from a third uid,
  plus `argv` secrecy (`ps -o command=` across uids is readable, spike 4b).

## Isolation suite on macOS (Mac M4, 2026-10-29)

Unit M4 of `docs/MAC_PLAN.md`: `packages/isolation` runs on a real Mac against the real
installer, as root, and probes the install from a third uid. Run on the test Mac (macOS 26,
Apple silicon): 29 tests pass, 9 Linux-only skipped, in about 110 s; the Linux container run
still passes its 26 (10 macOS-only skipped). No probe found an isolation hole.

- **How it runs.** `KEYFLAP_MAC=user@host packages/isolation/darwin/run-on-mac.sh` on Linux
  builds `keyflap-0.0.0-isolation-darwin-arm64.tar.xz` (`build-bundle.sh --release --os darwin`:
  GNU tar and the pinned launcher container, which a stock Mac lacks) and a source bundle,
  rsyncs the checkout to `/Users/Shared/keyflap-isolation` (home directories are closed to other
  users on macOS, and the probe uid has to read the probe scripts), runs `pnpm install` there and
  then vitest with `KEYFLAP_ISOLATION_ARTIFACTS`. On darwin, `global-setup.ts` hands over to
  `setup-darwin.ts`, which needs `sudo -n` and those artifacts and otherwise skips with the
  reason (`KEYFLAP_ISOLATION_REQUIRED=1`, which the runner sets, makes that a failure). Nothing
  here runs in `pnpm test`. It does not use the Command Line Tools: no `python3`, `lldb` or
  compiler.
- **What setup does.** Copies the release, the source bundle, `packages/install` and the cached
  `chromium-1248` into `/var/root/keyflap-isolation` (root:wheel 0700), checks `SHA256SUMS`,
  unpacks; purges any existing install with the release's `uninstall.sh --purge`; runs
  `install.sh` from a `_kfprobe`-owned copy (refused, nothing changed) and with `--xvfb`
  (refused, nothing changed); installs with `--user _kfprobe --approver-origin
  http://approver.localhost:8766 --high-risk rp.localhost`; starts the test RP and the simulated
  phone (the Linux `phone.ts`, as the admin user, its own headless shell) and pairs it; adds the
  agent, plants the same hook-dir decoys as Linux; upgrades in place from the source bundle
  (`packages/install/macos/install.sh --bundle --launcher --node-tarball`, the documented
  source install); then `uninstall.sh` and a reinstall from the release over the kept data.
  Teardown runs `uninstall.sh --purge` and fails the run if any of `/opt/keyflap`,
  `/Library/Keyflap`, the plists, the wrapper, a `com.keyflap.*` job or a process of a service
  user is left; it also removes the stage, the probe's scratch dir and `/usr/local/bin` if
  empty (a fresh Mac has none; the installer creates it and `uninstall.sh` keeps it).
  `KEYFLAP_ISOLATION_KEEP=1` skips the purge for debugging.
- **The probe uid.** `_kfprobe`: hidden, `UserShell /usr/bin/false`, `Password *`, home
  `/var/empty`, the highest free id below 500 (499 here, away from the installer's 450 upward),
  primary group `staff` like a real account, so anything group-staff readable would show.
  Created idempotently by adding only missing attributes (the installer's TCC rule) and never
  deleted (TCC refuses `dscl -delete` over ssh). Not `_keyflap-probe`: `install.sh` refuses a
  `--user` matching `_keyflap-*`, and it would read as a service user. It is the install's
  `--user`, the uid an agent runs as, so the intent socket and hook dir are legitimately its
  own, as `agentuser`'s are on Linux. The admin account that ran the install (in `admin`, `staff`
  and `_developer`, passwordless sudo aside) is probed as well, and is refused the hook dir and
  the intent socket too.
- **One body, two layouts.** `test/platform.ts` holds per OS the paths (data, credentials, logs,
  sockets, configs, unit files or plists), the users, what must be unreadable, what must exist
  and what must be immutable, plus `servicePids`, `restartCore` (`systemctl restart` or
  `launchctl kickstart -k`), `waitReady`, `owner`, `sha256` and `auditEvents`. The Linux values
  are the old literals moved, not changed. Tests that differ by mechanism branch on `L.os`
  inside the same file under the same names; the OS-only describes say "(macOS only)" or
  "(Linux only)" when skipped. New on Linux: the core's uid can't connect to the core admin
  socket, the user's uid can connect to its intent socket, and the page's owner checks name the
  group too.
- **Process probes and their controls** (`probe/darwin-process.ts`, run as the probe uid with
  the installed Node). Measured on the Mac before relying on them: a non-admin uid can `vmmap`,
  `sample` and `lsof -p` its own child and see its environment with `ps eww` when the child is
  the installed Node, but `ps eww` shows no environment for its own `/bin/sleep` (a platform
  binary), and `task_for_pid` fails on its own children (hardened Node, platform binaries) but
  returns 0 on itself. So the control is a Node child carrying a random marker in its
  environment (vmmap, sample, lsof, kill -0, ps eww) and the probe's own pid (task_for_pid). The
  core, signer, front and Chromium each give vmmap and sample "do not have appropriate
  privileges", an empty `lsof`, `EPERM` on kill -0, no environment (`ps eww` equals `ps ww`) and
  `kr=5`; root's `ps eww` of the core shows `CREDENTIALS_DIRECTORY=`, so the environment is there
  to hide. `sample` gets `-file /dev/null` because it otherwise leaves a report in `/tmp`.
- **argv.** `ps` shows every uid's command lines (spike 4b), so the test reads the KEK, both
  channel-key copies and the host token as root and checks that none of them (hex, base64,
  base64url, or the text) and not the agent token is in any line of a `_keyflap-*` process,
  after checking that the core, signer and Chromium lines are visible to the probe.
- **Invariant 7 without `/proc`.** Root's `ps` gives the browser's command line
  (`--remote-debugging-pipe`, no `--remote-debugging-port`, `--headless`, no `--no-sandbox`, the
  full `Google Chrome for Testing.app`); `lsof -iTCP -sTCP:LISTEN` shows no listener in the
  tree of `_keyflap-core` processes under `/opt/keyflap/browsers/`, and the service users
  listen only on 8765 and 8766, neither of which answers `/json/version` as DevTools. There is no
  X display on macOS, so the Linux display test has no twin; the headless check stands in.
- **Invariant 5.** launchd (pid 1) holds `127.0.0.1:8766` and `[::1]:8766`; the core's uid gets
  `EADDRINUSE` on those and on `0.0.0.0` and `::`, also right after the front is `kill -9`ed,
  and the next request is answered by a new front. Linux stops the unit instead; on macOS
  `bootout` would release the port with the job, but no service uid can boot a system job out.
- **Mutation checks.** On the kept install, opening `credentials/signer` to 0555 and the KEK
  to 0444 made the probe's read of the KEK `ok`, and `run/signer` 0755 with the socket 0666 made
  its connect `ok`; both back to `EACCES` once restored.
- **Found and fixed.** `packages/install/macos/install.sh` sourced `runtime-pins.sh` only from
  its own directory, so the documented source install (`packages/install/macos/install.sh
  --bundle …` from a checkout) stopped at once; only the release tarball has the file there. It
  now falls back to `../linux/runtime-pins.sh` and refuses that file unless it is root-only.
- **Differences from Linux, not holes.** The signer has network on macOS (launchd has no
  `RestrictAddressFamilies`); the Linux test of that has no darwin twin. `uninstall.sh` leaves
  `/usr/local/bin`, which a fresh Mac lacks (M7). The admin user is a sudoer, so it is root in
  all but name; the probes show only that its uid, without sudo, gets nothing.
- **Not covered.** A reboot (`/Library/Keyflap/run` and launchd's sockets after one); the
  "Background Items" switch being turned off; a probe from the console user's GUI session
  (TCC, WindowServer); Intel Macs.

## Agent-led setup and the one-command install (2026-10-29)

Unit M5 of `docs/MAC_PLAN.md`: the owner's two ways in from keyflap.com ("Mac works like Linux",
DECISIONS.md) do the same thing. The agent prompt points the agent at
`docs/INSTALL_FOR_AGENTS.md`, which checks the machine and hands the user one command; the user
can also run that command without an agent. Nothing in section 5 of ARCHITECTURE.md changes.

- **The command is `curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | sudo bash`.**
  The `latest/download` URL is stable across releases and needs nothing from keyflap.com (a
  redirect there can come later without changing what runs). `sudo` asks for the password on
  the terminal, not on stdin. The whole script is one `main` function, called on its last line
  as `main "$@"; exit $?`, so a download cut off anywhere runs nothing, and bash never reads
  the rest of the pipe as commands after `main` returns. The script never reads stdin, which is
  the download: questions use `/dev/tty`, the tools that could read stdin get `</dev/null`
  (`curl`, `tar`, `tailscale`) or `</dev/tty` (`install.sh`, setup), and a real install refuses
  when there is no terminal. `sudo bash -c "$(curl …)"` was the
  alternative: the same trust, harder to read, and the script in root's argv.
- **What is checked, and by whom.** `packages/install/bootstrap/make-bootstrap.sh DIST_DIR
  VERSION` writes `install-keyflap.sh` from `install-keyflap.sh.in` with the SHA-256 of each
  `keyflap-V-{darwin-arm64,linux-x64,linux-arm64}.tar.xz` listed in `SHA256SUMS` (each checked
  against the file on disk), then adds the installer's own line to `SHA256SUMS`, so the release
  attestation (`subject-checksums: dist/SHA256SUMS`) covers it too. The installer refuses a
  tarball whose hash differs and deletes it unopened, before it unpacks or changes anything.
  The installer itself is fetched by the user's `curl` in the user's shell: an agent that
  already controls that shell's startup files can swap it, or `sudo` itself. That is the
  residual the "gated list belongs to the owner" gate in DECISIONS.md names, not something a
  script can close. A user who wants the stronger check downloads it, runs `gh attestation
  verify install-keyflap.sh --repo johnpippett/keyflap`, then `sudo bash install-keyflap.sh`.
- **Root hygiene.** As root the installer sets `PATH=/usr/bin:/bin:/usr/sbin:/sbin` (macOS
  `sudo` keeps the user's `PATH`), unsets `CURL_HOME`, `TAR_OPTIONS`, `XZ_*`, `BASH_ENV` and
  `ENV`, runs `curl -q` (no `.curlrc`, which could name an output file) with
  `--proto =https --proto-redir =https --tlsv1.2`, and runs `tailscale` as root only if the
  binary and every directory above it belong to root and nobody else can write them (sticky
  directories allowed). Any other Tailscale CLI it runs as `$SUDO_USER` (`sudo -n -u`), so
  nothing the user's uid can replace ever runs as root. It downloads into `mktemp -d
  /opt/keyflap-release/.download.XXXXXX`, refusing a `/opt/keyflap-release` that is a link or
  not root-only, unpacks there as root, and moves `keyflap-V-OS-ARCH/` next to it, where
  `uninstall.sh` stays. `install.sh` repeats its own root-only check on that directory.
- **Platform choice.** `uname -s`/`-m` picks the tarball. `Darwin x86_64` is refused ("Intel
  Macs are not supported yet") unless `sysctl -n hw.optional.arm64` is `1` (bash under
  Rosetta on Apple silicon). A machine whose tarball the release lacks is refused before any
  download, with the list it does have.
- **Approver origin.** `tailscale status --json --peers=false` prints one `DNSName` (Self);
  the installer takes it if `BackendState` is `Running` and the name is in `CertDomains`, and
  uses `https://<name>:8766`. It parses with `sed` (no `jq` on Linux by default) and fails
  closed: zero or two names, or a name that isn't a hostname, means it asks. On a Mac the CLI
  is `/Applications/Tailscale.app/Contents/MacOS/Tailscale`. `/Applications` is `root:admin
  0775` (seen on the test Mac, macOS 26), so an admin user, and an agent running as one,
  can swap the app; the installer therefore asks it as the user. Its answer is then only as
  trustworthy as the user's account, which is no worse than today: see the open item below.
  Without an origin it explains Tailscale and asks on the terminal.
- **The password manager is asked by the installer, not by setup,** because in service mode
  Proton Pass and 1Password are `install.sh` options. The default is the one recorded from the
  last run, else 1Password if `op` is in a place `install.sh` trusts, else Proton Pass if
  `pass-cli` is, else the Apple Passwords import on a Mac, else none. If the tool is missing
  from `/opt/keyflap/tools/<cmd>/`, `/usr/local/bin` and `/usr/bin` (the paths `install.sh`
  searches), it says how to install it and offers to go on without it, rather than letting
  `install.sh` refuse the whole install. `install.sh` reads the 1Password token from
  `/dev/tty` itself. The import of an Apple Passwords export happens in setup.
- **Re-running upgrades with the same answers.** After `install.sh` succeeds the installer
  writes `/opt/keyflap-release/bootstrap.conf` (origin, password source, vault; no secrets),
  read back line by line without `source`, each value checked. It refuses to upgrade a
  service-mode install it did not make (no `bootstrap.conf`): `install.sh` rewrites the whole
  configuration from its options, so an upgrade with fewer options would drop the owner's
  `--high-risk` entries or TLS settings.
- **The test override can't reach a real install's trust.** `KEYFLAP_RELEASE_BASE` is honoured
  only when it matches `^http://(127\.0\.0\.1|\[::1\]):PORT(/path)?$` (so not
  `http://127.0.0.1:1@evil.example`), anything else set is a refusal, and the pinned hashes
  still decide what is accepted. `--dry-run` downloads, checks and unpacks into
  `mktemp -d $TMPDIR/keyflap-dry-run.XXXXXX`, removes it, and prints the `install.sh` command.
  It works as any user and never touches `/opt`. There is no install-root override: a real
  run always uses `/opt/keyflap-release`. `packages/install/test/bootstrap.test.ts` serves a
  fake three-platform release on 127.0.0.1 and runs the generated installer with a fake
  `uname`, `sysctl` and `tailscale` on `PATH`, which works only because it runs as non-root (it
  is skipped as root, where the `PATH` reset ignores them). It shows the asset choice per
  machine, refusals before any request (Intel Mac, other systems and processors, a release
  without this machine's build, a non-loopback override, not root), a tampered tarball refused
  with nothing left behind and `install.sh` never run, the script working from a pipe, a cut-off
  script running nothing, and the `make-bootstrap.sh` pins and refusals. Bash 3.2: a lint in
  the test rejects bash-4 syntax, and the dry run ran under macOS's `/bin/bash` 3.2.57.
- **Setup runs on the terminal, not on a pipe.** The installer runs
  `/usr/local/bin/keyflap setup </dev/tty >/dev/tty 2>&1`. Setup itself is unchanged in that
  respect: it still refuses when stdin or stdout isn't a terminal, so nothing can drive it
  through a pipe. Reopening `/dev/tty` inside setup was the alternative; it would have made
  setup accept piped input whenever any terminal exists.
- **Setup pre-selects what it detects; every change still waits for `y`.** The agent host
  menu marks the hosts it finds (`~/.claude` or `~/.claude.json`, `~/.codex`, `~/.hermes`) as
  installed and defaults to the first of Claude Code, Codex, Hermes found. Run from the home
  directory (as after the one command), the Claude Code scope defaults to all projects. In
  service mode the credentials step defaults to the configured password source, else to the
  import when nothing is stored. The questions that write or run something keep their
  `[y/N]` default: "Apply these changes?", "Run it?" (`tailscale serve`) and "Log in now?".
- **Tailscale CLI in setup.** In service mode setup looks only at `/usr/bin`, `/usr/sbin`,
  `/usr/local/bin` and the macOS app path, never `PATH` (the same macOS `sudo` reason as
  `id -P` above). It runs a root-only one as root and any other, such as the Mac app, as the
  install user, for `status` and for the `tailscale serve` it offers. In dev mode it uses
  `tailscale` on `PATH`, else the macOS app CLI.
- **The user's uid can repoint `tailscale serve`; Keyflap now watches it.** The approver
  integrity plan keeps the core off the approver port, but the HTTPS front most installs use is
  `tailscale serve`, and whoever may change its configuration decides what answers at the
  approver origin. On a Mac the GUI app gives that to every local user (and to
  `_keyflap-core`); on Linux it is root, or the user after `tailscale set --operator=$USER`.
  Confirmed on the test Mac on 2026-10-29. Owner's call (DECISIONS, "The approval address"): a
  tripwire inside Keyflap, an address only Keyflap controls next. Built and its residuals:
  "Approval-address tripwire" below.
- **Import in setup.** Step 5 gains "Import an export" (option 4; "Nothing" moved to 5). It
  reads the file as the user through `readUserFile` (no links, the user's own file, 4 MiB cap),
  accepts a path dragged into Terminal (quotes, backslash escapes, `~/`), shows the
  `formatLogins` table (site, username, TOTP yes or no; never a password), asks which sites
  (blank: all), stores only after `y` through the backend's `addPassword`, and prints
  `runImport`'s reminder to delete the file. It parses the file once, so what is stored is what
  was shown (the CLI needs `--expect` for that across two commands). `Backend.passwordCount`
  became `storedLogins` (site, username, native), which also feeds the import's duplicate check.
- **What M3 must match.** The installer expects each darwin and linux tarball to unpack to
  `keyflap-V-OS-ARCH/install.sh` (and `uninstall.sh`), taking `--approver-origin`,
  `--password-source proton-pass|1password`, `--proton-pass-vault`, `--1password-vault` and,
  on Linux only, `--headless`; `--user` defaulting to `$SUDO_USER`; the 1Password token read
  from `/dev/tty`; the wrapper at `/usr/local/bin/keyflap`; and, on a Mac,
  `/Library/LaunchDaemons/com.keyflap.core.plist` present once installed. `release.yml` should
  run `packages/install/bootstrap/make-bootstrap.sh dist "${TAG#v}"` after the last tarball and
  before the attest step, and upload `dist/install-keyflap.sh` with the tarballs.

## Simple Mac install (Mac M6, 2026-10-29)

Unit M6 of `docs/MAC_PLAN.md`, the README roadmap's "one installer that does not need `sudo` …
It will say clearly that it protects less". It is dev mode (`keyflap daemon --unprotected`,
same uid, D6) packaged for a Mac: no section 5 invariant changes, and nothing in it is the
default (DECISIONS.md "Security beats convenience"). User guide:
`docs/integrations/simple-mac-install.md`. Decisions and what was measured:

- **How it is reached.** `install-keyflap.sh --simple`, run as `curl … | bash -s -- --simple`.
  The same script, the same pinned SHA-256 and the same refusals as the full install, with
  three more: `--simple` under sudo is refused (it names the command without sudo and the full
  install), `--simple` off macOS is refused, and so is `--simple` when the full install is on
  the Mac. The full install without sudo now also names the simple command. Before anything is
  downloaded the person reads the notice and must type `y` (default no). The tarball goes to
  `mktemp -d $TMPDIR/keyflap-simple.XXXXXX` as the user, and the release's
  `install-simple.sh --confirmed` and then `bin/keyflap setup` run on `/dev/tty`.
- **The label is one sentence, in one place.** `PROTECTS_LESS` in `cli/src/simple-install.ts`:
  "The simple install protects less: an agent that can run commands as you can read Keyflap's
  files and change its code. The full install stops that." It heads `keyflap status` (and
  `install`/`protectsLess` in `--json`), is doctor's `protection` warning (fix: the uninstaller,
  then the full-install command), heads setup and its finish summary, and is the daemon's
  banner in place of "Development only" (its `daemon.unprotected` audit entry gains
  `install: "simple"`). The two shell installers carry the same sentence; a test fails if any
  copy drifts.
- **Code** in `~/Library/Application Support/Keyflap/{app,node,browsers,bin/keyflap,uninstall.sh}`,
  copied by `packages/install/macos/install-simple.sh` (bash 3.2, in the darwin tarball). Same
  as the full installer: Apple silicon and macOS 14+ only, Node checked against
  `runtime-pins.sh`, `xattr -r -d com.apple.quarantine` on each fresh copy before anything in it
  runs, and no bundle symlink may point outside the app. Re-running it upgrades in place: it
  stops the job, swaps `app`, `node` and `bin`, keeps `browsers` when the pinned revision is
  there, and starts the job again. `bin/keyflap` sets `KEYFLAP_MODE=simple` and
  `PLAYWRIGHT_BROWSERS_PATH` and runs the installed Node; it is not put on `PATH` (no
  user-writable directory on a stock Mac is on it), so docs and messages give its full path.
- **Headless shell only.** It installs `playwright install --only-shell chromium`, so the daemon's
  default headless launch works unchanged and no new daemon flag was needed. Decision: no
  window, as in the full Mac install; human checks go to the phone's live view. Doctor's
  `headed` check reports this as the design.
- **Data in `~/.keyflap`**, the dev-mode default, so every CLI command, the hook and the
  `mcp-headers` helper find it without `--data-dir`, and setup's Claude Code deny rules cover it
  as in dev mode. A `~/.keyflap` whose key store a passphrase unlocks is refused (by
  `install-simple.sh` and by the key-file code) with `mv ~/.keyflap ~/.keyflap.dev`. A sibling
  dir would have avoided that collision but needed a data-dir default per mode in the CLI and
  an explicit `--data-dir` in every hook command.
- **The key file.** `~/.keyflap/unlock.key`: 32 random bytes, 0600, made with `O_EXCL` and
  `O_NOFOLLOW`. Its base64url form is the key store's passphrase, the way service mode feeds its
  KEK to `KeyStore.open`, so `keystore.ts` doesn't change. Rules (`cli/src/key-file.ts`): a data
  dir that has the file is unlocked by it, everywhere `getPassphrase` and setup's passphrase
  step run (so `password add`, `approver list` and the rest need no passphrase); the file must
  be a regular file of yours, mode 0600, exactly 32 bytes, else a refusal; it is created only
  when `KEYFLAP_MODE=simple` (the wrapper and the plist set it) and never next to an existing
  key store; a key file plus `KEYFLAP_PASSPHRASE` is a refusal. The plist and every command line
  hold the data dir only, never the key.
  - **Why this is no weaker than dev mode against an agent running as you.** In dev mode that
    agent already gets the passphrase: it can read the daemon's memory, edit the code the next
    start runs, or alias `keyflap` and fake the prompt (ISOLATION_PLAN "The problem,
    concretely"). The key file saves it a step, not a barrier.
  - **Where it is weaker.** A copy of `~/.keyflap` alone (a backup, Time Machine, a sync tool)
    now opens the store; in dev mode the copy also needed the passphrase. FileVault covers a
    stolen disk; the installer reports it off and does not refuse, as the full install does.
  - **What it doesn't protect at all.** Files, code, memory and the browser profile, against
    anything running as you: the label says so.
- **The LaunchAgent** `~/Library/LaunchAgents/com.keyflap.simple.plist` (0644, written by setup
  from its state, `cli/src/simple-install.ts` `launchAgentPlist`): `ProgramArguments` = the
  installed Node, `--disable-warning=ExperimentalWarning`, the installed `main.ts`, then
  `daemonCommand(state)` (`daemon --unprotected --approver phone --approver-origin …`, the MCP
  port, the password source with its absolute `pass-cli` path). `EnvironmentVariables` holds
  `KEYFLAP_MODE`, `PATH` (Homebrew first, then the system dirs) and `PLAYWRIGHT_BROWSERS_PATH`;
  `RunAtLoad`, `KeepAlive {SuccessfulExit false}`, `ThrottleInterval 10`, `ExitTimeOut 30`,
  `ProcessType Background`, `Umask 63`, stdout and stderr to `~/Library/Logs/Keyflap/daemon.log`.
  It is bootstrapped into `gui/<uid>` (it needs a login session; the error says so) and stopped
  with `bootout`, polling `launchctl print` until it is gone.
- **Setup in simple mode** (`KEYFLAP_MODE=simple`, no `--unprotected` needed: the person agreed at
  install). Phone approver only (no terminal to approve on). Before pairing or storing a
  password, it offers to stop the background job (default yes) instead of asking you to press
  Ctrl-C somewhere; the finish step asks "Run Keyflap in the background now, and every time you
  log in?" (default yes), writes the plist, starts it, waits up to 90 s for the intent socket,
  then prints doctor, the walkthrough, the label, the command path, the uninstaller and the
  full-install command. 1Password is not offered: its service account token would have to sit in
  a file any agent running as you can read, so setup points to Proton Pass, an export or the full
  install. Doctor in a key-file data dir reports mode `simple`, adds `protection` and
  `background` (the job is loaded) and gives `launchctl kickstart -k gui/<uid>/com.keyflap.simple`
  as the daemon fix; the checkout-in-project warning (`hook-code`) is replaced by the label.
- **Uninstall.** `uninstall.sh` (as you; sudo refused) boots the job out, kills a leftover headless
  shell under the app's `browsers/`, removes the plist, the log dir and the app dir, and keeps
  `~/.keyflap`; `--purge` removes it too. It leaves Claude Code's MCP entry and hook and says how
  to remove them (setup made backups).
- **Simple to full.** The full Mac installer (`macos/install.sh`) and the bootstrap's root path
  refuse while the person's simple install exists (its plist or app dir), naming the uninstaller.
  No key migration, by decision: those keys were readable by every process running as the user,
  and moving them would put possibly-copied keys behind the boundary that promises they never
  were readable. Phone, agents and passwords are set up again; passkeys made in the simple install
  are not carried over.
- **Never next to the full install.** The bootstrap and `install-simple.sh` refuse while
  `/Library/LaunchDaemons/com.keyflap.core.plist` exists. A test-only override used once on the
  test Mac was removed before merge: a shipped switch that runs a second broker beside the full
  install earns nothing.
- **Tests (Linux).** `cli/test/simple-install.test.ts`: key file creation (0600, 32 bytes,
  same passphrase every time), refusals (mode, link, size, owner, next to a passphrase store),
  the daemon unlocking without a terminal and refusing a passphrase too, the plist (arguments,
  escaping, no secret), the label in status and doctor, and setup's simple finish, stop, phone-only
  and 1Password steps. `install/test/bootstrap.test.ts`: `--simple --dry-run` on a Mac, refused
  under root (`unshare -r`, where user namespaces exist), off macOS and without a terminal, the
  full install's message naming `--simple`, and the full install refusing over a simple install
  (fake `dscl`). `install/test/simple-install-shell.test.ts`: `install-simple.sh` refusals before
  it writes anything, and `uninstall-simple.sh` with and without `--purge`. Both new scripts are
  in the bash-3.2 and BSD lint.
- **Measured on the test Mac** (macOS 26, Apple silicon, FileVault on, a non-admin
  account, no sudo; the M4 full install was running, so MCP 18765 and approver 18766). The
  bootstrap with a loopback release: the notice, default no ("Nothing was installed."), `y`, the
  download checked, and `install-simple.sh` refusing the account's existing passphrase store with
  the `mv` hint; after the move, installed (Chromium headless shell downloaded), then setup to the
  pairing link (`http://localhost:18766/pair#…`; no phone was available), agent `mac-simple`, and
  the job started. `launchctl print gui/502/com.keyflap.simple`: `state = running`; `ps`: the
  daemon's parent is pid 1, tty `??`; its environment holds `KEYFLAP_MODE=simple` and no secret;
  `unlock.key` 32 bytes, 0600; `plutil -lint` OK. MCP `initialize` with the agent token 200,
  without 401. `keyflap status` and `doctor` print the label (`doctor --json` mode `simple`).
  `launchctl kickstart -k`: new pid, `runs = 2`, MCP 200 again within 5 s; `kill -9`: respawned
  (`runs = 3`, `last terminating signal = Killed: 9`). An upgrade in place by running the new
  tarball's `install-simple.sh` while the job ran: stopped, swapped, started, agent and audit
  chain kept. `uninstall.sh`: no job, no plist, app dir, log dir or process; `--purge`: no
  `~/.keyflap`. The account's own `~/.keyflap` was put back and the test files removed.
- **Open.** The full installers' refusal over a simple install was not run on the Mac (it needs
  sudo, and the M4 install was live); it is unit-tested. The `keyflap` command is not on `PATH`.
  The daemon log keeps the terminal line "Ctrl-C to stop.". README's roadmap item and
  `INSTALL_FOR_AGENTS.md` don't mention the simple install yet (M7). Time Machine backs up
  `~/.keyflap` with its key file (see "Where it is weaker").
- **Closed by M7 (2026-10-29).** The simple daemon's log names
  `launchctl bootout` and the uninstaller instead of Ctrl-C (`simpleStopHint`), and README and
  `INSTALL_FOR_AGENTS.md` mention the simple install (the guide only when asked; a test holds its
  wording). M7 first made every Mac CLI fix say `sudo /usr/local/bin/keyflap …`
  (`ServiceManager.sudoKeyflap`; `checkTool` took it as data); see "`sudo keyflap` on a Mac
  (2026-10-30)" below.

## Approval-address tripwire (invariant 5, 2026-10-30)

DECISIONS.md, "The approval address": Keyflap can't lock Tailscale, so it watches the serve
setting and stops approvals when it points anywhere else. Code: `signer/src/approver-address.ts`
(compare, state machine, `ApproverAddressWatch`), the gates in `signer/src/server.ts`, the latch
in `signer/src/keystore.ts`, `approver/src/address-sync.ts` (the core's reaction),
`cli/src/approver-address.ts` and `cli/src/service/address.ts` (status, doctor, pair).
User docs: `docs/integrations/phone-approver.md` ("The approval address is watched") and
`service-mode.md`.

- **The watcher is in the signer.** `_keyflap-core` can change serve on a Mac, so the core can't
  be the one that reports it. The signer reads the serve config itself, one of two ways
  (`approverAddress.tailscale.via`): `cli` runs `tailscale serve status --json` (execFile, no
  shell, 5 s timeout then SIGKILL, 1 MiB output cap); `localapi` asks tailscaled's LocalAPI over
  loopback (`signer/src/tailscale-localapi.ts`, below; same timeout and cap). Both feed the same
  `compareServeConfig`. Zero npm dependencies, as before (`node:http`).
- **Which `tailscale`.** Service mode: `approverAddress.tailscale.bin` in `signer.json`, checked
  on every run by the same root-only rules as `pass-cli` and `op` (`@aab/sources` `checkTool`:
  a system bin directory or `/opt/keyflap/tools/tailscale/`, root-owned all the way up, no group
  or other write, no symlink), no SHA-256 pin. `install.sh` takes `--tailscale-bin PATH`; for a
  `*.ts.net` origin without it, the first of `/usr/bin`, `/usr/sbin`, `/usr/local/bin` that
  passes. **Deviation from the first build:** that build accepted the Mac app's own CLI at
  `/Applications/Tailscale.app/Contents/MacOS/Tailscale` by exact path with a SHA-256 pin
  (`ToolSpec.alsoAllowed`, `keyflap approver trust tailscale`). `/Applications` is `root:admin
  0775`, so an admin user can rename the bundle in and out; the pin was checked by path and the
  run was a second lookup by path, so a swap between the two ran the agent's code as the signer
  uid, and a swap between `lstat` and the read cached the genuine hash under the fake file's
  key. Both are gone: the Mac installer verifies the app (`codesign --verify --strict --deep`,
  `TeamIdentifier=W5364U7YZB`), copies it with `ditto --noacl` into a root-only staging
  directory, verifies the copy again, and moves it to `/opt/keyflap/tools/tailscale/Tailscale.app`;
  the signer runs that copy. Re-running the installer refreshes it after an app update.
  `toolSha256` now hashes through one `O_NOFOLLOW` descriptor and keys its cache on that
  descriptor's `fstat`, for every tool. It caches a hash only when the file last changed more
  than 3 s before that `fstat` (git's racy-clean rule): a same-size rewrite inside the
  filesystem's timestamp granularity leaves the whole key unchanged (a review found it on ext4,
  kernel 6.12), so a file that just changed is hashed again on every read. Dev mode runs `tailscale` from `PATH`, else the app's CLI
  (same uid: nothing to protect from).
- **On a Mac: the LocalAPI, not a CLI. Deviation from the second build (the app copy above), on
  2026-10-30.** On the test Mac (standalone Tailscale, bundle `io.tailscale.ipn.macsys`, tailscaled
  run as root by a system extension) every `serve status --json` from the copied CLI as
  `_keyflap-signer` timed out, so approvals stayed paused for good. The macsys CLI reaches
  tailscaled over XPC through the GUI app ("NSXPCSharedListener ... listener
  'ClientCallsAuxiliary': Connection interrupted", "The Tailscale GUI failed to start"), and a
  LaunchDaemon has no GUI. A read entry on the token file did not make the CLI use it. What
  works, measured there with curl as root and as `_keyflap-signer`: `/Library/Tailscale`
  (`root:wheel 0755`) holds `ipnport`, a root-owned symbolic link whose target is the port
  (`49152`), and `sameuserproof-49152` (`root:admin 0640`, 21 bytes, the token); the extension
  listens on `127.0.0.1:49152`; `GET /localapi/v0/serve-config` with basic auth `:TOKEN` and
  `Sec-Tailscale: localapi` returns 200 in about 1 ms with the JSON `serve status --json` prints
  (401 "auth required" without the token). The signer does exactly that, each read: in service
  mode `rootOnlyProblem(dir, 'directory')` on `/Library/Tailscale` (root-owned up to `/`, no group
  or other write, no symbolic link on the way) and a root-owned `ipnport` link whose target is a
  port number, else *unreadable* `tailscale is not trusted: …` and nothing is read; then the token
  through one `O_NOFOLLOW` descriptor, trimmed, 1 to 128 printable characters; then the request.
  No port link, a missing token file or a refused connection is `Tailscale is not running`; a
  token it may not read is `Tailscale's token cannot be read`; 401/403 is `Tailscale refused the
  token`; any other status or a hang is unreadable too, and an oversized or non-JSON serve
  setting latches (below). The token
  is never logged, audited or kept between reads (a test checks the signer's log for it and its
  base64). `install.sh` picks this when the origin is a `*.ts.net` name, `--tailscale-bin` is not
  given and `/Library/Tailscale/ipnport` is a link; it checks the same rules first and passes
  `--tailscale-localapi /Library/Tailscale` to install-config, which checks them again. It lets
  `_keyflap-signer` read the token without changing anything else of Tailscale's: `chmod +a
  "user:_keyflap-signer allow read,file_inherit,only_inherit" /Library/Tailscale` (tailscaled
  writes a new token file when the extension restarts, and the new file inherits the entry) plus
  `allow read` on the current `sameuserproof-PORT`, each replacing any `_keyflap-signer` entry
  already there (`drop_signer_aces`, by index from `ls -led`). `uninstall.sh` drops every
  `_keyflap-signer` entry, direct or inherited, from the directory and every `sameuserproof-*`
  before `--purge` deletes the user. The app copy, its `codesign`/team-ID checks and the
  re-run-after-update step are gone. With only the App Store app (no `ipnport`; its token lives
  in the app's sandbox container) the installer says the signer can't read the setting and names
  the standalone app or open-source `tailscaled`; `--tailscale-bin` stays the override, and
  open-source `tailscaled` on a Mac uses the CLI path (its CLI talks over a unix socket).
  Doctor and status name the fix: token unreadable, untrusted directory or no reader: re-run
  install.sh; not running or refused: start Tailscale. Dev mode and the simple install keep the
  CLI (same uid, and the GUI is there).
- **What counts as correct.** Only for a `*.ts.net` origin (or `--tailscale-bin`, which the
  isolation suite uses with `http://approver.localhost:8766`; the serve keys must match the
  origin's host). The serve config must have `Web["host:port"]` with exactly one handler, `/`,
  that is exactly `{"Proxy": "<listener>"}` (a trailing slash tolerated), `TCP["port"]` exactly
  `{"HTTPS": true}`, no `AllowFunnel["host:port"]`, no other name on the same port, and no
  foreground session using the port. Nothing at all at our host and port is *empty*, which is
  decided by Tailscale's status (below). Anything else is a mismatch, with a short `seen` text
  (host:port and what is there, no secrets; what the config wrote, a proxy target, a handler
  path or another name, is quoted with `JSON.stringify`, stripped of control, format and line
  separator characters and cut to 80 characters, so it cannot read as Keyflap's own words or
  reach root's terminal raw; status and doctor strip and cut it again before printing). From
  the trusted reader, an answer over the 1 MiB cap, not JSON, or not a JSON object is a
  mismatch too (`the serve setting is over 1 MiB`, `… is not JSON`, `… is not a serve config`):
  an account that can change serve can make the setting that large (a `text:` handler of a
  megabyte on another port) while tailscaled serves its own page at our origin, so a pause
  there would leave the phone's cookie and an open page to it. The cap stays, to protect the
  signer. A failed or timed-out run, a missing or untrusted CLI, tailscaled not answering and
  the token are *unreadable*: no account but root can produce them (the timeout: next bullet
  but one, and the residuals). The CLI reader checks Node's output cap before a kill, since a
  run cut off at the cap is also killed and used to read as a timeout. The CLI's own "failed to connect to local Tailscale …"
  (exit 1; the 1.104.2 CLI prints `getting serve config: Failed to connect to local Tailscale
  daemon for /localapi/v0/serve-config; not running? …`) reads as `Tailscale is not running`,
  the LocalAPI reader's word for the same thing. Other fronts (own certificate,
  another proxy): the signer has no `approverAddress`, status says "not watched (not a
  Tailscale name)" and doctor warns "Keyflap can't watch this address".
- **A Tailscale restart reads as nothing served. Deviation from the first build, on
  2026-10-30** (DECISIONS.md, "A Tailscale restart must not sign the phone out"). From
  Tailscale's source (main): `ipn/ipnlocal/serve.go` `reloadServeConfigLocked` sets the serve
  config to empty while the node's own info is not valid yet, and `ipn/localapi/serve.go`
  answers `GET serve-config` with 200 and `json.Marshal(config)`, which is `null`. So for a
  few seconds after tailscaled starts (an update, a reboot, the Mac app relaunched or its
  extension restarted, an offline start, where it lasts until it reaches the control server) a
  correct setting reads `null`. On the dev Linux machine the journal shows 6.1 s and 8.7 s from
  `Program starting` to `serve: creating a new proxy handler` on the last two boots, most of it
  waiting for the control server. The first build mapped `null` to `{}`, called it "nothing is
  served at host:port", latched, and so signed the phone out on a restart. On a Mac the restart
  also moves the LocalAPI to a new port and token: reads in between fail with no port link, a
  refused connection, a missing or empty token file, or a refused token.
- **Nothing in the serve config is not nothing at the address. Corrected 2026-10-30 after a
  security review.** The second build treated every empty config as a pause, on the premise
  that nothing served means no page. That is wrong while tailscaled is up: a port serve does
  not claim is handed to the host stack (kernel TUN: any socket bound to the Tailscale IP and
  port; userspace mode: `127.0.0.1:port`), and an account that can change serve can usually
  also run `tailscale cert <name>.ts.net`. Such an account could clear serve (a pause with a
  grace: no latch, phones and cookies kept), listen with TLS at the exact approval origin,
  have the phone load its page, restore serve, then use the phone's cookie on the loopback API
  to fetch a pending challenge and have its still-open page sign it under its own prompt text.
  Before that build, step one latched within one poll. Now *empty* is harmless only when
  Tailscale says this machine is off the tailnet, read in the same check: LocalAPI
  `GET /localapi/v0/status?peers=false`, or `tailscale status --json --peers=false`.
  **The signal** (`tailnetPresence`): `BackendState` is not `Running`, `Self.InNetworkMap` is
  `false`, and `TailscaleIPs` is `null` or empty. From Tailscale 1.104.2's source:
  `reloadServeConfigLocked` (ipn/ipnlocal/serve.go) empties the serve config exactly when
  `currentNode().Self()` is not valid, and `nodeBackend.Self()` is invalid exactly when there is
  no netmap; `updateStatusLocked` (ipn/ipnlocal/local.go) sets `Self.InNetworkMap` and fills
  `TailscaleIPs` only from the netmap. With no netmap the engine has no Tailscale address and no
  peers (NoState and Stopped reconfigure it empty, Starting configures it from the netmap), so
  nothing on the tailnet reaches the address. `BackendState` is also required not to be
  `Running` because `nextStateLocked` can keep `Running` with no netmap; any field missing or of
  the wrong type makes the status unreadable, and any other combination counts as on the
  tailnet (the latching side). Each check reads the status first, then the serve setting once
  (an earlier version read serve, then status only when empty, then serve again; the extra read
  was a cue visible in `ps` on Linux and a window to restore in). Empty with the status off is
  offline; empty with the status on is a mismatch, `nothing is served at <host:port>`, which
  latches; anything else in the serve setting decides by itself, whatever the status said. Only
  when the serve setting is empty and the status could not be read does the status read's
  failure decide: a pause with the cause's own grace. Not running and the token causes keep the
  restart grace whichever endpoint they came from: they describe tailscaled and its token, not
  the status body, and since the status is read first a restart now usually shows there. A
  status of the wrong shape (`Tailscale's status cannot be read`) gets none.
- **Where the line is.** The tripwire is there because another page at the approval origin could
  fake the prompt (invariant 5). *Offline* (empty and off the tailnet) is a pause, not a trip:
  `null`, `{}`, or a config where no `Web` key and no `TCP` key uses our port, no foreground
  session uses it and `AllowFunnel` has no entry for our host:port, while Tailscale has no
  netmap. It refuses everything like an unreadable read and resumes on the next correct one.
  Empty while on the tailnet latches, as in the first build. A config only half there latches: HTTPS on our port with no handler, a handler with no
  HTTPS listener, a raw forward, another name on the port, a foreground session, Funnel. A
  restart replaces the whole config at once (empty, then everything), and `tailscale serve`
  writes the `TCP` and `Web` entries together, so a half config is something written by hand
  (`serve set-raw`) or a change in progress, not a restart, and some of them do serve a page
  (a raw forward, a foreground session). Telling the harmless ones apart would be guessing at
  tailscaled's behaviour on configs it never writes; failing closed is cheaper. Other ports on
  the same name are not looked at (residuals).
- **States.** `paused` (not checked yet) from start until the first read, which happens before
  the signer accepts connections; `ok`; `paused` while unreadable or offline; `latched`. A
  mismatch at any read latches, the first read after a pause included. Unreadable and offline
  never latch and never leave a latch. The signer refuses every approval check, grant use and
  pairing while paused, inside the grace or not.
- **The grace (30 s), one per incident.** A pause gets `graceUntil` = its start + 30 s when its
  cause is one a restart explains: `Tailscale is not connected` (offline),
  `Tailscale is not running`, `Tailscale's token cannot be read`, `Tailscale refused the token`
  (`RESTART_DETAILS`). A read in the same pause with any other cause (a timeout, a status of the wrong
  shape, another exit or status, an untrusted tool)
  drops the grace for the rest of that pause; a pause that started without one never gets one.
  The grace's start (`graceSince`) is kept on the pause and on `ok` after it for 10 minutes
  (`GRACE_WINDOW_MS`): a restart pause in that window gets only what is left of the first
  grace, so flapping between empty and correct cannot renew it. Inside the grace
  (`addressPhase` = `holding`) the core cancels nothing: pending approvals, handoff starts and
  the open pairing keep waiting and the page shows no warning. A new request is refused
  (`approver_address_unverified`), not queued or pushed, and the phone's `/api/challenge`,
  approve, handoff challenge and start, and the pairing steps (`/api/pair/options`,
  `/api/pair/finish`, the native pair) answer 503 `approver_address_unverified` without touching
  what waits, so no passkey is made for a pairing the signer would then refuse; a denial still
  goes through. Once the address reads correct they carry on. At the end of the grace the core
  cancels as for any pause. Why 30 s: three times the slowest restart measured above, short
  enough that a real problem shows the warning within half a minute, and well inside the 2
  minutes an approval waits (the statement the phone signs lasts 60 s from its challenge).
  Pairing is still refused to start while paused. Handoff challenges and starts are now
  refused during any pause; before, a pause only cleared the starts already open.
- **After a trip the signer keeps reading**, every 2 s, for status only: `latched.latest` is the
  newest reading and its time. The latch itself is unchanged: approvals stay off and the phones
  stay removed until `approver.address.clear` reads a correct setting. A refused clear no longer
  rewrites the stored trip (`at`, `seen` stay what was seen first).
- **Polling.** 2 s idle, 250 ms while the core reports a pending approval or pairing (channel op
  `approver_address {pending}`, which the core sends every 1 s idle and every 250 ms while busy;
  the fast window lasts 3 × 250 ms + 2 s after the last report). One read at a time.
  CPU cost, measured on the dev Linux machine (Tailscale 1.104.2, 4 cores, load about 3):
  one `serve status --json` costs about 11 ms of CPU in the CLI (200 runs: 2.25 s user+sys)
  and under 1 ms in tailscaled (9 ticks of 10 ms for those 200). The watcher itself, timed
  with its children for 60 s minus a 0 s run's startup: 0.34 s idle (0.6 % of one core) and
  2.5 s at the fast cadence (4.2 % of one core), which matches 30 and about 230 runs at 11 ms.
  Fast polling lasts only while something is pending. Not measured on a Mac (the CLI took
  about 55 ms wall there). Each check now also reads the status (`status --json
  --peers=false`), so these costs about double; not measured again.
- **The latch.** Persisted in the encrypted key store (`addressTrip: {at, seen}`), so it survives
  a restart; on start a persisted trip skips reading until cleared. Tripping removes every
  approver (passkey and native), drops allow-for grants and accepted fill assertions, and logs
  `approver_address_tripped {seen, approversRemoved}`. While latched or paused the signer refuses
  every approval check (`approver_address_latched` / `approver_address_unverified`), grant uses
  included, and both pairing ops. The core polls the state (`ApproverAddressSync`); on a new trip
  it sends a Web Push (`{"t":"address","on":"Mac"|"computer"}`, the page text "The approval
  address on your Mac was changed. Don't approve anything until you've checked it at your Mac.",
  "computer" on Linux) and waits for it (10 s cap per phone), then audits
  `approver.address_tripped {origin, seen}`, cancels every pending approval, handoff start and
  pairing (`approver_address_changed`), and drops every phone session; a signed-out page shows
  the same text. On a pause it audits `approver.address_unreadable` (again when the cause
  changes) and keeps the phones; once the pause is past its grace, or has none, it cancels
  everything pending (`approver_address_unverified`) and the page says approvals are off until
  Keyflap can check the address.
- **Recovery is root's.** Service mode: `sudo keyflap approver pair` first calls
  `approver.address.clear` on the signer's root-only admin socket. The signer reads the setting
  again: still wrong, offline or unreadable refuses (the trip is kept as first seen; `latest` is
  updated), correct clears
  the trip, logs `approver_address_cleared` and, with no approver left, reopens first-use pairing
  (as removing the last phone as root does). The CLI then asks the core to pair, and the core
  re-reads the state first. The core's channel gets `admin_required` for the clear. Dev mode
  and the simple Mac install: `keyflap approver pair --approver-origin …` with the daemon stopped
  (a spawned signer with `approverAdmin`), which is the same uid as everything else there.
- **Status words** (`cli/src/approver-address.ts`, one place for status, doctor, pair and the
  console). After a trip: `off: it was changed at <ISO time> (<seen>), so phones were signed out
  to be safe`, then `. It is right again now` with the fix `pair your phone again to turn
  approvals back on: …`, or `. It is still wrong`, `. Now: <seen now>`, `. Now Tailscale is
  not connected`, `. Now it can't be read: <detail>` with the serve (and reset) fix. Inside the
  grace: `waiting for Tailscale: Tailscale is not running` (or `is not answering yet`, or
  `Tailscale is not connected yet`), fix `wait a moment: approvals resume by themselves
  once Tailscale answers`; doctor warns instead of failing. Past the grace, offline is
  `paused: Tailscale is not connected` (fix: start Tailscale); the rest
  keep `unreadable: <detail>` and today's fix, so a token that stays unreadable still says to
  re-run the installer, and only then.
- **Dev mode and the simple Mac install** run the same watcher in their spawned signer when the
  phone origin is a `*.ts.net` name. It is a guard against mistakes and other uids there, not
  against an agent running as the same user, which can read the key store anyway (D6).
- **Linux sandbox.** `keyflap-signer.service` is unchanged: `RestrictAddressFamilies` already
  has `AF_UNIX`, and `ProtectSystem=strict` leaves connecting to a socket under `/run`
  (`/run/tailscale/tailscaled.sock`) possible. The isolation suite runs a probe with the unit's
  sandbox properties against a socket there.
- **Tests.** `signer/test/inv5-address-restart.test.ts` (a restart through the LocalAPI: refused,
  no token file, an empty token, `null` with no netmap, correct; and through the CLI: not
  running, `null` with no netmap, correct; neither latches, phones and grants stay, approvals
  and grant uses are refused only while it lasts; a cause no restart explains has no grace;
  `{}` or `null` while on the tailnet latches, through the CLI and the LocalAPI; empty with a
  status of the wrong shape is a pause with no grace; a second restart soon after gets only the rest of
  the first grace; something else served and each half config latch; another port alone, while
  on the tailnet, latches; a latched signer keeps reading, across a restart),
  `signer/test/inv5-approver-address.test.ts` also has the `tailnetPresence` table, the latch on
  a setting over the cap, not JSON or not an object, the order of the reads (status, then serve
  once, through the CLI and the LocalAPI), and the
  quoting of what the config wrote, `approver/test/inv5-address-hold.test.ts` (inside the grace
  nothing is cancelled, challenge and approve are refused without losing the request, a new
  request is refused and not pushed, a waiting one can still be denied, pairing steps answer
  503, the approval completes after the pause; past the grace and without one it cancels; a
  trip during a pause still signs out), `signer/test/inv5-tailscale-localapi.test.ts` (the LocalAPI reader against a fake
  tailscaled on loopback: the request it sends, a refused token, no port link, nothing
  listening, an unreadable or malformed token never sent, a port link that is not a link to a
  port, a user-owned directory refused before anything is read, hang, error, oversized; a spawned
  signer that pauses, resumes and latches through it and never logs the token),
  `signer/test/service-mode.test.ts` (the service path refuses a LocalAPI directory root does
  not own), `install/test/tailscale-bin-flag.test.ts` (the Mac installer's choice, its refusals,
  the ACL entries it adds and the uninstaller removes), `signer/test/inv5-approver-address.test.ts` (fake CLI, spawned signer: correct
  allows; a mismatch latches, removes approvers, logs and refuses; the latch survives a restart;
  unreadable pauses and resumes; a flip and restore during a pending approval is caught at the
  fast cadence; pairing refused; only the admin path clears),
  `approver/test/inv5-approver-address-sync.test.ts` (the core's reaction, push before
  sign-out, pairing refused), `cli/test/inv5-address-daemon.e2e.test.ts` (dev daemon),
  `isolation/test/inv5-approver-address-isolation.test.ts` (service mode in a container: the
  agent's uid repoints serve through a fake CLI, the next sign-in is denied, nothing is signed,
  phones are gone, `approver pair` refuses until the setting is right, then clears and the next
  sign-in works).
- **Residuals.**
  - **The grace and a fake page.** Could an approval accepted after a pause have been obtained
    by a fake page during it? A decision is accepted only while the address reads correct, and
    the signer checks again on every approval. To be accepted after the pause, the assertion
    must be for a request still waiting (no new one is queued or pushed during a pause), and a
    fake page would have had to be served at the address while the reads did not see it. For
    the causes that get a grace that window is the same as without one: an offline read means
    Tailscale has no netmap, so nothing on the tailnet reaches the address (an empty config
    while on the tailnet latches); while tailscaled is not running or still starting (its token
    not written yet, the port link moving) nothing is served at the address at all; and no
    account but root can make the reads fail that way while tailscaled serves. A page put
    there between two reads is the repoint residual below, at the same cadence, which stays
    fast while a request waits. Going offline on purpose (`tailscale down` by an operator, or a
    logout) takes the address off the tailnet with it, and the grace is one per 10 minutes. A token left unreadable by an
    update that re-created `/Library/Tailscale` is root's doing and does not clear without the
    installer, so nothing waiting can be decided before the grace ends.
  - **Cancelling is not enough for a cause a serve writer controls.** A pause cancels what
    waits and refuses new requests, but keeps the phones and their cookie. If the account that
    made the read fail is also serving its page at our origin through tailscaled, a phone that
    opens the page during the pause loads that page, and after the pause the account can fetch a
    challenge with the cookie and have the still-open page sign it under its own text. So the
    causes such an account can produce latch (over the cap, not JSON, not an object: above).
  - **Timeouts still pause.** A read past the 5 s timeout is a pause with no grace, not a
    latch. tailscaled's answer to serve-config or status does not get slower with the content
    under the cap (a marshal of under 1 MiB takes milliseconds), so a serve writer cannot cause
    a timeout through the setting; it would have to slow the whole machine for 5 s at every
    read, which a status read just before would mostly show as well. A loaded or swapping
    machine can time out benignly, and the owner does not want false sign-outs, so the remaining
    case (a local account starving tailscaled or the CLI for every read while tailscaled serves
    its page, and a phone opening the page during that pause) is accepted.
  - Offline is not a trip, so an account that can take this machine off the tailnet (an
    operator's `tailscale down`) turns approvals off without signing the phone out. Removing our
    serve entry while on the tailnet trips the latch, as before.
  - The status-then-serve read is two reads, not one snapshot. If the netmap arrives between
    them, the serve read already has the real setting. If it vanished between them (a logout,
    or tailscaled stopped and back up within those milliseconds), an empty setting is read with
    a status that said on, and latches: a false trip, in a window of milliseconds. A netmap
    that arrives between them while the setting has been emptied reads as offline once, and the
    next check latches: the same window as the repoint residual.
  - **Other ports on the same name are not compared.** `compareServeConfig` looks only at our
    host:port (and at other names on our port, and foreground sessions using it). A page at
    `https://<name>.ts.net` (443) or any other port of the name is a different origin, so it
    gets no access to the approver page's storage or service worker, and an approval assertion
    made there carries that origin in its client data, which the signer refuses
    (`assertion_origin_mismatch`; the passkey's rpId is the bare host, so the phone would sign
    it). The phone's browser does send it the `__Host-aab_device` cookie (cookies are not
    scoped by port). A local process holding that token can call the approver API on its
    loopback listener as the phone: read the pending requests (the fields the prompt shows),
    deny them, replace the phone's push subscription, and see which handoffs are open.
    Approving, starting a handoff and pairing all need an assertion made at our origin. Not
    changed here; checked 2026-10-30.
  - A repoint shorter than one poll interval, timed to the phone's request, is not caught. A
    page that loads at the address in that window runs at the approver's origin, and may leave
    a service worker on the phone. After a caught trip the docs tell the owner to delete the
    home-screen icon and the address's website data before pairing again.
  - The pending signal comes from the core. A compromised core can withhold it, so against the
    core the window is the 2 s idle poll, not 250 ms.
  - The reading is only as true as tailscaled's answer through a root-only CLI, or at the port a
    root-owned link names.
  - LocalAPI: while tailscaled is down, any local user can bind `127.0.0.1:PORT` and receive the
    token on the signer's next read, and answer with a correct-looking serve config. The token
    gives no capability beyond what a local user already has through the Tailscale GUI (on the
    Mac any local user can change serve, which is why the tripwire exists), and while tailscaled
    is down nothing is served at the `.ts.net` address, so the fake answer covers no page. Not a
    deviation from ARCHITECTURE section 5: no invariant depends on the token's secrecy.
  - The ACL entries on `/Library/Tailscale` are the one change Keyflap makes to Tailscale's files.
    A Tailscale reinstall or update that recreates the directory drops them: reads then fail with
    `Tailscale's token cannot be read` (approvals pause, after the 30 s grace with the fix to
    re-run `install.sh`) until `install.sh` is run again. The user docs say so.
  - Not verified against a real Tailscale on a Mac: what tailscaled answers, and for how long,
    while the system extension restarts or the app relaunches (the restart sequence is tested
    against the fake LocalAPI only), and whether 30 s covers it there.
  - The warning is best effort and reaches only phones with notifications on.
  - The root-only check (`rootOnlyProblem`, `tool_problem`) does not look at macOS ACLs; that
    applies to every tool, not only `tailscale`. Not changed here.
  - Mac-only, not verified on Linux (the tests use a fake LocalAPI on loopback and fake `ls`,
    `chmod` and `sudo`): that `chmod +a` takes `read,file_inherit,only_inherit` on a directory,
    that a token file tailscaled writes after an extension restart inherits the entry (it would
    not if tailscaled wrote it elsewhere and moved it in), the `ls -led` entry format the scripts
    parse, and that Node's request from `_keyflap-signer` gets the 200 curl got.


## Every push alerts the iPhone (2026-10-30)

On the test iPhone an approval notification arrived silently: it showed up only when the
owner woke the phone. Every approval push used the tag `keyflap-approval` with `renotify`.
Safari does not implement `renotify`, so a push whose tag matches a notification still in
Notification Center replaces it without a sound or a banner. The service worker now gives each
notification its own tag, and the page closes its notifications whenever it comes to the front.
The Web Push `TTL` stays at 60 seconds, the lifetime of an approval request
(`APPROVAL_TTL_MS`). The cause is inferred from Safari's documented support, not seen in a
trace.

## `sudo keyflap` on a Mac (2026-10-30)

DECISIONS.md, "Plain `sudo keyflap` on a Mac". M7 had every Mac fix and doc say
`sudo /usr/local/bin/keyflap …` (`ServiceManager.sudoKeyflap`, `checkTool`'s `sudoKeyflap`
parameter). The full path only stopped a planted `keyflap` earlier on the owner's `PATH`, and an
agent that can plant one can redefine `sudo` in the shell config just as well; both belong to the
open question in DECISIONS (telling the owner at the machine from an agent in the same account).
So the field, `sudoKeyflap()` and the parameter are gone: every printed fix in the CLI and every
doc says `sudo keyflap …` on both platforms.

- **Unchanged on purpose.** `/usr/local/bin/keyflap` still names the installed file (installer,
  uninstaller, paths tests) and the hook and `mcp-headers` commands written into agent configs,
  which no person types.
- **The installers too.** The text `install.sh` and the one-command bootstrap print, and the
  assertions on it in `packages/isolation/test/release-install.test.ts`, say `sudo keyflap …`
  (the install progress branch).

## Install progress and the install log (2026-10-30)

The owner, after running the one-command install on a Mac: "I'd also love better installation
animations, like progress bars", the output is "vomiting a lot of information on the user", and
"Lines should have proper spacing between them" (DECISIONS.md, "Setup should look as good as it
is safe"). He picked the bar header for setup, so the install uses the same bar.

- **One shared file, two ways in.** `packages/install/linux/progress.sh` (bash 3.2, BSD and GNU
  tools, functions only) is sourced by both `install.sh` scripts and ships next to them in a
  release (`build-bundle.sh`). The macOS script checks it is root-only before sourcing it, like
  `runtime-pins.sh`. `make-bootstrap.sh` copies it into `install-keyflap.sh`, which can't source
  anything before its download is checked.
- **The view is chosen by stdout, not by a flag.** On a terminal (stdout a TTY, `TERM` set and
  not `dumb`, `/dev/tty` readable, 30 columns or more) the scripts draw setup's header (K tile,
  KEYFLAP, `install · VERSION`), one thin bar, and the step in progress next to the flipping
  tile, redrawn in place six lines high by a background ticker (0.12 s). Otherwise every line is
  the one printed before this change: the fake-Mac test compares macOS `install.sh` output byte
  for byte, and the bootstrap's dry runs were compared against the previous version.
- **Real progress where it is cheap.** The bootstrap's download and a source install's Node
  download read curl's own progress meter from a file; Chromium reads Playwright's per-10% lines
  (it prints them when its stdout is not a terminal). Steps without a measure only animate.
- **Detail goes to a root-only log.** Once the view starts, stdout and stderr go to
  `/Library/Keyflap/log/install.log` (macOS; that directory is made then, root 0711, as the
  install made it before) or `/var/log/keyflap/install.log` (Linux, a new root 0700 directory,
  removed by `uninstall.sh`). The file is 0600, and a symlink in its place is removed first. It
  holds exactly what the scripts printed before, plus their commands' output. No secret passes
  through these scripts as a value; the 1Password token is read with `read -s` and only piped to
  the credential. The view starts after the checks, so a refused install still changes nothing
  and writes no log. The bootstrap keeps its own lines in its root-only download directory and
  appends them to install.sh's log afterwards.
- **Errors stay on screen in full.** `die` stops the frame on the failed step (the inverted
  flap) and prints the same message as before under it, then where the log is. A command that
  fails without `die` shows the log's last 12 lines; Ctrl-C says to run the command again (both
  scripts are idempotent). The cursor and the terminal's echo are restored on every exit.
- **The bootstrap asks first, then runs one bar.** For a real install, the origin and password
  manager questions now come before the download, so the bar is not interrupted. The download,
  check and unpacking fill the first quarter, and `install.sh` continues the same frame from
  there (`KEYFLAP_PROGRESS_FROM=250`) and leaves the next step to the bootstrap. A dry run keeps
  the old order. A real install always has a terminal for its questions, so its plain lines only
  appear when stdout alone is redirected; there they now show the questions first too.
- **The 1Password token prompt moved before the first change** in both `install.sh` scripts.
  Before, an empty token stopped the install after the users and the code were in place.
- **Tests run the real macOS `install.sh` on Linux.** `packages/install/test/fake-mac.ts` builds
  a chroot in a user and mount namespace (`/opt`, `/Library` and `/usr/local` of its own, the
  host's `/usr/bin` under an overlay of fakes for `dscl`, `launchctl`, BSD `stat` and the rest),
  so the script runs unchanged, under `script(1)` for a terminal. It needs unprivileged user
  namespaces and overlayfs, and skips without them (macOS CI). What only a real Mac can show:
  the glyphs in Terminal.app's default font, the colours under `sudo` (which drops `COLORTERM`,
  so 256 colours), and how Playwright's real download paces the bar.

## Setup sets up every installed agent host (2026-10-30)

The owner: writing Claude Code's config "doesn't add it to the desktop Claude app, its only the CLI,
it should be both, same for Codex" (DECISIONS.md, "Setup should look as good as it is safe").
The desktop app's Code tab reads the user-scope Claude Code config, so that half was already
true; the gap was step 4 asking for ONE host (`chooseHost`) when Codex or Hermes was installed.

- **Every host in turn.** `agentStep` builds the list from `hostsToSetUp`: Claude Code always,
  then Codex and Hermes when `detectHosts` finds `~/.codex` or `~/.hermes` (in that fixed order).
  `--host X` is a list of one. Each host runs its existing single-host path unchanged
  (`claudeCodeStep`, `otherHostStep` and `configureOtherHost`): its own `pickAgent`, its own
  preview-and-`y`, its own state record. A host skipped or declined does not stop the next one;
  the step is `done` when any host was written. The menu `chooseHost` and `asksForHost` are
  deleted.
- **Own agent per host, enforced.** `pickAgent` refuses an existing agent that `setup.json`
  records for a different host ("already serves another host"), and does not list it. Keyflap
  keeps one live intent per agent, so two hosts on one agent would overwrite each other's
  intent. The default name is the agent the host already uses (from `claudeCode` or
  `agentHosts`), else the host's own name; so a re-run reaches "Use the existing agent" with
  Enter, creates nothing and rewrites no up-to-date file. `agentHosts` already held one entry
  per host and directory; `claudeCode` one per scope and project. Nothing in the state shape
  changed.
- **Security unchanged.** Codex still gets the same hook merge and the same `config.toml`
  (protected profile, `granular` approval policy, token only by `$(cat file)`), Hermes the same
  plugin and Docker-backend instruction, Claude Code the same sandbox and deny rules. The token
  of each agent goes to its own 0600 file; no step prints or logs one (the preview scenario
  checks all of them). The hook-trust step is still the person's (`/hooks` in Codex).
- **What the screen shows.** One screen set per host, headed "Codex (2 of 2)". The manual part
  that setup never edits (Codex `config.toml`, Hermes `.env` and `config.yaml`) used to be
  printed straight onto the screen and overflowed it with two hosts; it is now a two-sentence
  summary on screen (it still says the protected profile keeps the model away from the host
  token, and the health check still fails without it) with the full text behind Tab and in the
  setup log. `reflow`, which joins wrapped prose in the Tab view, no longer joins lines indented
  three or more columns, so a block to copy (TOML, YAML) stays one line per line.
- **Finish** lists every host set up (`setUpHosts`, from `setup.json`, so hosts from earlier
  runs count): "Claude Code, all projects (terminal and desktop app)", "Claude Code, ~/proj",
  "Codex", "Hermes Agent".
- **Tests.** The two tests that asserted the one-host menu ("Which agent host should use
  Keyflap?" in `setup-steps.test.ts` and `agent-hosts.test.ts`) are replaced by tests of the new
  behaviour: both hosts set up with distinct agents and files, Claude Code offered with only
  Codex installed, one host declined, all declined, `--host` alone, the shared-agent refusal, the
  re-run, three hosts, and the Finish list. `FakeBackend.createAgent` now returns a distinct id
  and token per agent. The `mac-agents` preview scenario (`pnpm setup:preview --scenario
  mac-agents`) has Claude Code and Codex installed.
- **Not confirmed here.** That the Claude desktop app's Code tab picks the config up on a
  Mac (the owner saw it work), that Codex's desktop app reads `~/.codex` the same way as its CLI, and
  that `/hooks` offers the hook for trust after setup: only a real machine can show those.

## Management console: `sudo keyflap` (2026-10-30)

DECISIONS.md, "A management console, not a command suite". `sudo keyflap` with no command, on a
terminal, opens a full-screen console on setup's screen (`packages/cli/src/console/`). It adds no
socket, no admin operation and no privilege: it is a menu over code that already runs as root.

- **The menu is a table.** `console/menu.ts` holds `SECTIONS`: seven sections, each a list of
  typed actions. `show` and `list` run a read command; `pick` lists items from a `--json` list
  command and runs a removal on the one picked; `form` asks its fields and builds an argv; `flow`
  runs an existing setup step; `doctor` runs the doctor checks. `console/listings.ts` parses each
  `--json` output at the boundary and passes every name through `printable`, so an agent name or
  an imported username can't write to the terminal. `console/run.ts` is the loop; it knows
  nothing about passwords or agents.
- **Commands go through the CLI's own path.** An action's argv is parsed by `parseCli` (so the
  console validates exactly as the command does, before it asks to confirm) and run by
  `runServiceCommand`, the function `sudo keyflap <command>` calls. `consoleCommand` allows only
  17 command kinds: none of them prints a token or a pairing link, or reads a secret from the raw
  terminal. `agent add` (prints the token), `approver pair` and `approver qr` (print the link
  outside the screen), `password add` and `password import` (read secrets or a file themselves),
  `setup`, `doctor` and the daemon are refused; a test pins that list and checks every argv in
  the table is allowed.
- **Setup's own steps for the rest.** Adding a password (`addPassword`), importing a CSV
  (`importExport`), pairing (`pairStep`), adding an agent and writing its app's config
  (`agentStep`), and the Proton Pass and 1Password checks (`protonPass`, `onePassword`) run with
  a `SetupContext` built by `setupContext()`, now split out of `runSetup`. So secrets are typed
  into setup's no-echo prompt and sent to the same `password.add` admin operation, and a new
  agent's token goes to its file and is never shown. `addPassword`, `protonPass` and
  `onePassword` are now exported from `setup/steps.ts`; nothing else there changed.
- **Every change confirms, and the default is no.** A `pick` or a `form` yields a `Change`: the
  argv and the question. Every change defaults to no: a removal (password, phone, agent, rule,
  saved sessions), anything that loosens a rule (an allow-for window, keeping a high-risk site
  signed in, trusting an updated tool), and setting a rule, which replaces any rule the site
  had and so can loosen it (`ask` over a `deny`); the console doesn't read the old rule to
  tell. These are the owner-only changes of DECISIONS "The CLI is the owner's control panel".
  Setup's flows ask as they always did. (The independent review found the plain-rule default
  of yes, 2026-10-30.)
- **Fail closed.** A command's error is shown (`✗ …`, after any output it printed) and the
  console returns to the section. When the status can't be read, the overview says why and every
  section still opens; each action then fails on its own.
- **Screen changes.** `Frame` gains `app` (`setup` or `console`) and `section`. For the console
  the header reads `console · service mode`, the bar marks the current section's seventh of the
  rule in blue instead of progress, Esc at any prompt goes back (`PromptAborted('back')`), and
  setup's numbered `step()` becomes a page title. Setup's screens are byte for byte unchanged.
  `ScreenUi` gains `place()` (a section screen, no Enter gate) and `hold()` (the gate itself).
- **Status on the overview** comes from `status --json` through the same path, and the address
  words from `serviceAddressWords`, so the overview and `sudo keyflap status` can't disagree.
- **Password managers connect on the spot** (see "Connecting a password manager after the
  install"). **Not built:** session TTLs and per-agent rule lists stay on the command line.
  Dev mode and the simple install have their own console, below. `keyflap` as your own user,
  in the full install, prints its usage and one line saying `sudo keyflap` opens the console.
- **Try it without installing.** `pnpm console:preview` runs the console in a terminal against
  `test/console-world.ts`: the real core and CLI admin operations (`registerCoreAdminOps`,
  `registerCliAdminOps`) on a throwaway SQLite database behind real admin sockets, with a fake
  signer, fake sessions and in-memory phones. `--capture DIR` walks a scripted tour and writes
  every screen as ANSI and HTML, with an `index.html`. `test/console.test.ts` drives the same
  world.
- **Esc is new on this screen.** `KeyDecoder` reads an Esc byte that arrives alone as Esc at
  once. An arrow key whose bytes were split right after the Esc (possible over a slow ssh link)
  would read as Esc, which now goes back. Setup never bound Esc, so this did not matter before; a
  short wait for the rest of a sequence is the fix if it shows up.
- **What only a real Mac can show:** the glyphs and colours in Terminal.app under `sudo` (256
  colours), the Esc timing above, and pairing and the Proton Pass login against the real
  services.
- **The pairing code is drawn at paint time (2026-10-30).** The owner's iPhone could not scan
  the code in Terminal.app (213×54). The encoder was right. The drawing was wrong. Terminal.app
  draws `▀` from the font, and the glyph does not fill exactly the top half of the cell, so every
  text line had a light seam through the dark modules. Short windows also cut the code's top
  rows, because the paint drops lines from the top. The figure block now carries the `QrCode`,
  not a drawn string. `paint` picks the drawing from the current size and terminal on every
  paint, so a resize or a zoom (which changes the columns and rows) picks again. The order is:
  (1) full cells, two spaces a module with a background colour, which fill the cell in every
  terminal; (2) half blocks, only on a terminal known to draw block elements itself
  (`drawsBlockElements` in `term-style.ts`: `TERM` `xterm-ghostty`, `xterm-kitty`, `alacritty`,
  `foot`, `wezterm`; `TERM_PROGRAM` `ghostty`, `iTerm.app`, `WezTerm`, `vscode`;
  `LC_TERMINAL=iTerm2`; or a Ghostty, kitty, WezTerm or Alacritty window variable; never inside
  tmux or screen, where any terminal may attach; `Apple_Terminal` and anything else is not
  known); (3) no code, and the line "Make the window bigger or zoom out to see the code, or
  press Tab for the link". A drawing is used only when the whole body (code, the text beside or
  below it, the waiting line) fits the window in some trim stage without a cut, so a partial
  code can't be painted. The replacement line is kept on screen when the body is trimmed. The
  code never touches the last column, so the erase after each line can't eat a module. The
  quiet zone is 4 modules. The colours are pure black and white (`48;2;0;0;0` and `48;2;255;255;255`
  at 24-bit colour, cube 16 and 231 at 256 colours, palette 40/107 below that), and both colours
  are always painted, so the terminal's theme (dark or light) is never part of the code. The
  usual link (version 6, 41 modules) needs 130×49 for full cells with the text beside, or 99
  columns and 61 rows with the text below; half blocks need about 90×25 beside or 50×38 below.
  Sudo keeps `TERM` but drops `TERM_PROGRAM`, so iTerm2, WezTerm and VS Code under `sudo` count
  as not known and get full cells or the replacement line. `pairing-qr-fit.test.ts` paints the
  console and setup pairing screens from 40×12 to 260×80 for nine terminal kinds and three link
  lengths, rebuilds the module grid from the painted cells, and requires the exact code (quiet
  zone included) or the replacement line, never both and never neither. It samples the sizes
  (every column at every 6th or 10th row, every row at every 6th or 10th column, a coarser grid
  for the rest) and pins the thresholds above exactly; every size for all nine kinds passed once
  (about 5 minutes), too slow to keep in the suite.
- **Resize repaints.** `ttyScreen.enter`'s parameter shadowed its own resize handler, so a resize
  never cleared the screen or reset the line diff, and `restore` removed a listener it had never
  added. Fixed, with `tty-screen.test.ts`.
- **Printed codes** (`keyflap approver qr`, `sudo keyflap approver pair`, the daemon log, setup
  without the full screen) print full cells when the terminal is wide enough for them, or when
  the width is unknown (not a terminal); half blocks only on a terminal that draws them
  (`drawsBlockElements`) and is wide enough; else the line `NO_ROOM_FOR_PRINTED_CODE`, never a
  seamed or wrapped code (review of #48). They cannot pick again on a resize. The printed link is
  beside them.
- **The header and the fit agree.** `fitsWhole` checks the same layouts `paint` may use
  (`stagesFor`): with the unprotected header on, `paint` never drops the header, so a body that
  fit only without it lost the code's top row (review of #48). `pairing-qr-fit.test.ts` paints
  the pairing frame with the header on too.
- **Nothing of the code is left behind.** When the screen closes, the text it leaves in the
  scrollback (`bodyText`) shows a pairing figure as its text only: no code, which is one-use and
  would stay in the scrollback, and no "press Tab" line for a key that no longer works (review
  of #48).

## Connecting a password manager after the install (2026-10-30)

The owner: "I want people to be able to add a different password manager within the CLI tool that we
built." Before this, service mode took a password manager only from `install.sh`, and the
console's Connect entries printed "re-run install.sh". With 1Password installed, choosing Proton
Pass fell through to that message too: setup tested whether any source was configured, not
whether Proton Pass was.

- **One routine, two front ends.** `packages/cli/src/service/password-source.ts` is the engine
  (`applyConnect`, `applyDisconnect`); `packages/cli/src/setup/password-source-flow.ts` is the
  prompts. `sudo keyflap password-source add|remove` and the console call the same functions,
  in the root process, with the `System` and `ServiceManager` abstractions. Nothing goes through
  the admin sockets or the services, so a running service never writes its own config or picks
  the signer's binary.
- **Tool.** Found only in the root-only places (`toolCandidates`, `checkTool`) and pinned with
  `trustedToolSha256`. `--bin` is checked the same way. The fix text of a refused tool is now
  `sudo keyflap password-source add …` (`ToolSpec.connect`), not an installer flag.
- **Token.** 1Password's token is read without echo, checked by running `op vault list` as the
  signer's uid with a clean environment, then stored. Linux: `systemd-creds encrypt` with the
  token on stdin into a temporary file, promoted to 0600 root. macOS: the 0400 file owned by
  `_keyflap-signer`. Root files are written by descriptor (`O_EXCL`, `fchown`, `fchmod`,
  rename; `RootFiles` in `setup/system.ts`), so a planted symlink is not followed. The token is
  in no argv and no world-readable file; tests assert both.
- **Order, so a half-finished run is safe to repeat.** Add: token, drop-ins, configs (core, then
  signer), `systemctl daemon-reload`, restart signer then core, then clean up what the other
  manager left. Remove: configs, drop-ins, reload, token removal, restart, then a best-effort
  `pass-cli logout` as the signer. Configs are validated with `parseServiceConfig` and
  `parseCoreConfig` before any write.
- **The signer's network follows the tool.** Connecting 1Password removes `no-network.conf` and
  writes `1password.conf`; removing it, or switching to Proton Pass, restores `no-network.conf`.
  `ServiceManager` gained `reloadCommands` and `signerDropIns` for this (launchd has neither).
- **One at a time.** Connecting a different manager asks first, with the words "Agents stop
  using its logins." and what happens to them: they stay in Proton Pass and Keyflap signs out,
  or they stay in 1Password and Keyflap deletes its copy of the token. Default no. The
  command needs `--yes` without a terminal. Two at once is not built; it is the owner's call.
- **Upgrades keep it.** `install.sh` (Linux and macOS) reads the connected source from
  `signer.json` when no `--password-source` is given and carries its tool, vault, token and
  drop-in over, and its pin through `--proton-pass-sha256` / `--op-sha256` (`keptOrFreshPin`
  keeps the old pin and warns when the tool changed). `--password-source none` turns it off.
  The bootstrap script reads the same file, so re-running it cannot undo a console switch.
  **agent decided, approved by the owner 2026-10-31** (DECISIONS.md).
- **Unverified.** The `pass-cli logout` on remove and replace is best-effort and unchecked
  against a real `pass-cli`. The systemd-creds output goes to a file path as install.sh's
  `seal()` does. Real macOS, real systemd-creds and real vaults were not exercised; the tests use
  fakes (`test/source-machine.ts`).

Review follow-ups to the above (2026-10-30):
- Re-adding the connected manager keeps its vault (`pickVault` takes the current one; `all`
  lifts it), keeps its configured tool, and asks before re-pinning a tool whose hash changed.
  Every confirmation and success line names the scope, "every vault" included.
- Connect writes the configs and then opens the network; remove closes the network and then
  clears the configs, so a partial run leaves the signer without a network.
- Root is checked before any prompt or spawn. A Proton Pass login made during a run that ends in
  "no" or an error is signed out again, and every sign-out that cannot happen says why.
- `cliPrompter` opens stdin only when something is read and has `close()`, so the command exits
  on an open pipe.
- The installers stop when the kept source cannot be read; the bootstrap script keeps the
  connected manager unless the owner confirms a disconnect; `--op-token-file` alone rotates.
- The installer does not sign out of Proton Pass when it switches or turns the manager off. The
  docs say so and point to the command and console, which do.

## The unprotected console: `keyflap` in dev mode and the simple install (2026-10-30)

DECISIONS.md, "A console for the unprotected modes". `keyflap` with no command, as your own user,
on a terminal, opens the console when `~/.keyflap` (the default data dir) holds a dev or simple
install. It is the console above on the same screen, with the key-store work done as you instead
of through root-only admin sockets. It adds no privilege and no socket, and the modes protect no
more than before: an agent running as you can read what the console reads.

- **When it opens.** `main.ts` `openedConsole` takes the service path when `KEYFLAP_MODE=service`
  and otherwise asks `devInstallAt(defaultDataDir())` (`console/dev-install.ts`): a
  `unlock.key` means the simple install (`simple`), a `broker.sqlite` or `signer/keys.enc.json`
  means dev mode (`dev`), nothing means no install. With no install, no terminal, or any argument
  (`keyflap --help`), the usage prints as before. A key file on Linux stops with setup's "the
  simple install is for macOS only" rather than opening a console on a state it can't run.
- **Unmissable.** Two things that can't be turned off, both in the brand repo's `brand/README.md`
  ("The unprotected console"). Before the overview, `console/unprotected.ts` shows a full screen: a
  big `!` drawn in block characters on an inverted paper flap beside "This is the unprotected
  version of Keyflap.", "It runs as you, so an agent running as you can read Keyflap's files and
  change its code." and "The protected version stops that. It is the full install: Tab shows the
  command." The reasons and `FULL_INSTALL_COMMAND` are behind Tab; Enter continues and Esc
  quits. On every screen the header reads `KEYFLAP  console  ! UNPROTECTED` with the flap in
  reverse video and bold (`Frame.alert`, `ScreenUiOptions.alert`); `paint` never drops the header
  row when an alert is set, even on a terminal too short for the page. No red anywhere: the flap
  is the brand's "denied, failed, broken" flap.
- **Same menu, minus two.** `console/dev-menu.ts` takes `SECTIONS` as they are and drops the
  actions whose command is `password-source trust`: in dev mode the signer runs your own tool as
  you, so there is nothing to trust or re-pin. It also drops Disconnect, whose list (`CONNECTED`)
  reads the service's status, which dev mode has not got, so it always said "No password manager
  is connected" (review of #48). A test pins the difference to those two actions, so a new action
  added to the table shows up in the dev console unless it is dropped on purpose.
- **Never as root.** `openDevConsole` refuses uid 0 before it reads anything, and `main.ts` says
  to run `keyflap` without `sudo`: `sudo -E keyflap` would otherwise act on the owner's
  `~/.keyflap` as root and leave root-owned files there (review of #48).
- **Commands.** `console/dev-commands.ts` is the dev counterpart of `runServiceCommand` for the
  same 17 command kinds, calling the functions `main.ts` calls in dev mode (so the validation,
  output and audit are the CLI's own). It rebinds each command's `dataDir` to the console's, so a
  console opened on one data dir never acts on another. The overview (`devSnapshot`) reads the
  database and `approver/devices.json` and needs no passphrase, so the console opens without one;
  it shows no approval-address line because the address latch lives in the signer. A dev data dir
  using the terminal approver shows "No phone paired" like any dir with none.
- **The passphrase.** `KeyStoreUnlock` (`console/key-store-unlock.ts`) wraps `passphraseAsker`
  (now exported from `setup/run.ts`) and is the one place the passphrase is asked and kept for
  the session. It is asked lazily, the first time a command or a setup flow opens the key store,
  in the console's own no-echo input (`ui.prompt.secret`), so a console that only looks never asks.
  `KEYFLAP_PASSPHRASE` is read at start and unset, as setup does, and answers the first ask. The
  simple install's `unlock.key` answers every ask with no prompt. `setupContext` takes it as
  `io.passphrase`, so setup's own flows (adding a password, pairing) and the dispatch share one
  value. A wrong passphrase asks again, up to three times. `approver list|remove` and
  `password remove` take an optional `unlock` in place of `getPassphrase`, so nothing reads the
  raw terminal under the screen. A hidden answer is recorded in neither the screen's answer
  line, the details nor the setup log; tests check the screens, details, log and the text printed
  after leaving for the passphrase and for a password typed in the Add flow.
- **Actions that need the key store free.** The dev signer is spawned per command and locks the
  store, so these need the daemon stopped: password add, import and remove, pairing, and listing
  or removing phones (`approver list|remove` spawn their own signer). Policy rules, saved-session
  changes (queued, the daemon applies them within 30 s), agents, status, the audit checks and the
  password list work while the daemon runs. `DaemonKeeper` (`console/daemon-keeper.ts`) owns the
  stop. It is `ctx.daemonStop`, which `waitForDaemonStopped` calls first, and the dispatch calls it
  before the three commands above. In the simple install it offers to stop the LaunchAgent
  (`launchAgentLoaded`, `stopLaunchAgent`) with the default no, and after the action `settle()`
  (run by the console loop after every action and when it quits) bootstraps the existing plist
  again (`resumeLaunchAgent`; the plist is not rewritten). In dev mode the daemon runs in
  another terminal, which the console can't and doesn't stop: it says so, waits for Enter or
  `skip`, and after the action prints the daemon command to start it again (`daemonCommand` from
  the saved setup state). A "no" or `skip` changes nothing and says so.
- **What the console does not repair.** If the console is killed (SIGKILL, closed terminal) while
  the LaunchAgent is stopped, it stays stopped until the next login or
  `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.keyflap.simple.plist`; Ctrl-C and
  Esc both restart it. The restart bootstraps the plist as it was and doesn't regenerate its
  arguments, so a flow that changes the daemon's flags (the password-manager flows in dev mode)
  needs setup's finish step, which writes the new plist.
- **Setup changes this needed.** `setupContext` takes `home` (so tests don't use the real one) and
  `quiet` (skip the unprotected banner, which the warning screen replaces); `DoctorOptions` takes
  `home`; `SetupContext.daemonStop` replaces the stop prompt; `ConsoleIo.settle` runs after each
  action. Setup's own screens are unchanged (`Frame.alert` defaults to null).
- **Try it without installing.** `pnpm console:preview --mode dev` and `--mode simple` run the
  console against a throwaway data dir in a temp home, with a real key store (passphrase
  `dev-world-passphrase-Zq7!`, printed by `--help`) and, for simple, a pretend LaunchAgent.
  `--capture DIR` writes the screens; `test/console-dev-world.ts` is the world and
  `test/console-dev.test.ts` and `test/dev-console.e2e.test.ts` (a real pty running `main.ts`
  with a temporary `HOME`) are the tests.
- **Only a real Mac can show:** the simple install's stop and restart through the real
  `launchctl` (tests use a fake that records the calls), the glyphs and colours of the warning
  screen in Terminal.app, and that macOS's "Background Items" notification doesn't reappear on the
  restart.
