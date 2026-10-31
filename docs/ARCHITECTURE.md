# Keyflap — Architecture

Status: the design contract. Implemented through the v1 milestones (section 15), plus
service mode on Linux and the sessions work (saved browser state, human handoff).
Deviations and decisions are recorded in
[IMPLEMENTATION_NOTES.md](./IMPLEMENTATION_NOTES.md). Scope: self-hosted, for a single user
on their own machines. (Keyflap was called agent-auth-broker while it was designed; the
internal `@aab/*` package names and the `aab-…-v1` protocol tags come from that. The
command is `keyflap`.)

> Implementation notes that deviate from or tighten this document are tracked in
> [IMPLEMENTATION_NOTES.md](./IMPLEMENTATION_NOTES.md). This file is the design contract;
> change it deliberately.

## 1. Problem

AI agents that drive a browser hit a wall at login. Today's options are (a) re-enter passwords into the agent vendor's vault or (b) take over the agent's browser and sign in by hand. Neither works with passkeys, and 2FA is awkward or exposes codes to the model. Password managers with agent support cover passwords and TOTP but not passkeys.

## 2. What this is

A broker that sits between an agent and the user's credentials. When an agent-driven browser reaches a login, the broker:

1. Determines the real origin itself, from a source the agent cannot influence.
2. Checks that the user recently asked for something (intent binding).
3. Asks the user to approve on a separate device, showing the user's own words and the verified origin.
4. Performs the login (passkey assertion, or password/TOTP fill) without the agent ever holding a secret.

The agent sees "login succeeded" or "login denied". Nothing else.

## 3. Goals and non-goals

### Goals (v1)

- Passkey registration and authentication for agent-driven browsers, on unmodified websites.
- Password and TOTP fill on the same rail, with the same approval flow.
- One MCP endpoint that any MCP-capable agent can connect to.
- Self-custody: keys and credentials stay on hardware the user owns.
- Just-in-time access per site. No moving items between vaults.
- Full audit log of every request, approval, denial, and fill.

### Non-goals (v1)

- Hosted multi-tenant service. No other people's credentials on our infrastructure.
- Closed cloud agents whose browser we cannot reach (Muse, Dots).
- Policing what the agent does after login (action-level scoping). See open questions.
- Portable memory / profile layer. Deferred to a later phase; keep the policy model general enough to add "memory" as another resource type.
- Payments. Card networks are standardizing this separately.
- CAPTCHA solving or bot-detection evasion. Out of scope permanently. A human handoff (`browser_handoff`: the user completes a site's human check themselves, by hand, in a live view of the agent's page on their paired phone) is not CAPTCHA solving: the broker never solves, clicks or answers a check on its own.

## 4. Design constraints

- **The browser runs on the user's own device.** The user's machine talks to the website; the broker is a local tool the user operates. Do not design anything where a server we operate connects to third-party sites on a user's behalf.
- **Our passkey is always an additional credential.** Never remove or replace the user's existing sign-in methods. If the broker breaks, the user logs in the way they do today.
- **No disguise.** Do not spoof or hide automation to defeat a site's detection. Support a per-origin denylist so a site that objects can be turned off.
- **Fail closed.** Any error, timeout, or ambiguity results in a denial.

## 5. Security invariants

These are the contract. Each one needs at least one automated test. Do not weaken any of them to make a feature work; stop and flag it instead.

1. The agent process never receives secret material: private keys, passwords, TOTP seeds, or TOTP codes.
2. The origin used for any credential operation comes from the browser's trusted side (CDP / Playwright frame URL / extension API). Never from the agent, never from page-supplied data. The document's own security origin, also read on the trusted side, must equal it: a document with an opaque origin (a sandboxed page) or any other mismatch is denied.
3. A credential is bound to its rpId (passkeys) or registrable domain (passwords). The broker enforces WebAuthn's rule that the rpId must be a registrable-domain suffix of the verified origin.
4. No approval prompt is shown unless there is a live user intent captured out-of-band (section 8). Requests without one are auto-denied and logged.
5. The approval prompt shows only: the user's verbatim words, the verified origin, the agent's identity, and the credential type. Never text written by the agent or the page.
6. Every signing or fill operation requires an approval decision under policy (section 9). High-risk origins always require fresh user verification on the approver device.
7. The agent has no raw debugging access (CDP) to any browser the broker manages. It acts only through broker-mediated tools.
8. After a password or TOTP fill, the secret is not readable by the agent through any tool output (snapshots, DOM reads, screenshots of plaintext fields).
9. The signer accepts requests only from the broker core, over an authenticated local channel.
10. Every request, decision, and operation is written to an append-only, hash-chained audit log.

## 6. Components

```
 +-----------+   MCP    +-----------------------------------------------+
 |   Agent   |<-------->|                 Broker core                   |
 +-----------+          |  policy | intent store | audit | orchestration |
       ^                +---+----------+-----------+-----------+--------+
       | user msg           |          |           |           |
 +-----+------+   intent    |          |           |           |
 | Agent host |-------------+     +----v----+ +----v-----+ +---v-----------+
 |   hook     | (side channel)    | Signer  | | Approver | | Browser shim  |
 +------------+                   | (keys)  | | (phone)  | | (managed      |
                                  +---------+ +----------+ |  Chromium)    |
                                                           +-------+-------+
                                                                   |
                                                              Websites
```

### 6.1 Broker core

Long-running local daemon. Owns policy, the intent store, the audit log, and orchestration of every flow. Exposes the MCP server and a local admin CLI.

### 6.2 Signer

Separate process. Holds private keys and password/TOTP secrets. Exposes a tiny API over a unix socket with peer-credential checks:

- `create_credential(rpId, userHandle) -> credentialId, publicKey`
- `sign(credentialId, authenticatorData, clientDataHash, approvalToken) -> signature`
- `get_secret_for_fill(itemId, approvalToken) -> secret` (returned only to the broker core's fill routine)

The signer verifies the approval token itself. It should be impossible to obtain a signature without one, even if the broker core has a bug.

v1: software keys, encrypted at rest, unlocked by approval. Later: keys in the phone's secure hardware so approving and signing are the same act (section 12).

### 6.3 Browser shim

Makes the broker act as the passkey authenticator for a browser. v1 implementation is a broker-launched Chromium via Playwright:

- `context.addInitScript` overrides `navigator.credentials.create` and `.get` in every frame, and stubs the capability checks sites use (`PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable`, conditional mediation availability).
- The override forwards the request options to the broker via `context.exposeBinding`. The binding callback receives the frame from Playwright; the broker reads the origin from `frame.url()` on the trusted side. A frame URL is not the document's origin (a page served with `Content-Security-Policy: sandbox`, as sites do for user uploads, has the site's URL and an opaque origin), so the broker also requires the security origin Chromium reports for the frame's current document, read from the CDP events of Playwright's own connection, to equal the URL's origin. The same check runs before every password fill step.
- The broker builds `clientDataJSON` and `authenticatorData` itself, gets the signature from the signer, and returns a response the override wraps into a `PublicKeyCredential`-shaped object (ArrayBuffers, `getClientExtensionResults`, `toJSON`).

The page's script world is untrusted. A malicious page can only ask for an assertion; it cannot choose the origin the broker records, and the rpId check stops it from requesting another site's credential.

v1 rules: top-level frames only (deny all iframes), HTTPS only (plus `http://localhost` and `*.localhost`, which browsers treat as secure contexts; used by the local test RP and dev, accepted in every mode), canonical host names only (no trailing dot).

Do not use Chrome's built-in CDP virtual authenticator for real credentials: it holds the private key inside the browser and exposes it through `WebAuthn.getCredentials`.

Second implementation (later): a browser extension for the user's everyday Chrome, with the override injected in the main world and the origin taken from the extension's trusted sender info, talking to the broker over native messaging.

### 6.4 Approver

The device where the user says yes or no. Phased:

- Phase A: terminal / desktop prompt on the same machine (development only).
- Phase B: a web page on the user's phone, reached by push notification, where approval requires a WebAuthn user-verification gesture (Face ID / fingerprint) against a passkey registered with the broker.
- Phase C: native phone app holding the signing keys in secure hardware.

Status: Phases A and B are built; the phone web page (B) is the supported approver. Phase C
(the `ios/` app) is parked: its broker side is merged and tested, the app isn't shipped.

The approver channel is end-to-end authenticated. An approval is a signed statement over `(requestId, verifiedOrigin, credentialId, intentHash, expiry)`. The signer checks this before signing. It binds the origin, rpId (with its own public suffix list), credential and expiry; `intentHash` is the core's hash of an intent record the core holds, so the signer can only require that one is present. The user's words are bound by what the phone shows, not by the signer (docs/APPROVER_INTEGRITY_PLAN.md).

### 6.5 MCP server

The agent-facing surface. Tools:

| Tool | Purpose |
|---|---|
| `browser_open(url)` / `browser_click` / `browser_type` / `browser_snapshot` | Drive the managed browser. Snapshots redact password and one-time-code fields. |
| `auth_status()` | For the current page: does the broker have a credential for this origin, and of what type. No secrets. |
| `auth_login()` | Ask the broker to sign in on the current page. Broker picks the method, runs approval, performs it, returns success/denied/unsupported, or `challenge` when it submitted a password form and the site answered with a known human check. |
| `auth_enroll_passkey()` | On a site's "add a passkey" page, let the broker register its own passkey (approval required). |
| `browser_handoff({timeoutMs?})` | After a `challenge` (or `humanCheck: true`), ask the user to complete the human check themselves from their paired phone: a live view of this page only, started with a user-verification gesture, on a screen with no approval action. Needs a detected check and a live intent; while it is open every credential operation of that agent is denied and its other tools fail. Returns done/cancelled/expired/pending/denied/unsupported; the agent never sees frames or the user's input. |

`browser_snapshot` and `auth_status` also report `humanCheck: boolean`: the page shows a known human check, detected from structured trusted-side signals (frame URLs, response headers), never page text.

Passkey prompts triggered by the page itself are intercepted automatically; `auth_login` exists so the agent has an explicit way to say "I'm at a login wall".

No tool accepts an origin or a justification from the agent as input to an approval.

### 6.6 Intent hook

A small integration in the agent host (not the model) that forwards each user message to the broker. See section 8.

### 6.7 Credential sources

Interface `CredentialSource` so passwords and TOTP can come from more than one place:

- Native store (inside the signer).
- Adapters to an existing password manager's CLI, so the user does not have to migrate or shuffle items between vaults. Verify what each CLI can actually do before building an adapter.

Passkey private keys always live in the signer.

## 7. Core flows

### 7.1 Passkey sign-in

1. Agent navigates the managed browser to a site; the page calls `navigator.credentials.get`.
2. Shim forwards the options. Broker reads the verified origin from the frame.
3. Broker validates rpId against origin, finds matching credentials, checks policy and the intent store.
4. No live intent, or policy says deny: return `NotAllowedError` to the page, log, done.
5. Broker sends an approval request to the approver: user's verbatim message, verified origin, agent name.
6. User approves with user verification. Approver returns a signed approval.
7. Broker builds:
   - `clientDataJSON`: `{"type":"webauthn.get","challenge":<b64url>,"origin":<verified origin>,"crossOrigin":false}`
   - `authenticatorData`: `SHA-256(rpId)` (32 bytes) | flags | signCount (4 bytes)
8. Signer checks the approval and returns an ECDSA P-256 / SHA-256 signature (DER) over `authenticatorData || SHA-256(clientDataJSON)`.
9. Shim resolves the page's promise. The site completes login.
10. Audit entry written.

### 7.2 Passkey enrollment

Same shape with `navigator.credentials.create`:

- Type `webauthn.create`, attestation format `none`.
- `authenticatorData` includes attested credential data: AAGUID, credential ID, COSE-encoded public key (ES256, alg -7).
- Honor `excludeCredentials`.

v1 enrollment is manual: the user (or the agent, with approval) gets to the site's "add passkey" page while already signed in, and the broker registers its own credential. Per-site automation of that navigation is a later phase.

### 7.3 Password and TOTP

1. Agent calls `auth_login()` on a login page.
2. Broker reads the verified origin, finds a matching item by registrable domain, runs the same intent + approval steps.
3. Broker locates the fields and fills them from the trusted side, then submits.
4. If a one-time code is requested, broker computes TOTP and fills it the same way, in the same approved operation.
5. Broker verifies the secret fields are gone or cleared before handing control back. Snapshots redact these fields regardless.

SMS and email codes are out of scope for v1.

## 8. Intent binding

Problem: a hijacked agent can make any request look reasonable. The approval prompt must show something the agent cannot write.

- The agent host forwards each raw user message to the broker's intent endpoint through a channel the model has no access to (separate unix socket or token held by the host process, never placed in model context).
- The broker stores `{intentId, text, agentId, timestamp}` with a short TTL (default 10 minutes).
- An approval request attaches the most recent live intent for that agent. The prompt shows its text verbatim with its timestamp.
- No live intent: auto-deny.
- The approval signature covers the intent hash, so an approval cannot be replayed against a different request.

v1 hosts: whatever self-hosted agent stacks are in use, via their message hooks or middleware. One reference integration is enough for v1.

Known limit: this proves the user asked for something recently, not that this login serves that request. The human judges the match. A later risk-scoring layer can assist but must take only structured inputs (origin, timing, history), never page or agent text.

## 9. Policy

Per-origin, per-agent rules stored by the broker:

- `deny`: never.
- `ask`: approval every time (default for everything).
- `ask-strong`: approval with fresh user verification, short expiry, no batching. Mandatory default for financial, government, email, and identity-provider origins.
- `allow-for(duration)`: after one approval, further logins to this origin by this agent are allowed for a window. Never available for `ask-strong` origins.

Also per origin: session TTL, after which the broker clears that origin's cookies and storage in the managed browser.

## 10. Data model (SQLite, broker core)

- `agents(id, name, public_key, created_at)`
- `credentials(id, type[passkey|password|totp], rp_id, registrable_domain, user_handle, username, public_key, signer_ref, source, created_at)`
- `policies(origin_pattern, agent_id, mode, session_ttl, updated_at)`
- `intents(id, agent_id, text, created_at, expires_at)`
- `requests(id, agent_id, verified_origin, credential_id, intent_id, kind, status, created_at, decided_at)`
- `audit(seq, prev_hash, hash, ts, event_type, payload_json)`
- `session_clocks(agent_id, origin, host, started_at)`: session-TTL clocks (section 9), persisted.
- `browser_sessions(agent_id, site, cookies, origins, saved_at)`: an index of each agent's saved, encrypted browser state (counts only; the state itself is a file encrypted with a key from the signer).
- `session_clear_requests(id, agent_id, site, requested_at, via)`: session clears queued by the admin CLI.
- `persist_optins(agent_id, site, created_at, via)`: the user's opt-ins to keep a high-risk site's session saved ("Keep me signed in"), written only by the user (CLI, admin socket, or their own signed approval).

Secrets never appear in this database. `signer_ref` is an opaque handle.

## 11. Threat model

| Threat | Mitigation |
|---|---|
| Prompt-injected agent requests a login the user didn't want | Intent binding, verbatim prompt, default `ask`, audit |
| Phishing page asks for a credential | Verified origin + rpId binding; credential simply doesn't match |
| Relay: attacker page proxies a real site's challenge | Origin in signed clientDataJSON is the attacker's origin, so the real site rejects it |
| Agent tries to read a filled password | Snapshot redaction, fill-and-submit, post-fill check, no raw CDP |
| Agent tries to call the signer directly | Unix socket peer credentials + signer-verified approval tokens |
| Approval fatigue | Auto-deny without intent, one pending approval per agent (the rest denied, never queued), handoff push limits, `ask-strong` tier, no agent text in prompts |
| Stolen phone | User verification on every approval; revoke approver from CLI |
| Broker core bug | Signer independently verifies approvals; fail closed |

Out of scope: a fully compromised OS on the machine running the broker.

## 12. Later phases (do not build yet)

- Keys held in phone secure hardware, so the phone is the authenticator and the broker only relays.
- Threshold (split-key) signing between phone and a server, for a hosted version where the service cannot sign alone. Requires external cryptographic review.
- Extension shim for the user's everyday browser.
- Per-site enrollment automation.
- Import/export via the FIDO credential exchange format.
- Alignment with the FIDO agentic-authentication delegation spec once published.
- Memory/profile as another policy-governed resource.
- Action-level session policy (what the agent may do after login).

## 13. Stack (v1)

Originally a recommendation; this is what was built. The departures from the original
suggestion (`@noble/*`, a CBOR library, `better-sqlite3`) and why are in
IMPLEMENTATION_NOTES.md, "Stack changes".

- TypeScript run directly by Node 22's type stripping (no build step; `tsc --noEmit` for
  type checking), pnpm monorepo.
- Playwright (Chromium) for the managed browser.
- `@modelcontextprotocol/sdk` (Streamable HTTP) and `zod` for the MCP server.
- `node:crypto` for every cryptographic operation (P-256 ECDSA, Ed25519, AES-GCM,
  scrypt, HMAC); a small built-in CBOR encoder in the shim for COSE keys and attestation
  objects.
- `node:sqlite` for storage.
- `tldts` for registrable domains (Public Suffix List).
- `@simplewebauthn/server` for the local test relying party, and in the approver for
  pairing phones (registering the approver passkey). The signer verifies approval
  assertions itself, with `node:crypto`.
- Signer as its own package and process from day one, so it can be rewritten or moved to
  another device without touching the rest. It has **zero npm dependencies**: only the
  workspace package `@aab/sources` (password-manager adapters), itself built-ins only.

Keep the signer's dependency list minimal. Ask before adding anything to it.

## 14. Repo layout

```
packages/
  core/        broker daemon: orchestration, origin/rpId rules, policy, intents, audit,
               SQLite, password fill and output scrubbing, allow-for grants, session TTL,
               human-check detection, saved browser state, human handoff
  signer/      separate process: encrypted key store, approval verification (Ed25519 and
               phone WebAuthn assertions), high-risk list, socket server; service mode
  shim/        Playwright launcher, page override script, WebAuthn encoding
  mcp/         MCP server and tool definitions
  approver/    approval transports: terminal, phone web page (pairing, Web Push, handoff
               live view) and its service-mode front; native iOS API (parked)
  sources/     CredentialSource adapters run inside the signer (Proton Pass via pass-cli)
  test-rp/     local relying party for end-to-end tests
  cli/         `keyflap`: daemon, admin CLI (agents, passwords, approvers, policy, sessions,
               status, audit), Claude Code hook; service-mode entry points
  install/     service-mode installer (Linux, systemd)
  isolation/   service-mode isolation tests against a third uid
ios/           native iPhone approver (parked)
docs/
  ARCHITECTURE.md, IMPLEMENTATION_NOTES.md, *_PLAN.md, integrations/
```

## 15. Milestones

All six are done (status and the invariant tests for each: IMPLEMENTATION_NOTES.md,
"Status"). Kept as the original plan.

- **M0 Skeleton.** Monorepo, CI, local test RP that supports passkey register/login and password+TOTP login.
- **M1 Passkey core.** Shim + signer + terminal approver. End-to-end: register and authenticate against the test RP with keys never in the browser process. Tests for invariants 2, 3, 9.
- **M2 Agent surface.** MCP server, mediated browser tools, intent hook with one reference host integration, auto-deny without intent, audit log. Tests for invariants 1, 4, 5, 7, 10.
- **M3 Passwords and TOTP.** Fill flow, redaction, post-fill verification, first external `CredentialSource` adapter. Test for invariant 8.
- **M4 Phone approval.** Push + phone web page with user-verification gesture, signed approvals checked by the signer. Test for invariant 6.
- **M5 Policy and sessions.** Risk tiers, `allow-for`, session TTL cleanup, denylist, CLI polish.

Then validate against a handful of real sites the user relies on, starting with low-stakes ones.

## 16. Open questions

1. Authenticator flags: what should backup-eligible / backup-state report for software keys, and what AAGUID should we present? Some sites treat these differently.
2. Sites that enforce attestation or allowlist authenticators will reject us. How common is that among the sites that matter?
3. How does the shim behave with conditional UI (autofill-style passkey prompts) and with sites that feature-detect in unusual ways?
4. Intent-to-request matching is human-judged in v1. What structured signals could tighten it without trusting agent text?
5. Action-level scoping after login: proxy the session, or wait for site-side delegation standards?
6. Phone transport without operating a relay: local network / private mesh only, or is a minimal relay acceptable for a self-hosted v1?
7. Recovery: if the signer's keys are lost, the user re-enrolls per site. Is an encrypted backup worth the added attack surface?

## 17. Instructions for the implementing agent

Written for the first implementation (M0, M1); the rules still apply to changes.


- Start with M0 and M1 only. Do not scaffold later milestones beyond empty packages.
- Write the invariant tests alongside the code that satisfies them. A milestone is not done until its invariant tests pass.
- Treat section 5 as fixed. If an invariant blocks progress, stop and ask rather than relaxing it.
- Never log secrets, challenges' signatures aside. Audit payloads contain identifiers and origins, not key material or passwords.
- Use only the local test RP in automated tests. Do not point tests at third-party websites.
- Keep the signer boundary real from the first commit: separate process, socket API, no shared memory with the core.
