# M4 plan: phone approval

Scope (section 15): push + phone web page with a user-verification gesture, signed
approvals checked by the signer. Invariant test: 6.

Constraint from the parallel isolation work: the broker (core, signer, data dir) moves to
its own OS user. So no approver secret lives anywhere the agent's user can read, nothing
needs a TTY, and **no approval-forging key exists on the broker machine** in phone mode.

## Shape

```
 broker ──ApprovalRequest──► PhoneApprover ──push (content-free)──► phone
                                  ▲                                   │ opens approver page
                                  │  statement S (fixed when the user taps Approve)
                                  │◄──────── navigator.credentials.get({challenge: H(S), UV required})
                                  │
 broker ◄── { statement S, approverKeyId, webauthn: {authenticatorData, clientDataJSON, signature} }
   │
 signer: verifies the phone passkey's ES256 assertion itself (rpIdHash, origin, challenge = H(S),
         UP+UV flags, counter), then the usual statement checks
```

The phone's passkey **is** the approver key. The core never verifies-then-re-signs.

## Signer

- `SignedApproval` becomes a union: the existing Ed25519 form, or a `webauthn` form whose
  `approverKeyId` is the approver passkey's credential id. Challenge =
  `b64url(SHA-256(approvalSigningBytes(statement)))`.
- Approver passkeys live in the encrypted key store (`approvers`: credentialId, x, y,
  rpId, origin, signCount, createdAt). Public halves only, but trust decisions, so they
  belong to the signer, not the core.
- Ops: `list_approvers`, `add_approver`, `remove_approver`.
  - `add_approver` with no approvers paired: trust on first use (pairing is an admin act,
    gated by a one-time code only the broker's service account can read).
  - With approvers paired: needs an `approver.add` approval from an existing approver
    (webauthn), binding the new key (`credentialId` = new id, `clientDataHash` =
    H(new key descriptor)). A core bug can't add a key on its own.
  - `remove_approver` needs nothing (it only reduces trust).
- **Once any phone approver is paired, Ed25519 approver keys are ignored.** Restarting the
  daemon in terminal mode can't downgrade approvals.
- Webauthn approvals always require UV, `statement.userVerified = true`, ES256, no AT/ED,
  a counter that increases when non-zero.
- **High-risk origins (invariant 6):** a built-in list (government suffixes, major email /
  identity providers, payment and banking sites) plus extra domains from config. For a
  high-risk rpId / item domain / origin host the signer requires a webauthn approval with
  UV and a lifetime ≤ 60 s, whatever the core says. Shared module `@aab/signer/risk`.

## Approver (`PhoneApprover`, `@aab/approver`)

- HTTPS server in the daemon on an origin the user configures (their own cert, e.g.
  `tailscale cert`). No relay we operate (open question 6). `http://*.localhost` is
  accepted for tests only.
- Pairing: when no approver is paired (or with `--pair`), the daemon creates a one-time
  code (10 min) and writes the URL (code in the fragment) to its log and to
  `<dataDir>/approver/pairing-url` (0600). The phone registers a passkey (ES256, UV
  required, attestation none); the server verifies the registration and calls
  `add_approver`. The phone gets a device cookie (`__Host-`, HttpOnly, SameSite=Strict);
  its hash is stored in `<dataDir>/approver/devices.json` (0600).
- Approving: the page polls pending requests (device cookie), shows only
  `ApprovalRequest.display` (textContent, control/bidi characters replaced), and on
  Approve fetches a fresh statement, runs `navigator.credentials.get`, posts the
  assertion. The server pre-checks it with the signer's own verifier; the signer decides.
- Push: Web Push (VAPID, aes128gcm), payload "Approval requested", nothing else. VAPID
  key in `<dataDir>/approver/vapid.json` (0600). Optional: the open page works without it.
- Hardening: Host and Origin checks, strict CSP, `frame-ancestors 'none'`, no-store,
  small JSON bodies, pending requests and decisions only with a device cookie.
- Terminal approver: denies `ask-strong` requests without prompting (it can't verify the
  user). Still dev-only.

## Core

- `ApprovalRequest.policy = { tier: 'ask' | 'ask-strong' }` (not displayed). `ask-strong`
  when the rpId / domain / origin is high-risk. M5 adds the rest of section 9.
- `startDaemon({ makeApprover })`: the approver is built after the signer starts, with a
  narrow signer port (list/add approvers). `highRiskDomains` goes to both broker and signer.

## CLI

- `aab daemon --approver phone --approver-origin URL [--approver-listen host:port]
  [--tls-cert F --tls-key F] [--pair] [--high-risk DOMAIN]...`. Phone mode needs no TTY
  and loads no Ed25519 approver key.
- `aab approver list | remove <id>` (daemon stopped, like `aab password`).

## Invariant 6 tests

- Signer (`packages/signer/test/inv6-*.test.ts`): webauthn approvals verified end to end;
  bad challenge / origin / rpIdHash / signature / missing UV / counter regressions refused;
  high-risk rpIds and items refuse Ed25519 approvals (even ones claiming UV) and long
  lifetimes; Ed25519 ignored once a phone is paired; `add_approver` TOFU then approval-gated.
- E2E (`packages/core/test/inv6-phone-approval.e2e.test.ts`): a separate "phone" browser
  with a CDP virtual authenticator (test-only) pairs, receives the request, approves with
  UV; the test RP sees UV. High-risk origin with the terminal/scripted approver → denied,
  no prompt. Phone authenticator without UV → denied. Push delivered to a local fake push
  service, decrypted, content-free.
