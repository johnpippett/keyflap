# M3 plan: passwords and TOTP

Status: **done**. Invariant tests: IMPLEMENTATION_NOTES "Status". Phase 2 done: Proton Pass,
then 1Password.

Scope (section 15): fill flow, redaction, post-fill verification, first external
`CredentialSource` adapter. Invariant test: 8. Phase 1 (this plan, built first) is
everything except the external adapter; phase 2 is the adapter, once the owner picks
which password manager it targets (section 6.7: verify what its CLI can do first).

## Shape

```
 agent ──auth_login──► AgentPort ──► Broker.fill ──► intent ─► approval ─► signer.release_secret
                          │                                                   (per field, once)
                          └─ FillDriver (Playwright, trusted side): find fields, fill via
                             ElementHandle, press Enter, watch for the next step, verify
```

## Native store (signer)

- `KeyStore` gains `items: { [itemId]: { domain, password, totp?, createdAt } }` in the
  same encrypted file. `totp = { secret (base32), algorithm SHA1|SHA256|SHA512, digits
  6..8, period 15..120 }`. Older files without `items` load as empty.
- New signer ops (authenticated channel, as today):
  - `store_item { domain, password, totp? }` → `{ itemId }`. No approval: it releases
    nothing, and only the process holding the channel key can call it.
  - `delete_item { itemId }` → `{ deleted }`.
  - `release_secret { itemId, field: 'password' | 'totp', approval }` → `{ value }`.
    The signer computes TOTP codes itself; the seed never leaves it.
- A fill approval is `kind: 'fill'`, `rpId` = the item's registrable domain,
  `credentialId` = itemId, `clientDataHash` = SHA-256 of the fill scope
  `aab-fill-v1\n<fields, comma-separated>`, plus the usual origin/intent/expiry fields.
  The signer checks signature, freshness, kind, item, domain (origin host is the domain
  or a subdomain; the core does the public-suffix check), that the field is in the scope,
  and releases each field **at most once per approval**.

## Core

- `credentials` rows: `type='password'`, `registrable_domain`, `username` (user-supplied
  via the CLI; never shown in prompts), `signer_ref = itemId`, new column `has_totp`.
- Matching: the verified origin's registrable domain equals the item's domain (invariant
  3 for passwords). Several items for one domain → deny `ambiguous_credential` (same as
  passkeys: choosing needs an account label in the prompt).
- `auth_login` picks the method: a passkey ceremony in flight (or recently ended) on the
  page → its outcome; else a fillable login form + a matching password item → fill; else
  a matching passkey → wait for the page's ceremony; else `unsupported/no_credential`.
- Fill flow (one approval for the whole operation):
  1. Detect a step on the agent's current page, main frame only: exactly one visible
     `input[type=password]` that is not `autocomplete=new-password` (plus a username field
     in the same form), or a one-time-code field, or (identifier-first) a lone username
     field. More than one candidate → deny `ambiguous_form`. A form whose `action` (or a
     submit button's `formaction`) points at another registrable domain → deny.
  2. Intent → approval (`credentialType: 'password' | 'password+totp' | 'totp'`, action
     `sign-in`). Scope = password and/or totp.
  3. Take the agent's port lock (no other tool runs until the fill ends), re-check the
     page's origin equals the approved one, resolve fields to ElementHandles (they fail if
     the document changes), get each secret from the signer just before filling, fill,
     press Enter.
  4. After submit, watch up to `stepTimeoutMs` for the next step (identifier → password →
     one-time code), at most one of each, same registrable domain. Same approval.
  5. Post-fill verification: no input on the page may still hold a filled secret; any that
     does is cleared. Form still there → `{status:'failed'}`; otherwise `success`.
- Every value the broker filled is remembered by the agent's session (until its context
  closes) and scrubbed from **every** tool output (url, title, snapshot), raw and in
  JSON-, URL- and form-encoded forms. This covers "show password" toggles, pages that echo
  the value into text, and GET forms that put it in the URL.
- Audit: `request {kind:'password.fill'}`, `approval`, `fill.released {requestId,
  itemId, field}`, `fill.completed {requestId, outcome, steps}`, `denied`. No values.

## MCP

- `AuthStatus.credentials[].type`: `'passkey' | 'password' | 'totp'`.
- `AuthOutcome` gains `{status:'failed'}` (filled and submitted, but the form stayed).
- Tool descriptions updated; still seven tools, no new inputs.

## CLI

- `aab password add <site> [--username U] [--totp]` prompts (no echo) for the password
  and, with `--totp`, the TOTP secret or `otpauth://` URI. Never from argv or env.
- `aab password list` (site, username, totp yes/no, id; never secrets), `aab password
  remove <id>`.
- They spawn their own signer on the key store, so the daemon must be stopped (the
  single-instance lock enforces it). An admin socket on the daemon is M5 work.

## Test RP

- Identifier-first login (`/password/login-id` → `/password/login-pw`), plus the existing
  password and password+TOTP flows.

## Invariant 8 tests (`packages/core/test/inv8-*.test.ts`)

- Password + TOTP sign-in through MCP only: neither the password, the seed, nor any code
  in a ±3-step window appears in anything the MCP server sent, the audit log or the DB.
- After a fill: "show password" toggle, a page that copies the value into text, a GET
  form that puts it in the URL → absent from snapshot, url and title.
- Post-fill verification: a form that doesn't submit is cleared, outcome `failed`.
- Cross-site: an item for `rp.localhost` is never offered on `evil.localhost`; a form
  posting cross-site is refused; the signer refuses a release whose origin is outside
  the item's domain, a field outside the scope, a second release, and a passkey approval.
- No live intent → denied without a prompt.
