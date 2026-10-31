# Approver integrity plan: the web approver shows what it signs, from code the core can't change

Status: **building** (owner decision 2026-10-20). Follows the owner's choice to make the web
phone approver the supported phone path and park the native iOS app (IMPLEMENTATION_NOTES,
"Phone approver: the web page is the supported path").

## Problem

M4's known limit: the approver page and its API are served by the core. The page shows the
core's display fields, then asks `/api/challenge` for an opaque hash and signs it with the
phone's passkey. Two consequences if the core is ever compromised (for example through a
browser exploit from a hostile site; Chromium runs inside aab-core):

1. **The card and the signature are unrelated.** The core can show "Sign in to example.com"
   and hand over the challenge of a statement for the owner's bank. Face ID shows only the
   approver's own rpId, so the owner can't tell. The signer then releases the bank's password
   or passkey signature, which is the one thing a compromised core can't get by itself.
2. **The live view's start check signs any challenge too.** `/handoff` signs the challenge
   `/api/handoff/challenge` returns. A compromised core can return an approval challenge
   there instead, so "Start live view" becomes a bank approval.
3. **The core serves the page code**, so even a page that checked the statement could be
   swapped for one that doesn't.

The native app never had this limit: its own code shows the request and builds the signed
bytes. This plan gives the web page the same property.

## Part 1: the page checks what it signs (all modes)

- New classic script `packages/approver/src/page/approval-check.js` (no imports; loaded by
  `app.html` and `handoff.html` before the page script). It defines canonical JSON (the
  signer's rules), SHA-256 through WebCrypto, `approvalChallenge`, `handoffStartChallenge`,
  `fillScope`, `checkCode`, and `checkStatement`.
- `/api/challenge` also returns the `statement` (and, for "add a phone", the new key's
  `descriptor`). The page **computes the challenge itself** from that statement after
  `checkStatement` passed, and never uses the server's `challenge` field.
- `checkStatement` is the Swift app's `StatementCheck`, extended to everything the web card
  can show: request id, `userVerified`, lifetime (≤ 5 min, ≤ 60 s when `strong`), freshness
  against the broker clock (`now` in `/api/state`), unknown fields refused, the site
  (`verifiedOrigin` equal to the card's, its host within `rpId`), kind/action/credential type
  (fill: `clientDataHash` = hash of the fill scope shown), the allow-for window signed
  exactly as shown, "Keep me signed in" signed exactly when ticked (and only on `strong`),
  P3b (handoff id, the single-use grant's window as shown, `clientDataHash` bound to the
  handoff for a passkey), and for "add a phone" the descriptor (hash, check code, key id,
  this approver's origin).
- `/api/handoff/challenge` also returns its `nonce`; the page computes
  `SHA-256("aab-handoff-start-v1\n" + id + "\n" + nonce)` itself, which can never equal an
  approval challenge (different domain prefix).
- Not bound, and can't be without the signer knowing more: the agent's *name* (the
  statement carries an agent id only on grants) and the "You said" words (`intentHash` is
  the core's own hash of an intent record it controls). Both stay display-only, as today.
  AGENT_ADMIN_PLAN decision 2 (`agentId` in every statement) would tighten the first.

Part 1 alone already fixes problems 1 and 2 against a core that lies through the API. Part 2
stops a core that rewrites the page.

## Part 2: the page is served by its own service (service mode)

- **`aab-approver.service`** runs as a new system user **`aab-web`**: a small front with
  node built-ins only (`packages/approver/src/front.ts`, entry
  `packages/cli/src/service/approver-main.ts`). It serves the page files, read once at start
  from the root-owned `/opt/aab/app`, and forwards `/api/*` to the core.
- **`aab-approver.socket`** (systemd, root) holds the approver listener (default
  `127.0.0.1:8766`, what `tailscale serve` points at) for as long as the socket unit is
  enabled, whether or not the service runs. The core can never bind it.
- **`aab-core-approver.socket`**: the core's API listener, `/run/aab-approver/api.sock`
  (root:aab-web 0660, directory root:aab-web 0750), passed to the core as an fd. Only root
  and aab-web can connect; the user and the agent can't.
- The front **filters what the core may return**: status, `content-type` only
  `application/json` (and `image/jpeg` for the live view's frame), `set-cookie` only the
  device cookie in its exact form, size caps; the security headers (CSP `script-src 'self'`,
  `nosniff`, …) are the front's own. So the core can't serve a script or document on the
  page's origin, or register a service worker.
- The front checks `Host` (the origin's host, or loopback behind the proxy) and forwards
  requests with `Host` set to the origin's host, plus only the request headers the API reads
  (`content-type`, `content-length`, `cookie`, `origin`, `sec-fetch-site`, `authorization`),
  and request bodies up to 16 KiB.
- **TLS** (`--tls-cert/--tls-key`) moves to the front: the sealed credentials load into
  `aab-approver.service`, not the core.
- The front's unit sandbox: `RestrictAddressFamilies=AF_UNIX` (it accepts on the inherited
  listener but can open no network sockets of its own), no state directory, read-only
  everything.
- **Dev mode** (`aab daemon --unprotected --approver phone`) is unchanged: one process serves
  page and API (the same user could edit either anyway). Part 1 applies there too.
- For people installing it: nothing new to do. `install.sh` creates the user, units and
  sockets; `uninstall.sh` removes them. The `tailscale serve` line is the same.

## Tests (invariants 5 and 6)

- `approver/test/inv5-approval-check.test.ts`: the page script run in Node (vm, WebCrypto):
  its challenge equals the signer's `approvalChallenge` and its handoff challenge equals the
  server's, over statements of every kind; every honest statement `buildStatement` produces
  passes; every mismatch (site, rpId, kind, fill scope, allow-for, keep, P3b, strong
  lifetime, unknown field, pair descriptor, request id, UV, expiry) is refused.
- `approver/test/inv5-approver-front.test.ts`: the front against a fake lying core:
  HTML/JS/unknown content types, extra or foreign cookies, service-worker headers, oversize
  bodies and non-`/api` paths never reach the phone; static files are the front's own.
- `core/test/inv5-lying-core.e2e.test.ts`: the real page in Chromium with a virtual
  authenticator, while `page.route()` makes the core's answers lie (another site's statement,
  an approval challenge as the handoff start): no assertion is made, the card says why, the
  request denies.
- `isolation/test/inv5-approver-isolation.test.ts`: in the service-mode container, the page
  comes from aab-approver; aab-core can't bind the approver port, can't write the page
  files, and the user can't connect to the core's API socket.

## Docs

IMPLEMENTATION_NOTES (status, this section, the M4 limit closed in service mode),
`phone-approver.md`, `service-mode.md`, ISOLATION_PLAN (who serves the page), CLAUDE.md
layout, SESSIONS_PLAN (P4 dropped).
