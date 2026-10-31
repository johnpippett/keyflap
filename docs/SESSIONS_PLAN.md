# Sessions plan: persistent browser state, honest challenge outcome, human handoff

Context: the Hugging Face demo (2026-10-13). The owner typed "Sign in to huggingface.co for
me", approved on the phone with Face ID, and the broker filled the Proton Pass password. Hugging
Face then showed an AWS WAF "Let's confirm you are human" page, and `auth_login` reported
`success` because the form went away (IMPLEMENTATION_NOTES "Real-site validation", known limit).

Three pieces, all within ARCHITECTURE sections 3 and 4:

1. **Honest outcome.** Post-fill verification reports `challenge` when a known human check
   replaces the form. Detection uses structured signals only. The agent also gets a
   `humanCheck` flag in `auth_status` and `browser_snapshot`.
2. **Persistent per-agent browser state.** Each agent's cookies and storage survive a daemon
   restart, so a restart no longer looks like a brand-new browser. It is still one browser per
   broker.
3. **Human handoff.** The owner's phone shows a live view of only that agent's page. The owner
   taps and types to pass the check, taps Done, and the agent continues.

The broker never solves, clicks or answers a challenge itself. Detection is used only to report
honestly and to offer the owner a handoff.

Invariants touched:

- 1: saved state is unreadable to other uids; the agent never gets frames or the owner's input.
- 2: the handoff's host comes from the frame URL.
- 4: a handoff needs a live intent.
- 5: the live view is never on a screen with an approval action. **See the flag below.**
- 6: no credential operation runs while a handoff is open.
- 7: no new CDP sessions on managed pages.
- 8: saved state is filtered, and text the owner types is scrubbed. **See the flag below.**
- 10: every save decision, clear and handoff is audited.

## Section 3/4/5 check (read first)

- **Section 3 (no CAPTCHA solving, permanently).** Nothing here solves or automates a
  challenge. The handoff is the owner taking over the agent's browser by hand, routed through a
  paired phone. The broker relays the owner's taps and keystrokes only while the owner holds the
  live view.
- **Section 4 (no disguise).** Unchanged. The HeadlessChrome user agent, `navigator.webdriver`
  and Playwright's flags all stay. Keeping cookies is what every browser does; no fingerprint,
  user agent or timing is altered. A site that still refuses the browser after a human passed its
  check is a correct outcome, not a bug to work around. The denylist turns both persistence and
  handoff off for a site.
- **Flag: invariant 5.** The live view puts page-authored pixels on the owner's approver device.
  Invariant 5 governs the approval prompt, and this plan keeps those pixels off any screen that
  has an approval action:
  - the live view is its own document (`/handoff`), with its own script;
  - approvals never render there;
  - while a handoff is open, every credential operation from that agent's browser context is
    denied before it reaches the approver (`handoff_open`).

  The owner decides whether this boundary is acceptable (decision 1).
- **Flag: invariant 8.** Persistence would weaken it unless filtered. Today the scrub list
  (`AgentSession.filledSecrets`) dies with the context, and so does the context's storage. A site
  that copies a filled password into a cookie or localStorage would otherwise survive a restart
  while the scrub list does not. The fix is save-time filtering (below). The existing known limit
  (transformed copies such as base64 or upper-case are not caught) now also lasts across restarts.
- No other invariant needs weakening. The live view uses `page.screenshot` and `page.mouse` /
  `page.keyboard` on Playwright's existing page session, so there is no attach or detach and no
  WebAuthn environment reset.

## 1. Honest outcome: `challenge`

### Detection (`packages/core/src/challenge.ts`, new)

Detection reads only trusted-side, structured signals: Playwright frame URLs, request URLs,
main-document response status and headers, and frame-element visibility. Page text is never used.

- **`ChallengeWatch` per page.** `AgentSession.track()` attaches it. It listens to
  `page.on('request' | 'response' | 'framenavigated')` (Playwright events, no CDP session) and
  records:
  - the main-frame navigation response's status and challenge headers;
  - the hosts of challenge scripts and frames requested since the last main-frame navigation.
- **`CHALLENGE_PROVIDERS`.** Hosts are matched on label boundaries, so
  `x.captcha.awswaf.com.evil.localhost` does not match.

  | Provider | Signal |
  |---|---|
  | AWS WAF | header `x-amzn-waf-action: captcha` or `challenge` (status 405 / 202); hosts `*.captcha.awswaf.com`, `*.token.awswaf.com` |
  | Cloudflare | header `cf-mitigated: challenge`; frame host `challenges.cloudflare.com` (Turnstile, managed challenge) |
  | hCaptcha | frames on `*.hcaptcha.com` with `#frame=checkbox` or `#frame=challenge` (not `checkbox-invisible`) |
  | reCAPTCHA | `www.google.com/recaptcha/`, `www.recaptcha.net/recaptcha/`: `api2` or `enterprise` `/anchor` without `size=invisible`, or a visible `bframe` |
  | Arkose | `*.arkoselabs.com`, `*.funcaptcha.com` |
  | DataDome | `geo.captcha-delivery.com` |
  | HUMAN / PerimeterX | `captcha.px-cdn.net`, `*.perimeterx.net` |

- **`detectHumanCheck(page, watch)`** returns `{provider} | null`. It is positive when either:
  - the current main document came with a challenge header; or
  - a frame on a challenge host is an interactive widget, visible (`frame.frameElement()` then
    `isVisible()` and `boundingBox()` of at least 60×60 CSS px).

  A script host alone is not enough: login pages routinely load invisible reCAPTCHA or Turnstile.
  A page can spoof detection; that only causes a `challenge` result or the offer of a handoff,
  never a credential operation or broker text.
- **Test-only option** `DaemonOptions.challengeHosts` (same precedent as `launchArgs`) adds a
  `*.localhost` frame host, because automated tests never touch the real provider hosts.

### Fill outcome

- `packages/core/src/fill.ts`: `FillDriverOptions` gains
  `humanCheck: () => Promise<{provider} | null>`.
  - In `next()`: if the form is still there but a challenge has shown for at least 750 ms (for
    example an hCaptcha popup over the form), end with `challenge`.
  - In `run()`: when the form went away or the page left the origin, wait up to 2 s
    (`waitForLoadState('load')`), check once, and return `'challenge'` instead of `'success'` if
    one is found.
  - Post-fill clearing runs as before, whatever the outcome.
- `packages/core/src/broker.ts`:
  - `FillTarget.perform` and `FillOutcome` gain `'challenge'`.
  - The audit becomes `fill.completed {…, outcome: 'challenge', humanCheck: provider}`.
  - `emitLogin` does **not** fire, so no session-TTL clock starts; handoff completion starts it
    (below).
- The passkey path is unchanged here: the ceremony really completed. The agent sees `humanCheck`
  in its next snapshot.

### Agent surface

- `packages/mcp/src/port.ts`:
  - `AuthOutcome` gains `{status: 'challenge'}`.
  - `AuthStatus` and `SnapshotResult` gain `humanCheck: boolean`. It is a boolean, not page text;
    the provider stays in the audit log.
- `packages/mcp/src/tools.ts`: `OUTCOME_HELP` adds: "`challenge`: the broker submitted the form
  and the site answered with a human check. The broker will not solve it. Call `browser_handoff`
  to ask the user to complete it, then continue."
- `packages/core/src/agent-port.ts`: `authLogin` passes `humanCheck`; `snapshot()` and
  `authStatus()` return the flag.

### Test site (`packages/test-rp`)

`TestRpOptions.challenge?: 'aws-waf' | 'cloudflare' | 'frame'`. When it is set, a correct
password POST answers with the matching challenge page:

- `aws-waf`: status 405 plus `x-amzn-waf-action: captcha`;
- `cloudflare`: status 403 plus `cf-mitigated: challenge`;
- `frame`: status 200 with an iframe from the injected `captcha.localhost` host.

The page has an "I'm human" button. `POST /challenge/solve` sets an `rp_clearance` cookie and
redirects to `/account`, and `/account` requires both the session and the clearance cookie. A
further variant, `textOnly`, shows "Let's confirm you are human" with no structured signal; it
must read as `success`, proving page text is not trusted.

## 2. Persistent per-agent browser state

### Mechanism

- **Playwright `storageState`** (1.56.1, checked in
  `playwright-core/lib/server/browserContext.js`):
  - Collection: `context.storageState({indexedDB: true})` returns cookies (session cookies
    included), plus localStorage and IndexedDB for every origin the context visited.
  - Restore: `browser.newContext({storageState})` restores all three. The restore script deletes
    and recreates databases and unregisters service workers.
  - Both directions read and write storage in the utility world on Playwright's own hidden
    "storage state" page. Every request on that page is fulfilled with `<html></html>`, so it
    makes no network request and runs no site script.
  - That page is never emitted to the client (`Page.emitOnContext` skips `isStorageStatePage`),
    so `AgentSession.track()` never sees it.
  - Its target is auto-attached paused like every page, so layer A of `native-webauthn-block.ts`
    covers it.
- **Shim:** `ManagedBrowser.newContext(onWebAuthn, opts?: {storageState?})` in
  `packages/shim/src/browser.ts` passes it to
  `browser.newContext({acceptDownloads: false, storageState})`. The restore happens inside
  `newContext`, before `block.cover()` and before the binding and override, on inert content.
- **Rejected: `launchPersistentContext` per agent.**
  - It breaks one-browser-per-broker: one process per agent, and the native WebAuthn block would
    need installing once per browser.
  - It persists the whole Chromium profile: HTTP cache, history, form autofill, and Chromium's own
    password store. That could write a broker-filled password to disk (an invariant 8 hazard).
- **Not persisted:** sessionStorage (per tab), cache, history, service workers (unregistered at
  restore), permissions.

### Where it lives

- **Dev mode:** `<dataDir>/browser-state/` (0700), one file per agent, `<agentId>.state` (0600).
  Writes go to `<agentId>.state.tmp-<random>`, then fsync, then rename.
- **Service mode:** `/var/lib/aab/core/browser-state/`. It sits under `StateDirectory=aab/core`
  (0700, `aab-core`, `UMask=0077`), so no installer change is needed, and `uninstall.sh --purge`
  already removes it.
- **Path safety:** agent ids are validated as a UUID before use in a path. Files are opened
  `O_NOFOLLOW` and must be regular files owned by the process.
- **SQLite tables** (`packages/core/src/db.ts`; identifiers only, never values):
  - `session_clocks(agent_id, origin, host, started_at, PRIMARY KEY(agent_id, origin))`: the M5
    TTL clocks, now persisted.
  - `browser_sessions(agent_id, site, cookies, origins, saved_at, PRIMARY KEY(agent_id, site))`:
    an index for `aab sessions list` (counts only).
  - `session_clear_requests(id, agent_id, site, requested_at, via)`: clears queued by the CLI.

### Encryption at rest

Session cookies are bearer secrets. Options:

| Option | Protects against | Cost |
|---|---|---|
| A. File permissions only | other uids (service mode), not disk theft or backups | none |
| B. **Data key held in the signer's key store** (recommended) | other uids, plus offline copies of `/var/lib/aab/core` or backups; in service mode TPM-bound through the KEK, in dev mode passphrase-bound | one signer op, node:crypto only |
| C. A separate `systemd-creds` credential for the core | as B, service mode only; dev mode needs a second scheme | installer and unit change |
| D. The signer encrypts and decrypts the state itself | as B | megabytes of cookies through the signer; no gain, since the core holds them in memory anyway |

Recommendation: **B.**

- New signer op `browser_state_key`, no approval needed, like `store_item`. It is reachable only
  over the authenticated channel, so invariant 9 is unchanged.
- It returns a random 32-byte key, created once and stored in the encrypted key store as
  `stateKeys.browser`. It survives a future passphrase or KEK rotation.
- The core fetches it once at `startDaemon` and keeps it in memory, no worse than the live
  cookies it already holds.
- Encryption is AES-256-GCM with a random 12-byte IV per write and AAD
  `"aab-browser-state-v1\n" + agentId`, so one agent's file renamed to another agent decrypts to
  nothing.
- File format: `{v: 1, iv, tag, ct}`.
- The signer stays zero-dependency (`randomBytes`).
- Files touched: `packages/signer/src/protocol.ts`, `server.ts` (`handle` case), `client.ts`
  (`browserStateKey()`), `keystore.ts` (optional `stateKeys`); in the core, `SignerPort` and
  `daemon.ts`.
- If the key cannot be obtained, persistence is off for that run: nothing is restored or saved,
  existing files are kept, and `browser_state.unavailable` is audited.

### Save

- `BrowserStateStore` (`packages/core/src/browser-state.ts`, new) handles paths, encryption,
  atomic writes, load, filtering and trimming.
- `AgentSessions` (`sessions.ts`) owns the save schedule:
  - **Event saves (full `storageState`):** after a broker login (`onLogin`), after a handoff ends
    `done`, after `clearSite`, every 10 minutes if the session is dirty, and on shutdown.
  - **Cheap saves (`context.cookies()` only):** every 60 s while the session is dirty and the
    cookie hash changed. These merge into the last full snapshot's origins.
  - "Dirty" is set by every tool call, login and handoff input.
- **Shutdown:**
  - `AgentSessions.closeAll()` already runs before `browser.close()` in the `startDaemon`
    teardown stack. It saves each active agent first, with a 5 s cap per agent and 10 s overall,
    so a hung page cannot hang the stop.
  - A crash loses at most about 60 s of cookies.
- **Before every write:**
  - `registry.byId(agentId)` must still be active; otherwise no write.
  - After the rename, check again and unlink if the agent was revoked meanwhile. This closes the
    race with a dev-mode CLI revoke.
- **Save-time filters** (also run at restore):
  - **Secrets (invariant 8).** Every form in `scrub.ts` `secretForms()` of every value in
    `AgentSession.secrets()` is checked. That covers broker-filled secrets and handoff-typed text.
    A cookie whose name or value contains one is dropped. An origin whose localStorage or
    IndexedDB (serialized) contains one has its whole storage dropped (fail closed). Counts are
    audited.
  - **Denylist.** A site (registrable domain) is dropped if any known origin on it resolves `deny`
    for this agent: an origin in the state, a clock origin, `https://<site>`, or
    `https://<cookie domain>`. This is site-level and conservative, matching `clearSite`'s
    granularity.
  - **High-risk** (`isHighRisk` / `isHighRiskOrigin` with the configured `highRiskDomains`): not
    persisted (decision 3). A bank or email session lives only as long as the daemon does.
  - **Size cap** of 16 MiB plaintext per agent. IndexedDB of the largest origins goes first, then
    localStorage; cookies are never trimmed. Audited `browser_state.trimmed`.
- The `browser_sessions` index is rewritten per save. Routine saves are not audited, to keep the
  chain readable; failures are, once per distinct reason (the `source.sync_failed` pattern).

### Restore (`AgentSessions.get`, on the agent's first tool call, as today)

1. Load and decrypt. If the file is undecryptable, malformed or over the cap, discard it and
   audit `browser_state.discarded {agentId, reason}`.
2. Apply pending `session_clear_requests` for this agent.
3. Apply the save filters, plus the **TTL filter** (next section).
4. Call `newContext(handler, {storageState})`. If that throws, start with an empty context and
   audit `discarded {reason: 'restore_failed'}`.
5. Audit `browser_state.restored {agentId, sites, cookies, origins, dropped: {ttl, deny,
   highRisk, cleared, secret}}`. The dropped entries hold sites and counts, never cookie names or
   values.

At daemon start, files of inactive or unknown agents are deleted
(`browser_state.deleted {reason: 'agent_inactive'}`).

### Session TTL across restarts (`packages/core/src/session-ttl.ts`)

- **Clocks persist.** `record()` upserts into `session_clocks`; a clear deletes the row. The
  constructor loads rows for active agents. Clocks start on a broker login, as today, and also on
  a handoff that ends `done` (decision 12). The policy is still re-read on every sweep, so the
  deadline is `started_at + current TTL`.
- **Restore filter (fail closed).** For each site S in the saved state, compute the shortest TTL
  over every known origin on S, as in the deny filter. If any TTL applies, the state must have a
  clock for (agent, an origin on S) with `started_at + ttl > now`. If there is none, or it has
  expired, drop every cookie and storage entry for S before the context exists. Audit
  `session.cleared {agentId, origin, ttlMs, cookies, pages: 0, via: 'restore'}`. "Can't establish
  a deadline" therefore always means "cleared".
- **Sweeper changes:**
  - A clock whose agent has no loaded session is no longer deleted (today's
    `if (!session) delete` would lose clocks of agents not yet restored). It is deleted only if
    the agent is inactive.
  - For an unloaded agent whose clock expired, the sweeper rewrites that agent's file through
    `BrowserStateStore.rewrite(agentId, filter)`, with no browser involved, so expired cookies
    don't linger at rest.
  - After a live `clearSite`, the sweeper triggers a save.
  - The sweeper also applies queued clear requests.
  - `session.cleared` gains `via: 'ttl' | 'restore' | 'admin'`.

### Revoke

- **Service mode** (admin socket): the `registry.onRevoke` listener becomes
  `sessions.discard(id)`. That closes the context **without saving**, deletes the file and the
  `session_clocks` / `browser_sessions` rows, and audits
  `browser_state.deleted {agentId, reason: 'revoked'}`.
- **Dev mode, CLI** (`packages/cli/src/agent.ts` `agentRevoke`): deletes the file and rows
  directly (same data dir). The daemon's context stays open until restart, as today, but the
  daemon never re-saves a revoked agent (registry check before and after each write).

### Admin CLI

- `aab sessions list [--agent ID] [--json]`: per agent and site, it shows cookie and
  storage-origin counts, the last save time, and the TTL deadline if any. It reads the SQLite
  index, clocks and policy only, so no key is needed and it works while the daemon runs.
- `aab sessions clear (--agent ID | --all) [--site SITE]`:
  - **Dev mode:** queues a `session_clear_requests` row. The running daemon applies it on its
    next sweep (at most 30 s), or at the next start before anything is restored. It prints
    "queued". The whole agent's file can also be deleted offline.
  - **Service mode:** `sudo aab sessions …` uses core admin ops `sessions.list` and
    `sessions.clear` in `packages/core/src/admin-ops.ts`, which apply at once (`clearSite` or
    `discard`, then save) and return counts.
  - Audited `session.clear_requested {agentId | '*', site, via}`, then
    `session.cleared {via: 'admin'}`.
- `aab status` adds a "Saved sessions: N agents, M sites" line.
- Persistence can be disabled: `aab daemon --ephemeral-browser`, or `browser.persist: false` in
  `/etc/aab/core.json` (`packages/cli/src/service/config.ts`). The default is on (decision 13).

## 3. Human handoff

### Flow

1. The agent calls `browser_handoff` (typically after `auth_login` returned `challenge`, or after
   seeing `humanCheck: true`).
2. The core checks the gates, opens a handoff bound to (agent, page, site), and pushes "Human
   check on huggingface.co".
3. The owner opens the paired approver at `/handoff` and confirms with Face ID to start the live
   view. The page shows broker-authored context and the live frames; the owner taps and types,
   then taps Done (or Cancel).
4. The handoff ends, the agent's `browser_handoff` returns `done`, the state is saved and the TTL
   clock starts. The agent continues with ordinary tools.

### Trigger and gating (`packages/core/src/handoff.ts` `HandoffManager`, new)

Checks run in this order. Every refusal is audited as
`handoff.denied {agentId, verifiedOrigin, reason}` and sends no push.

| Check | Refusal |
|---|---|
| A handoff-capable approver is configured. The terminal approver is not. | `unsupported` / `not_available` |
| There is a current page, and `verifiedOriginFromFrame(mainFrame().url())` is OK. | `unsupported` / `not_eligible` |
| The policy for that origin is not `deny`. | `denied` |
| `detectHumanCheck` is positive (decision 7). | `unsupported` / `no_human_check` |
| A live intent exists for the agent (invariant 4 spirit: the owner is pinged only when they recently asked for something). | `denied` |
| No approval is pending for this agent. | `denied` |
| Rate limits hold: one open handoff per agent (a second call joins the open one, no new push), at most 2 open overall, at most 3 handoff pushes per agent per 10 minutes, at least 30 s after a cancelled or expired one. | `denied` |
| At least one paired device exists. | `unsupported` / `not_available` |

Not automatic in v1: `auth_login` returns `challenge` and the agent decides (decision 9).

### Tool semantics: `browser_handoff`

- **Schema:** `{timeoutMs?}` only (1 000 to 120 000; default 45 000, so MCP clients with the
  SDK's 60 s default timeout stay inside it). No free text, URL or origin.
- **Blocking with re-call:**
  - If no handoff is open for this agent, the call opens one and then waits; if one is already
    open, it just waits.
  - It returns `{status: 'done' | 'cancelled' | 'expired' | 'pending' | 'denied' |
    'unsupported', reason?}`, with `reason` only for `unsupported`.
  - `pending` means "still open; call again". The broker ends a handoff after 5 minutes
    (`expired`).
  - `left_site`, `page_closed` and `revoked` endings map to `cancelled`.
- **What the agent sees:**
  - **During** a handoff, every other tool of that agent fails with a fixed `ToolError`: "a human
    check is in progress on your page; call browser_handoff to wait for it". This is checked in
    `AgentPort.call`. Fail closed: the agent can't interfere or watch partial input.
  - **After** it, the agent sees ordinary scrubbed tool output.
  - It never sees a frame, a coordinate, typed text or anything else from the phone. A test
    checks the agent's raw MCP bytes for image content.
- **Tool surface:** `packages/mcp/src/tools.ts` goes from seven tools to eight.
  `inv7-no-cdp.e2e.test.ts`, `inv6-policy.e2e.test.ts` and `mcp/test/tools.test.ts` pin the list
  and change with it. ARCHITECTURE 6.5 gains the row (decision 11).

### Live view: screenshots, no CDP

- **Frames.** `page.screenshot({type: 'jpeg', quality: 60, scale: 'css', timeout: 5000})` on the
  bound page. It runs `Page.captureScreenshot` on Playwright's own main-frame session, so nothing
  attaches or detaches and the WebAuthn environment is untouched. It works headless and on Xvfb.
- **Rejected:** `newCDPSession` plus `Page.startScreencast` (its detach resets the tab's virtual
  WebAuthn environment, CLAUDE.md); Playwright's screencast (internal only, used for video and
  tracing).
- **Delivery.**
  - Frames are captured only while a device holds the live view, at most 4 per second, and cached
    for 250 ms.
  - Only the latest frame is kept, in memory; frames are never logged or written to disk.
  - Frames are served same-origin as `GET /api/handoff/frame?id=…` (`image/jpeg`, `no-store`,
    CORP same-origin). The existing CSP `img-src 'self'` already allows it, and the
    `SameSite=Strict` cookie plus Host checks apply.
- **Site binding.** A frame is captured only while the main frame's registrable domain equals the
  handoff's site. If the page moves to another site, the handoff ends `left_site`, so the pixels
  can never appear under the wrong host label.

### Input (taps and keyboard)

- **Endpoint:** `POST /api/handoff/input {id, …}`. It requires the existing JSON, Origin and
  `Sec-Fetch-Site` checks, and that this device started the view.
- **Event types:**
  - `click {x, y}`: coordinates in [0, 1] of the image, mapped onto the current
    `page.viewportSize()` and sent with `page.mouse.click`;
  - `scroll {dy}`: `page.mouse.wheel`;
  - `drag {from, to}`: `mouse.move` / `down` / `move` (with steps) / `up`, for slider checks;
  - `key {key}`: an allowlist of Enter, Backspace, Tab, Escape and the arrow keys;
  - `text {text}`: at most 256 characters, no control characters, sent with
    `page.keyboard.insertText`.
- **Keyboard risk (decision 6): restrict and scrub.**
  - Text goes through a broker-rendered text box on the phone, not keystroke streaming.
  - Text is **refused** when the focused element in any frame matches `SENSITIVE_FIELDS_CSS`
    (password and one-time-code fields), with the broker message "Use the broker's sign-in for
    passwords". Audited `handoff.input_refused {reason: 'sensitive_field'}`.
  - Every sent text of 4 characters or more goes through `session.rememberSecret()` **before**
    insertion, so it is scrubbed from all agent tool output and filtered out of saved state.
  - The page shows a fixed warning: "The agent can see this page after you tap Done. Don't type
    passwords here."
- **Popups.** Pages opened by the owner's taps are tracked as usual and become the agent's
  current page after Done. The handoff stays bound to its original page.

### Ending and binding

- A handoff is bound to (agentId, the Playwright `Page`, site, verified origin at open).
- It ends on: Done (`done`) or Cancel (`cancelled`) from the controlling device; 5 minutes
  (`expired`); the page closing (`page_closed`) or leaving the site (`left_site`); an agent
  revoke (`revoked`); the approver or daemon closing.
- At most one device controls a handoff (the first to start it).
- Fail closed: a frame capture error shows the fixed "live view unavailable" text; any input error
  is refused, never retried.

### Approver separation (invariant 5 boundary; `packages/approver`)

- **`/handoff` is its own document** (`page/handoff.html`, `handoff.js`, `handoff.css`), visually
  distinct (different header color and frame).
  - It never calls `/api/state`, `/api/challenge` or `/api/decide`, and renders no approval card.
  - Its only WebAuthn call is the start check, before any pixel is shown. The challenge for it is
    domain-separated: SHA-256 of `"aab-handoff-start-v1\n" + id + "\n" + nonce`, verified by the
    approver server with `@simplewebauthn/server` against the signer's trusted approver keys. It
    can never equal `approvalChallenge(statement)`, so it can't approve anything, and the signer
    is not involved.
- **Broker-authored chrome** around the image, written with `textContent` and `clean()`:
  - the verified host, from the frame URL at open;
  - the agent name;
  - "You said …" (verbatim intent and time);
  - "Live view of the website. Nothing in this picture is from the broker, and nothing here can
    approve a sign-in."
  - Done and Cancel sit outside the image.
- **The approvals page (`/`)** gets a fixed link card from
  `state.handoffs: [{id, host, agentName}]`: "Human check waiting on <host>, open live view".
  There are no pixels and no Approve button on it. A pending handoff is never put in `pending`, so
  old clients and the iOS app's `.unknown` case never see it.
- **No approvals during a handoff.** While a handoff is open, `Broker.handleWebAuthn` and
  `Broker.fill` deny for that agent with `handoff_open`, before the approver is called: a new
  check after the policy check in `broker.ts`, through an `isHandoffOpen(agentId)` hook. A hostile
  page therefore can't show a fake "tap Approve" in the live view while a real approval card waits
  for the same agent.
- **Approver-side types:** `packages/approver/src/types.ts` gains `HandoffView`, `HandoffInput`
  and a `HandoffPort` interface that the core implements; the approver package never imports
  Playwright. `PhoneApprover` gains `attachHandoffs(port)` and `notifyHandoff(view)`. The
  `ApproverHandle` from `makeApprover` gains optional `handoffs`; if absent (terminal approver),
  the result is `unsupported/not_available`.

### Push

- **Web Push:** encrypted payload `{"t": "handoff", "host": "<verified host>"}`. `sw.js` shows
  "Human check on <host>" and opens `/handoff`. The push service sees only ciphertext, as in M4.
- **APNs:** `ApnsNotification.kind: 'handoff'`. The body is "Human check on <host>" (or fixed
  text with `--apns-generic`). A new category `HANDOFF` has **no** lock-screen actions; tapping
  opens the app.

### Native iOS (P4, dropped 2026-10-20: the iOS app is parked, the web page is the phone approver)

- **API:** `/api/native/handoff/{state, start, frame, input, finish}` with the bearer token.
  `start` carries a Secure Enclave signature (Face ID) over
  `"aab-handoff-start-v1\n" + id + "\n" + nonce`, verified with `verifyNativeSignature`.
- **App:** a dedicated `HandoffView` screen with a distinct style that never reuses the request
  sheet or its Approve control; the frames as an image, a text field and key buttons, Done and
  Cancel. `ReplayApproverCore` gets a `Handoff.swift` (models and start bytes) and fixture vectors
  in both directions.
- `state` keeps `handoffs` separate from `pending`. Older apps' tolerance of an unknown top-level
  key needs checking (`BrokerClient.swift`).

### Audit (identifiers and origins only)

- `handoff.requested {handoffId, agentId, verifiedOrigin, provider}`
- `handoff.denied {agentId, verifiedOrigin?, reason}`
- `handoff.started {handoffId, deviceId}`
- `handoff.input_refused {handoffId, reason}`
- `handoff.ended {handoffId, agentId, verifiedOrigin, outcome, durationMs, inputs: {clicks,
  scrolls, drags, keys, texts}}`
- `denied {reason: 'handoff_open'}` for credential operations refused during a handoff

Never text, keys, coordinates or frames.

## Build order

- **P1: honest outcome (small, independent).**
  - New: `core/src/challenge.ts`.
  - Changed: `core/src/fill.ts`, `broker.ts`, `sessions.ts` (watch per page), `agent-port.ts`,
    `daemon.ts` (`challengeHosts`); `mcp/src/port.ts`, `tools.ts`; `test-rp/src/server.ts`,
    `pages.ts`.
- **P2: persistence.**
  - Shim and signer: `shim/src/browser.ts`; `signer/src/{protocol,server,client,keystore}.ts`.
  - Core, new: `core/src/browser-state.ts`.
  - Core, changed: `core/src/{sessions,session-ttl,db,daemon,admin-ops,index}.ts`.
  - CLI, new: `cli/src/sessions.ts`.
  - CLI, changed: `cli/src/{args,main,agent,status,daemon}.ts`,
    `cli/src/service/{cli,config,core-main}.ts`.
- **P3: handoff on the web approver (needs P1; uses P2's save and clock).**
  - Core, new: `core/src/handoff.ts`.
  - Core, changed: `core/src/{agent-port,broker,daemon,session-ttl}.ts`.
  - MCP: `mcp/src/{port,tools}.ts`.
  - Approver: `approver/src/{types,phone,webpush,apns,index}.ts`,
    `approver/src/page/{handoff.html,handoff.js,handoff.css,app.js,sw.js}`.
  - Wiring: `cli/src/daemon.ts`, `cli/src/service/core-main.ts`.
- **P4: handoff in the iOS app (dropped 2026-10-20 with the app, IMPLEMENTATION_NOTES Status).** `approver/src/phone.ts` native endpoints,
  `ios/ReplayApproverCore`, `ios/Sources/ReplayApprover/Views`.
- **Each phase:** `pnpm typecheck && pnpm lint && pnpm test && pnpm test:isolation`, the
  verify-aab skill's sandboxed run, plus the hand mutation checks listed below.

## Tests

### Unit

| Test | Covers |
|---|---|
| `core/test/challenge.test.ts` | Host matching on label boundaries; header rules; interactive vs invisible widget URLs; a script host alone is not a challenge; `evil.localhost` lookalikes are not one |
| `core/test/browser-state.test.ts` | Encrypt and decrypt round-trip; AAD binds the agent (a swapped file is discarded); a tampered file is discarded; filters (deny site, high-risk, secret in a cookie / localStorage / nested IndexedDB in every `secretForms` spelling, TTL with no clock / expired / live clock, pending clears); size trim order; path validation; file modes 0600 / 0700 |
| `core/test/handoff.test.ts` | Fake page and clock: gating order, one per agent, joining an open one, rate limits, expiry, `left_site`, revoke ends it, coordinate mapping, sensitive-field refusal, `rememberSecret` before insert |
| `signer/test/browser-state-key.test.ts` | Same key across a restart of one store; a different store gives a different key |
| `signer/test/inv9-channel.test.ts` | Extended: `browser_state_key` refused without a valid MAC (invariant 9) |
| `approver/test/handoff-server.test.ts` | Cookie required (401); 404 when nothing is open or for another id; Host, Origin and JSON checks; CSP and headers on `/handoff`; frames only for the starting device and only after a valid start assertion; an approval-statement assertion can't start a handoff and a start assertion can't approve; input validation; handoffs never in `pending`; Web Push payload |
| `approver/test/apns.test.ts` | `handoff` alert, `--apns-generic` wording, no actions |
| `mcp/test/tools.test.ts` | Eight tools; `browser_handoff` schema is `{timeoutMs?}` only, strict |
| `cli/test/sessions.test.ts`, `args.test.ts` | Parsing; list from the index; clear queues a row; dev revoke deletes the file and rows |
| `test-rp/test/challenge.test.ts` | Each challenge mode's status and headers, solve, clearance |

### E2E (daemon + MCP; the test RP on `rp.localhost`)

| Test | Covers |
|---|---|
| `core/test/fill-challenge.e2e.test.ts` (inv8, 10) | AWS WAF, Cloudflare and frame modes give `challenge`; `fill.completed {outcome: 'challenge'}`; no TTL clock; `humanCheck: true` in `auth_status` and the snapshot; the text-only page gives `success`; a login page with invisible reCAPTCHA (injected host) gives `success`; wrong password still `failed`; post-fill clearing still runs |
| `core/test/session-persistence.e2e.test.ts` | Log in, stop, start on the same data dir: signed in with no approval and no prompt; localStorage and IndexedDB survive; restore and save make no request to the RP (RP request log); revoke deletes the file; a dev CLI revoke while running means the daemon never re-saves; a file of an inactive agent is deleted at start; a deny rule added while stopped drops the site at restore; high-risk not persisted; audit events |
| `core/test/inv6-session-ttl-restore.e2e.test.ts` (inv6, 10) | TTL 5 s, stop, wait, start: the site is cleared before the first agent call, `session.cleared {via: 'restore'}`; TTL with the clock row deleted is cleared (fail closed); a live clock keeps the session, then the sweeper clears it after the deadline; an unloaded agent's file is rewritten on expiry; queued admin clears are applied |
| `core/test/inv8-persisted-state.e2e.test.ts` (inv8) | A page copies the filled password into a cookie, localStorage and IndexedDB. The decrypted saved file contains no form of it. After a restart (empty scrub list) a page echoing `document.cookie` and storage shows none of it in `browser_snapshot` |
| `core/test/inv4-handoff.e2e.test.ts` (inv4) | No live intent gives `denied`, no push, audited; with an intent there is exactly one push |
| `core/test/inv5-handoff.e2e.test.ts` (inv5, inv2) | A hostile challenge page fills its title, URL path and DOM with ZQX markers and draws an "Approve" button. `/api/handoff/state` and the approvals `/api/state` contain only broker fields (host from the frame URL, agent name, intent) and no marker. A page-initiated passkey sign-in during a handoff is denied `handoff_open` and never reaches the approver. The `/handoff` document has no approval controls and makes no WebAuthn call after start |
| `core/test/inv6-handoff.e2e.test.ts` (inv6) | No signature or fill can happen while a handoff is open (`auth_login` and page ceremonies deny); the handoff never produces an approval |
| `core/test/inv7-handoff.e2e.test.ts` (inv7) | `newCDPSession` is never called for the agent's page during a handoff (spy) and no CDP detach happens on it; afterwards native WebAuthn from that page still lands in the empty virtual environment (helper from `inv6-inv7-native-webauthn`); the agent's raw MCP bytes contain no image content or JPEG base64 |
| `core/test/inv8-handoff.e2e.test.ts` (inv8) | Owner text in a text field shows as `[redacted]` in the agent's snapshot after Done; text into a password or OTP field is refused; owner text is absent from the saved state |
| `core/test/inv10-audit.e2e.test.ts` (extended, inv10) | Every new event is in the chain; payloads have no values, text, coordinates or cookie names |
| `core/test/handoff-phone.e2e.test.ts` | Full flow with the separate "phone" Chromium (virtual authenticator, as in `inv6-phone-approval`): challenge → `browser_handoff` → push captured → Face ID start → frames → tap "I'm human" at mapped coordinates → Done → agent gets `done` → `/account`; restart the daemon and the clearance cookie persisted, so no challenge |
| `cli/test/service-mode.e2e.test.ts` (extended) | `sessions.list` / `sessions.clear` admin ops |

### Isolation (`pnpm test:isolation`)

- `inv1-isolation.test.ts` (extended): `/var/lib/aab/core/browser-state` (list) and
  `<agentId>.state` (read) give EACCES for `agentuser`. As a control, root sees a non-empty file
  after the legit login. The file, read as root, is `{v, iv, tag, ct}` only: no cookie name, value
  or origin in plaintext.
- `inv1-isolation.test.ts`, legitimate path (extended): after `loginApproved`,
  `systemctl restart aab-core`; the probe's snapshot of `/account` still shows
  `Signed in as isolation-user`, and the phone log shows no new request; `sudo aab agent revoke`
  removes the file.
- No new invariant 7 surface; `inv7-isolation` is unchanged.

### Mutation checks to run once by hand

Each of these must make a test fail: disable the save-time secret filter; disable the TTL restore
filter; let the sweeper delete unloaded agents' clocks; skip the handoff intent check; let
approvals through during a handoff; put the page title into `HandoffView`; capture frames with
`newCDPSession`; drop the AAD.

## Docs to update

- **IMPLEMENTATION_NOTES:** status entries; new sections "Persistent browser state",
  "Human-check detection", "Human handoff". Deviations: M5's "contexts aren't persistent" no
  longer holds (TTL clocks persist, restore fails closed); "CAPTCHA after submit reads as
  `success`" is fixed (`challenge`); seven tools become eight; new signer op
  `browser_state_key`. New known limits: transformed secret copies now persist; Turnstile and
  others may refuse automated browsers even after a human passes; `cf_clearance` is bound to the
  user agent, so switching between headed and headless invalidates it.
- **ARCHITECTURE** (decision 11): 6.5 adds the `browser_handoff` row, the `challenge` outcome and
  `humanCheck`; section 3 gets one line saying human handoff is not CAPTCHA solving; section 10
  lists the new tables.
- **ISOLATION_PLAN:** "Not fixed: Session cookies after login" now also covers on disk,
  encrypted, aab-core 0700. Add the tests list entry.
- **integrations:** `phone-approver.md` (Handoff section, push wording, the Face ID start);
  `service-mode.md` (where state lives, `sudo aab sessions`, sessions surviving restarts,
  `browser.persist`); `claude-code.md` (agent guidance: `challenge` → `browser_handoff`, re-call
  on `pending`, tool timeouts); `ios-app.md` (the handoff screen, P4).
- **CLAUDE.md:** the layout lines (`browser-state.ts`, `challenge.ts`, `handoff.ts`),
  `aab sessions` in Commands, and the tool count.

## Not in this plan

- Post-ceremony challenge detection on the passkey path.
- Auto-opening a handoff from `auth_login`.
- A dev-mode admin socket: dev clears are queued instead.
- Handoff in Phase A (terminal approver).
- Sharing state between agents.
- Exporting or importing state.
- Persisting sessionStorage, cache or permissions.
- Any change to the user agent or other automation signals.

## Decisions for the owner

Decided by the owner on 2026-10-13. Their priority: minimize how often they have to
interact.

1. **Invariant 5 boundary: approved.** The live view is its own screen with no approval
   action, it starts only after a Face ID check, and approvals for that agent are blocked
   while a handoff is open.
2. **Encryption at rest: B,** a random data key in the signer's key store, fetched over the
   authenticated channel.
3. **High-risk sites' sessions: opt-in per site.** Not persisted by default; the owner can
   keep one per (agent, site) ("Keep me signed in"): `persist_optins`, written only by the
   owner (`aab sessions keep|unkeep`, the core admin socket, and in P3 a broker-authored
   checkbox on the phone approval card that becomes part of the signed approval). Never
   reachable from MCP tool input. Removing an opt-in drops the site from the saved state on
   the next save or sweep. Audited `session.keep_set` / `session.keep_removed`. (Built in
   P2.)
4. **Denylist: yes,** through the policy `deny` rule only (`aab policy set <site> --deny`,
   the owner's standing block): deny sites are dropped from saved state and refused a
   handoff. Tapping Deny on a single phone request stays one-time and never touches saved
   state.
5. **IndexedDB: yes,** with the 16 MiB cap per agent (cookies always kept).
6. **Keyboard in the live view: allow typing with limits** (a text box plus named keys,
   refused into password and OTP fields, typed text scrubbed and filtered).
7. **Handoff gating: require both** a detected human check and a live intent.
8. **Face ID to start a live view: yes.**
9. **Auto-handoff on `challenge`: no;** the agent asks (`browser_handoff`).
10. **Push text: show the site,** "Human check on <host>" (with `--apns-generic`
    respected).
11. **ARCHITECTURE edits: approved.**
12. **TTL clock started by a completed handoff: yes.**
13. **Persistence default: on,** with `--ephemeral-browser` / `browser.persist: false`.

## P3b: one approval for check + sign-in

**Owner decision, 2026-10-13.** On huggingface.co the AWS WAF check appeared as soon as the
login page opened, before any password. With P3 alone that cost the owner two phone
interactions: the handoff (Face ID to start the live view, solve, Done), then a separate
sign-in approval when the agent called `auth_login`. The owner wants one.

### What the owner sees

- **One Face ID, at the start, never on Done.** The approval never happens anywhere near
  page pixels (the decision 1 boundary stays: the live view never shares a screen with an
  approval action).
- The push is the ordinary approval push (`{"t":"approval"}`), which opens the approvals
  page `/`. The card is a **normal broker-authored approval card**, with the invariant 5
  fields only (the owner's words, the verified origin, the agent, the credential type) plus
  broker text: "Human check, then sign in to <host>?" and "One sign-in within 7 minutes,
  without asking again. Approving opens a live view of the website on this phone."
- Approve (one Face ID) → the phone goes straight to `/handoff`, where the live view opens
  with no second Face ID → solve → Done → the agent signs in with no further prompt.

### When it applies (eligibility, computed by the broker from trusted state only)

When the agent calls `browser_handoff` and the whole P3 gate passes, the handoff is combined
if a sign-in at the page's verified origin (frame URL) would be eligible right now:

- exactly one credential: one password item for the registrable domain, else (no item) one
  passkey whose rpId fits the host;
- policy resolves to plain `ask` or `allow-for` for this agent (not `deny`, not
  `ask-strong`), and the origin, domain or rpId is not high-risk;
- a live intent, and no approval pending for the agent;
- no broker sign-in on that site under the same intent already (a check that appears
  **after** the password, fill outcome `challenge`, stays a plain handoff: the sign-in was
  already approved).

Otherwise it is exactly P3: a plain handoff with the domain-separated Face ID start on
`/handoff`, and a separate approval later. `browser_handoff`'s schema stays `{timeoutMs?}`:
no MCP tool input reaches eligibility, policy or approvals.

### How it works

- **Statement.** The phone signs an ordinary approval statement (kind `fill` or
  `webauthn.get`, the credential, the verified origin, the intent hash) that also carries
  `handoff: {id}` and a **single-use grant** `grant: {agentId, until, uses: 1}`, with
  `until - issuedAt` at most 7 minutes (`HANDOFF_GRANT_MAX_MS`: the 5-minute handoff plus a
  margin). For a passkey the clientDataHash is SHA-256 of `"aab-handoff-signin-v1\n" + id`
  (the site's challenge doesn't exist yet), so the statement can't sign anything by itself.
- **Signer.** New op `accept_handoff_grant`: verifies the approval like any other (signature,
  freshness, single use, issued after the signer started, credential and origin bindings,
  UV required: phone approvals only), refuses `strong` and high-risk sites and windows over 7
  minutes, and records the single-use grant without signing or releasing anything. A
  statement with `handoff` is never accepted as an operation itself. The grant then
  authorizes exactly one operation (one requestId; a fill may still release each field of
  its scope once) for that agent, kind, exact origin, rpId and credential. New op
  `drop_grant` forgets it.
- **Start of the live view.** The approver names the device whose own passkey approved
  (`allowCredentials` = that device's key only). The core starts the handoff for that device
  only after the signer accepted the approval; `/handoff` can never start a combined
  handoff with its own start check (`started_by_approval`), and shows "Starting the live view
  once you approve it on the approvals page…" until then.
- **Grant lifecycle (core).** Recorded unarmed; armed when the handoff ends `done`; dropped
  (core and signer) when it ends `cancelled`, `expired`, `left_site`, `page_closed`,
  `revoked` or by a daemon stop; withdrawn if the handoff ends while the card is still
  waiting. The agent's next `auth_login` at that origin uses it with no prompt, after the
  usual checks (verified origin, policy still `ask` / `allow-for`, no open handoff, the same
  credential, a live intent), audited `grant.used {singleUse: true, handoffId}`. It is taken
  out of the core's book by that use; a second `auth_login` prompts as usual.
- **Residual (fail closed, documented).** If the drop never reaches the signer (a crash, a
  lost message), the signer's copy stays usable until its expiry, at most 7 minutes after
  the approval, by that agent at that origin with that credential, once. The core forgets
  it either way, so only a compromised core could present it, and only for exactly what the
  owner approved.

### Audit

`handoff.requested {…, withSignIn: true}` or `{…, signInSkipped: <reason>}`; `request {kind:
'handoff.sign-in', handoffId}`; `approval`; `grant.created {singleUse: true, handoffId,
until}`; `handoff.started {deviceId, via: 'approval'}`; `grant.armed`; `grant.used
{singleUse: true, handoffId}`; `grant.dropped {reason: 'handoff_<outcome>'}`;
`grant.drop_failed`. Identifiers and origins only.

### Tests

`signer/test/inv6-handoff-grant.test.ts`, `signer/test/inv9-channel.test.ts` (extended),
`approver/test/handoff-signin.test.ts`, `core/test/handoff.test.ts` (P3b block),
`core/test/inv6-handoff-signin-broker.test.ts`, `core/test/handoff-signin-phone.e2e.test.ts`
(the full flow with exactly one approval; Cancel; the high-risk fallback),
`inv4-handoff.e2e.test.ts`, `inv5-handoff.e2e.test.ts` and `inv10-audit.e2e.test.ts`
(extended), `test-rp/test/challenge.test.ts` (`challengeAt: 'login-page'`).
