# M5 plan: policy and sessions

Status: **done**. Invariant tests: IMPLEMENTATION_NOTES "Status".

Scope (sections 9 and 15): risk tiers per origin and agent (`deny`, `ask`, `ask-strong`,
`allow-for(duration)`), the denylist (section 4), session TTL cleanup, CLI polish.
Invariants touched: 4 (a live intent for every login, also inside an allow-for window),
5 (the new "also allows" line is broker-authored, never agent or page text), 6 (every
operation under policy; high-risk stays mandatory `ask-strong`), 10 (every decision and
cleanup audited).

The signer stays the enforcer: it verifies an approver's signature on every operation,
and the one thing M5 adds that skips a prompt (allow-for) is authorized by the user's own
signed approval, remembered by the signer, never by the core alone.

## Policy rules

`policies(origin_pattern, agent_id, mode, allow_for_ms, session_ttl, updated_at)`, primary
key `(origin_pattern, agent_id)` (the table exists since M1; `allow_for_ms` is added).

- **Pattern:** an exact origin (`https://app.example.com`, `http://*.localhost:port` for
  tests) or a domain (`example.com`: the host itself and every subdomain, on label
  boundaries). A domain must have a registrable domain (no public suffixes such as `com`
  or `github.io`, no IPs, no `*`). Hosts are normalized by the URL parser (lower case,
  punycode), as the verified origin is.
- **Agent:** an agent id, or `*` for all agents.
- **Mode:** `deny`, `ask`, `ask-strong`, `allow-for` (+ duration, 1 s .. 24 h), or `none`
  (the rule only sets a session TTL).
- **Session TTL:** optional, 1 s .. 30 days.

**Resolution: every matching rule applies and the strictest wins.** Matching = pattern
matches the verified origin and the rule is for this agent or `*`. Mode order: `deny` >
`ask-strong` > `ask` > `allow-for` (shortest duration first) > default `ask`. TTL: the
shortest. So `deny` always wins (the denylist can't be undone by a narrower rule), and no
rule can weaken another: a narrower `ask` carves an exception out of a broader
`allow-for`, never the other way round. Deliberately simpler than "most specific wins":
there's no precedence to get wrong, and adding a rule never makes anything less strict
except an `allow-for` where nothing stricter applies.

Then the built-in/configured high-risk list (`@aab/signer/risk`) raises the result to
`ask-strong` (never lowers it), so `allow-for` never applies to a high-risk origin.

The daemon reads rules from SQLite on every request (no cache), so `aab policy` edits made
while it runs take effect on the next request. Agents never see or set policy: no MCP tool
input reaches it.

## Broker

Order per request: verified origin → **policy** (deny: audited `denied {reason:
policy_deny}`, no prompt, before credential lookup) → credential match → live intent
(always, also inside an allow-for window) → approval or grant → signer.

- `ask-strong` (policy or high-risk): `ApprovalRequest.policy.tier = 'ask-strong'` as in M4
  (terminal approver denies, broker requires a phone approval), and the statement carries
  `strong: true` (below).
- `allow-for`: the request asks for a grant (`binding.grant = {agentId, durationMs}`) and
  the display gains `allowForMs` ("also allows this agent to sign in here for N minutes
  without asking"). Only for passkey sign-in and password fill; a passkey registration
  always asks.
- An audit event `policy {requestId, mode, tier, rules}` whenever a rule matched.

## Grants (allow-for), signer-enforced

The approval statement gains two optional, signed fields:

- `strong: true`: the signer then requires a phone (webauthn, so UV) approval with a
  lifetime ≤ 60 s, as for its own high-risk list, and refuses any grant. This is how a
  policy `ask-strong` reaches the signer: per statement, signed by the approver, not a list
  handed to the signer at start (that would go stale when `aab policy` edits SQLite while
  the daemon runs, and in service mode the signer's config is root-provisioned).
- `grant: {agentId, until}`: built by the approver from `binding.grant` when the statement
  is fixed (`until = issuedAt + durationMs`). The user's approval itself authorizes the
  window.

Signer, when it consumes an approval with a grant: refuses the whole operation
(`grant_not_allowed`) if the kind isn't `webauthn.get` / `fill`, the rpId/domain or origin
is high-risk, `strong` is set, the window exceeds 24 h, or the shape is wrong. Otherwise it
remembers `{grantId = requestId, agentId, kind, verifiedOrigin, rpId, credentialId, fill
scope, until}` **in memory only** (a restart drops every grant).

A later operation may present a `GrantedApproval {statement, grantId, agentId}` instead
of a signed approval. The core builds that statement (new requestId, current intent hash,
clientData hash / fill scope, `userVerified: false`, ≤ 5 min lifetime). The signer accepts
it only if the grant exists and hasn't expired, and agent, kind, exact origin, rpId and
credential all match (fill: the scope is a subset of the granted one). The origin must
also not be high-risk and `strong` must be unset. Everything else is as for any approval:
clientData hash and origin checks, single use per requestId, each fill field once. A grant
can't create credentials, add approvers, or claim UV (the user verified once, not for this
login: UV stays off, so sites that require UV need a prompt each time).

Core: keeps its own view of grants (agent, origin, kind, credential, scope, until) and
uses one only while the policy still says `allow-for` (re-read per request; the window is
capped by the current duration). No prompt is shown, but the request, the grant use
(`grant.used {requestId, grantId}`) and the outcome are audited. `grant.created` is audited
when the signer accepts the first use. If the signer refuses a grant (restart), the
request is denied and the core forgets the grant, so the next login asks again.

## Session TTL

After a broker login succeeds (passkey signed, or a fill whose form went away) the core
records `(agent, origin, time)`. A sweeper (every 30 s) re-reads the policy for each entry.
Once `time + TTL` has passed it ends that site's session in the agent's context and audits
`session.cleared {agentId, origin, ttlMs, cookies, pages}`. Here "site" means the origin's
registrable domain.
- closes the agent's pages on that site (in-memory state and sessionStorage go with them);
- clears every cookie whose domain is the site or under it (`context.clearCookies`);
- clears the origin's storage (local storage, IndexedDB, cache storage, service workers…)
  with CDP `Storage.clearDataForOrigin` on a throwaway page of that context. The agent
  never sees that page, it's never one the agent drives, and it's closed right away.
A new login restarts the clock. Sessions the broker didn't log in aren't tracked.

## CLI

- `aab policy set <site> [--deny | --ask | --ask-strong | --allow-for DUR] [--agent ID]
  [--session-ttl DUR|off]`: upsert (given fields overwrite, others kept); `<site>` is an
  origin or a domain. `aab policy list [--agent ID] [--json]`, `aab policy remove <site>
  [--agent ID]`. Writes SQLite directly (works while the daemon runs); audited
  `policy.set` / `policy.removed`.
- `aab status [--json]`: agents, credential counts, policies, audit chain check, last
  audit entries. `aab audit verify` (exit 1 if broken), `aab audit tail [--limit N]
  [--json]`. SQLite only.

## Not in M5

- No `*` (match-everything) pattern. A global deny would switch the broker off, and a global
  allow-for is a footgun.
- The denylist stops credential operations, not browsing.
- No admin socket. Policy edits go to SQLite; the daemon reads them per request.

## Tests

- Signer (`packages/signer/test/inv6-policy-grants.test.ts`): grant created then used;
  refused for high-risk (built-in and configured), `strong`, create, > 24 h, wrong
  agent/origin/rpId/credential/kind, expired, unknown, after restart, replayed requestId,
  UV claimed, fill scope superset; `strong` needs a phone approval ≤ 60 s.
- Core unit (`policy.test.ts`): pattern normalization and matching, strictest-wins
  resolution, durations, store CRUD. Broker + real signer (`inv6-policy-broker.test.ts`):
  deny unprompted, grant per agent/origin, window narrowed by the policy, no intent → no
  grant use, high-risk/ask-strong never grant, tampered grants refused, signer restart.
- Approver: the terminal prompt shows the allow-for line; statements carry `strong`/`grant`;
  inconsistent requests are denied.
- E2E through daemon + MCP (`inv6-policy.e2e.test.ts`): deny → `denied`, no prompt,
  audited; `aab policy set` while the daemon runs applies at once; allow-for → one prompt
  then none inside the window, every use audited, a new login without a live intent is
  denied, an expired window asks again, a high-risk origin never gets a grant; session
  TTL clears cookies, storage and pages and is audited. With the phone page
  (`inv6-policy-phone.e2e.test.ts`): the card shows the allow-for line and the phone's
  signed statement carries the grant; policy `ask-strong` yields `strong: true`.
- CLI (`policy.test.ts`, `args.test.ts`): parsing, upsert/list/remove, agent check,
  status and audit verify.
