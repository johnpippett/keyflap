# Agent admin plan: agents run `aab`, the owner approves on the phone

Status: **design, not built.** This is the follow-up promised in ISOLATION_PLAN D3 ("Later (after
M4): admin operations require a phone approval instead"), extended so the owner's agents can run
the `aab` CLI themselves. Scope is **service mode only**: core and signer run as `aab-core` and
`aab-signer`, and the agent runs as the login user. Dev mode (`--unprotected`) keeps M5 behaviour
and gets none of this.

It covers SESSIONS_PLAN's new settings: saved sessions (`aab sessions list|clear`), the high-risk
"Keep me signed in" opt-in (`aab sessions keep|unkeep`, `persist_optins`, which already has
`via: 'approval'` reserved for this), and the human handoff (`browser_handoff`, P3).

Invariants touched:

- **4:** every change request needs a live intent, and that intent's words appear on the card.
- **5:** change cards are broker-authored from enums and existing broker state. Agent names stay
  owner-set or enum.
- **6:** the signer becomes the authority for policy *modes*, so the floor holds against a
  compromised core. `agentId` joins the signed statement.
- **9:** new signer ops are reachable only over the authenticated channel or the signer's
  root-only admin socket.
- **10:** every request, decision and change is audited.

**No section 5 invariant is weakened.** Three points need the owner's explicit agreement; they are
flagged in "Invariant check" and in the decisions list.

## Threat model for this feature

| Actor | Can | Can't |
|---|---|---|
| **Agent** (login uid; holds its own token; can run `aab`; can read `/var/lib/aab/hook/host-token` and other same-uid agents' configs; can alias `sudo`; talks to the owner in chat) | Run read-only ops, scoped to its own agent where it matters. Apply tightening changes at once (audited, phone notified). File loosening or disruptive requests within rate limits. Choose a request's subject, but only from existing broker state and enums. **Forge the "You said" text** (the existing inv 4/5 limit, now on higher-stakes cards). Use another same-uid agent's token, so attribution is a label and not a boundary. Social-engineer the owner. Capture a sudo password through an alias (D3 residual), which now becomes visible because root changes also notify the phone. | Apply any loosening or disruptive change without a fresh UV signature from a paired phone over exactly that change. Forge or replay a statement. Put free text on a card. Pick an arbitrary duration, an unrelated domain, or an agent name. Get a high-impact change in one tap. Reach the admin sockets or the signer. Pair or remove phones, or touch secrets. Lift its own block. |
| **Hostile page** (in the agent's browser or the handoff live view) | Prompt-inject the agent into filing requests. Draw "approve the next card" text. | Get anything onto a card (no field comes from a page). File requests while a handoff is open or within 60 s after one. |
| **Compromised core** (`aab-core` uid, e.g. a Chromium exploit) | Everything the core already enforces alone, without changing any setting: session TTL, saved sessions and "keep signed in", the agent registry, session clears. Deny everything. Lie on the Phase B web page and in the "recent changes" list, and suppress notifications. Tighten signer-held policy (a DoS). | Change signer-held policy (modes, phone-added high-risk domains) without the owner's signature over that exact change. Get a grant the signer's allow-for rule doesn't cover. Get past a signer-held deny or ask-strong. Use a change approval as a login approval or the reverse. Skip the high-impact wait. In Phase C, have the app sign a change other than the one it shows. Erase the iPhone's local history. |
| **Third uid** | Nothing new. | `connect()` to `request.sock` (user-owned 0600). |
| **Stolen phone** | Locked: Deny, Undo, and "pause this agent" only, all tightening, so at worst a DoS. | Approve anything without Face ID or the passkey's UV. |
| **Push provider / Apple** | See "Change request from <agent name>" (fixed text with `--apns-generic`). | See the change itself. |

The guarantee "a compromised core can't apply a loosening the owner didn't sign" is only
meaningful for state the **signer** enforces. For state the core enforces alone, a compromised
core already gets the effect without changing anything, so authenticating those rows buys
nothing. The design therefore moves the enforcement-relevant part of policy into the signer and
leaves the rest in the core.

## Operation classes

1. **Read.** Free, no approval. Some results are filtered (below).
2. **Tighten.** Applied at once, audited, and the phone is notified. A change is tightening only
   if it is *monotonic*: it never makes any (agent, origin) less strict.
3. **Confirm (disruptive).** Strictly tightening, but it hurts the owner's other agents or wipes
   state. It needs a phone approval with UV. No waiting period, and it doesn't count against the
   loosening budget.
4. **Loosen.** Becomes a pending change request; nothing applies until the owner approves with
   UV. Two impact levels:
   - **standard:** one approval;
   - **high:** type-to-confirm plus UV: the owner types the target (the site or the new agent's
     name) on the phone, then approves with Face ID. No waiting period, unless a red flag fires
     (next section): then the approval only *arms* the change, and it can be confirmed (UV again)
     after a 5-minute wait, within 1 hour.

### Red flags (high-impact only; owner decision 2026-10-13)

The owner rejected a fixed wait on every high-impact change ("that's going to piss people off").
A wait applies only when one of these structured signals is present; the card says which one:

| Flag | Computed by | Signal |
|---|---|---|
| `quiet_hours` | **signer** (its own clock and config) | Inside the owner's quiet hours (default 23:00 to 07:00 local, configurable by root only) |
| `not_in_your_words` | core | The target's registrable label (e.g. `chase` for `chase.com`, or the new agent's enum name) does not appear, case-insensitively, in the live intent's verbatim words |
| `recent_deny` | core | The owner denied a request from this agent in the last 24 h |
| `new_agent` | core | The requesting agent was created less than 24 h ago |

Flags only add friction; they never remove a gate. The signer enforces the wait whenever the
statement carries `delayed: true` **or** its own `quiet_hours` check fires, and refuses a statement
that omits a flag it can compute itself. Core-computed flags are a usability safeguard against a
misled agent, not a defence against a compromised core (which is already covered by the signer
floor: nothing loosens without the owner's signature over the exact change).

Type-to-confirm is a UI safeguard (the approver page, and in Phase C the app, compare the typed
text with the target before asking for Face ID), not a cryptographic one. The statement records
`typedConfirm: true`, and the signer requires it on high-impact statements.
5. **Human-only.** `sudo`, the installer, or pairing. Never through a request.

M5's strictest-wins resolution makes classification local and sound:

- adding a `deny`, `ask-strong` or `ask` rule never loosens;
- changing a rule's mode is tightening only if the new mode is at least as strict (a shorter
  allow-for window counts);
- removing a rule tightens only if it was an `allow-for`. Removing a deny, ask-strong or ask rule
  can loosen, because a narrower `ask` may have been carving an exception out of a broader
  allow-for;
- TTLs: shortest wins, so adding or shortening a TTL tightens, and lengthening or removing one
  loosens.

`core/src/change-classify.ts` implements this per field, and a property test checks it against
`resolvePolicy`.

### Op table (every existing and planned admin op)

| CLI (non-root caller) | Class | Notes |
|---|---|---|
| `status` | Read | Audit "last 10" filtered as for `audit tail` |
| `policy list [--json]` | Read | Owner config; no secrets |
| `agent list` | Read | ids and names only |
| `sessions list` | Read, **restricted** | Own agent only; counts only, as today |
| `audit verify` | Read | |
| `audit tail` | Read, **restricted** | Own agent's events plus `change.*`, `policy.*`, `agent.*`. Never other agents' `tool.call` / `fill.*` origins, and never `intent.recorded.textSha256` (a guessing oracle for short prompts) |
| `password list` | Read, **restricted** | Domain, type and source; **no usernames** (decision 8) |
| `approver list` | Read, **restricted** | Counts and kinds only, no key ids |
| `changes [--limit] [--json]` (new) | Read | The recent-changes list (below) |
| `request show / list / wait / cancel` (new) | Read; cancel own | Own requests only |
| `grants list` (new) | Read | Own agent's live allow-for grants (origin and end time) |
| `policy set <site> --deny` | Tighten | Self or `all` |
| `policy set … --ask-strong`, or `--ask` from allow-for, or a shorter `--allow-for` | Tighten | |
| `policy remove` of an allow-for-only rule | Tighten | Computed per field |
| `policy set … --session-ttl` (new or shorter) | Tighten | Can end sessions sooner |
| `sessions unkeep <site>` | Tighten | |
| `sessions clear --agent self [--site S]` | Tighten | |
| `grants end [--site S] [--agent self\|ID\|all]` (new) | Tighten | New signer op `end_grants`; closes M5's "signer copy lives until expiry" |
| `highrisk add <domain>` (new) | Tighten | Stored in the signer; drops saved sessions and allow-for for that site |
| `agent revoke self` | Tighten | Also discards its saved state (SESSIONS P2 `discard`) |
| `agent revoke <other>` | **Confirm** | DoS on the owner's other agent |
| `sessions clear --agent <other>` or `--all` | **Confirm** | Logs the owner's other agents out |
| `policy set … --allow-for D` (new or longer), self, D ≤ 1 h | Loosen, standard | Site must hold a broker credential; never high-risk (signer floor) |
| same with D > 1 h, or `--agent <other>` / `all` | Loosen, **high** | |
| `policy remove` or change of a `deny` | Loosen | Standard if an agent set it; **high** if the owner set it (root or migration) |
| `ask-strong` → `ask`, or removing an ask-strong / ask rule | Loosen | Same provenance rule. Refused outright if the site is high-risk (`no_effect_high_risk`: the floor stays) |
| `policy set … --session-ttl` longer, or `off` | Loosen, standard | **high** if not self |
| `sessions keep <high-risk site>` | Loosen, **high** | Bearer sessions for a bank or email at rest; site must have a broker login or saved session. Non-high-risk: no-op, refused |
| `agent add --kind <enum>` | Loosen, **high** | Name from an enum, token goes to the requester (below) |
| `highrisk remove <domain>` | Loosen, **high** | Only phone-added extras. Built-in and `/etc` entries are permanent floors |
| `approver pair / remove / qr` | Human-only | Pairing is the root of trust |
| `password add / remove / import` | Human-only | Secrets (inv 1); remove is irreversible |
| Proton Pass enable, vault, `pass-cli login` | Human-only | Signer config plus a secret session |
| Install, uninstall, upgrade, KEK, unlock | Human-only | |
| `/etc` config: approver origin, TLS, APNs, `--high-risk`, `browser.persist`, `--xvfb` | Human-only | |
| `agent rename` (new, root) | Human-only | Owner text on prompts |
| `policy migrate` (new, root) | Human-only | See "Migration" |
| `request unblock <agent>` | Human-only (sudo) or phone | An agent can't lift its own block |
| `browser_handoff` (MCP) | Not an admin op | SESSIONS P3 gates. Every request refused while any handoff is open, and for 60 s after |

**Non-root defaults:** `--agent` defaults to `self` for a non-root caller (root keeps `*`), and
`all` must be spelled out, so a plain request is never accidentally high-impact.

**Mixed calls:** a call that tightens some fields and loosens others, or loosens more than one, is
refused with "split this into separate commands" (one change per card).

**Never available, to anyone through a request:**

- allow-for on a high-risk site, or longer than 12 h;
- a `*` pattern;
- durations outside the enums;
- removing a built-in or `/etc` high-risk domain.

### Request-time gates (in order; each refusal is audited as `change.refused {requestedBy, op, reason}`)

1. A valid, active agent token over `request.sock`. Then strict schema validation: unknown keys
   get a 400, every string is checked against its enum or a validated pattern.
2. `changes.agentRequests` in `/etc/aab/core.json` is `on` (`tighten-only` refuses classes 3 and
   4).
3. Class 3 or 4 needs at least one paired phone (`no_phone`; use sudo).
4. A live intent for the requesting agent. Class 4 also requires that this intent hasn't already
   been used by another loosening request (one per user message).
5. No handoff open, none ended in the last 60 s (`handoff_open`), and no credential approval
   pending for this agent (`approval_pending`).
6. The subject comes from existing state (`no_such_rule`, `no_credential_for_site`,
   `no_session_for_site`, `no_effect_high_risk`).
7. Rate limits (below).
8. The current value is captured as `before`, along with its provenance (`beforeSetBy`).

## Where policy state lives (the signer as authority for modes)

| Option | Holds against a compromised core? | Verdict |
|---|---|---|
| A. SQLite stays authoritative; the signer only verifies change approvals | No. The core can rewrite rows or simply ignore them. Defense in depth against core bugs only | Use only for core-enforced state |
| B. **Signer-held mode rules plus phone-added high-risk domains**, enforced at sign, fill and grant-use time; the core keeps a read-only mirror | Yes, for everything that skips or weakens a prompt | **Recommended** |
| C. Signer-issued MACs over core rows | No, unless it is a whole-set MAC with a signer-held version: the core can *omit* a deny or ask-strong row, which is a loosening. With the version it is B plus extra bytes per request | Rejected |

**Signer-held, service mode** (key store `policy` section; zero dependencies):

```
policy: { version: number,          // +1 on every change, persisted
          rules: [{pattern, agentId | '*', mode: 'deny'|'ask'|'ask-strong'|'allow-for',
                   allowForMs?, setBy: 'owner'|'agent'|'approval', changeId?, updatedAt}],
          highRiskExtra: [{domain, addedAt, setBy}],
          migratedAt?: number }
```

- `resolvePolicy` and `patternMatches` move to `@aab/signer/policy` (pure, built-ins only); the
  core imports them, so both sides resolve identically. Pattern *validation* with the PSL stays in
  the core and the CLI. The signer requires LDH labels and a dot, and the owner sees the pattern
  when signing.
- **Floor checks in the signer** (`server.ts`, before consuming any approval or grant use). This
  needs **`agentId` in `ApprovalStatement`**, since today only grants carry it:
  1. `effective = resolve(rules, statement.agentId, origin)`, raised to ask-strong for built-in,
     config or phone-added high-risk sites.
  2. `deny` → `policy_deny`.
  3. `ask-strong` → UV method, lifetime ≤ 60 s, `strong: true`, no grant, *whatever the core
     sent*.
  4. A statement carrying a grant → the effective mode must be allow-for and
     `until − issuedAt ≤ allowForMs`.
  5. A grant use → still allow-for **now** and `now ≤ grant.createdAt + current allowForMs`.
     Narrowing or removing a rule therefore ends the signer's grants at once, which fixes the M5
     known limit.
  6. `GrantedApproval.agentId` must equal `statement.agentId`.
- **Signer ops on the channel:** `policy_snapshot` → `{version, rules, highRiskExtra}`;
  `policy_tighten {change}` → applied only if the signer's own classifier says monotonic, else
  `not_tightening`; `end_grants {agentId?, origin?}`; `apply_change {statement, approval}` (below).
- **Signer admin socket (root):** `policy.set|remove|list|import`, `highrisk.add|remove|list`.
  Root mode changes go **directly** to the signer admin socket, never forwarded by the core. Over
  the channel the signer can't tell root's words from a compromised core's.

**Core-held** (enforced by the core alone; changed through signer-verified approvals for defense
in depth and to keep "never verify in the core"): session TTL (the `policies.session_ttl` column;
`mode` becomes unused in service mode); `persist_optins`; `agents`; session clears and saved
state.

**Core mirror:** a `policy_mirror(pattern, agent_id, mode, allow_for_ms, set_by, version)` table,
replaced wholesale from `policy_snapshot`:

- at start;
- after every change the core applies or relays;
- on `policy.resync` (core admin op the CLI calls after a root signer-admin write);
- when the signer refuses with `policy_deny`, `grant_not_allowed` or `strong_required` while the
  mirror disagrees (audited `policy.mirror_mismatch {mirror, signer}`, then resync).

`PolicyStore.resolve` reads modes from the mirror and TTLs from `policies`, still per request. The
core's high-risk list becomes config plus the mirror's `highRiskExtra`; SESSIONS' save and restore
filters use it too.

**Fail closed on mismatch:** the signer always uses its own rules. A core that thinks "allow-for"
while the signer says "ask" gets a refusal, denies, resyncs, and the next login asks.

**Migration (upgrade):**

- `install.sh` runs `aab policy migrate`: the CLI as root reads `policy.list --json` from the core
  admin socket, prints it, and posts it to signer admin `policy.import` (`setBy: 'owner'`, sets
  `migratedAt`).
- Until `migratedAt` is set, the core resolves the **strictest of (old SQLite modes, mirror)**, so
  nothing loosens during the gap, and grants fail closed (more prompts).
- After import, the core clears the old mode columns (`none`).

**Dev mode:** the signer is spawned with `policyAuthority: 'core'`, so M5 behaviour and tests are
unchanged. Unit tests run the handler with `'signer'`.

## Change statement and verification path

New type in `@aab/signer/change`, with its own signing domains:

```ts
interface ChangeStatement {
  v: 1;
  type: 'change';
  changeId: string;                 // UUID, single use
  stage: 'apply' | 'arm' | 'confirm';   // 'arm'/'confirm' only when a red flag fires
  armId?: string;                   // confirm only: the arm statement's changeId
  flags: Array<'quiet_hours' | 'not_in_your_words' | 'recent_deny' | 'new_agent'>;
  delayed: boolean;                 // flags.length > 0 on a high-impact change
  typedConfirm: boolean;            // required true on high-impact statements
  op: 'policy.mode' | 'policy.ttl' | 'session.keep' | 'agent.add' | 'agent.revoke'
    | 'sessions.clear' | 'highrisk.remove';
  agentScope: string;               // agent id or '*'
  target: string;                   // normalized pattern / registrable domain / agent id / ''
  before: ChangeValue;              // closed unions, enum durations only (below)
  after: ChangeValue;
  beforeSetBy: 'owner' | 'agent' | 'approval' | 'none';
  requestedBy: string;              // requesting agent id
  intentHash: string;
  impact: 'standard' | 'high';
  userVerified: true;
  issuedAt: number; expiresAt: number;   // ≤ 60 s, fixed when the owner taps Approve
}
// signing bytes:  "aab-change-v1\n" + canonicalJson(s)
// native:         "aab-native-change-v1\n" + canonicalJson(s)
// WebAuthn challenge: b64url(SHA-256(signing bytes))
```

- `ChangeValue` is one of: `{mode: 'default'|'deny'|'ask'|'ask-strong'|'allow-for',
  allowForMs?}`; `{ttlMs: number|null}`; `{kept: boolean}`; `{agent: 'absent'|'active', name?}`;
  `{highRisk: boolean}`; `{sessions: 'kept'|'cleared', site?}`.
- Enums for request-made values:
  - allow-for: 5m, 15m, 30m, 1h, 2h, 4h, 8h, 12h;
  - TTL: 15m, 1h, 4h, 12h, 1d, 7d, 30d, off;
  - agent names: `Claude Code | Codex | Cursor | Gemini CLI | Goose | OpenCode | Agent`, plus
    " 2".."9" on a clash.
- **Domain separation.** The existing domains are `aab-approval-v1`, `aab-native-approval-v1` and
  `aab-handoff-start-v1`. Canonical JSON always starts with `{`, so no prefix collisions are
  possible. A change assertion can't verify as a login approval or a handoff start, and the
  reverse also holds (tested).

**Path:**

1. Agent → `request.sock` → the core validates, classifies and gates. It writes a
   `change_requests` row (`pending`), audits `change.requested`, enqueues a `change` view on the
   PhoneApprover, and pushes once.
2. The owner taps Approve. `/api/challenge` (or `/api/native/challenge`) fixes the statement:
   `before` is re-read now, `issuedAt` is now, 60 s lifetime. The phone asserts with UV, or the
   app signs with Face ID.
3. `/api/decide` → the approver pre-checks with the same verifier (better errors) → the core →
   signer `apply_change`.
4. **The signer:**
   - verifies the signature against trusted approver keys, with UV and counter (it reuses
     `verifyWebAuthnAssertion` / `verifyNativeSignature`, refactored to take the expected
     challenge);
   - checks freshness: ≤ 60 s, `issued_before_signer_start`, and `changeId` not used before;
   - checks the schema strictly (known fields and enums);
   - **recomputes class and impact itself** from op, before, after, scope versus requester,
     `beforeSetBy` (its own record for signer-held rules) and its high-risk lists, and refuses a
     mislabelled statement;
   - enforces stages: high impact needs `typedConfirm`; a delayed one (flags present, or the
     signer's own quiet-hours check) needs `arm`, then `confirm` with `armId`,
     `issuedAt ≥ armedAt + 5 min` and ≤ 1 h; an undelayed one is a single `apply`. Arms are kept in memory, so a restart drops them
     (fail closed);
   - for signer-held targets: compare-and-swap `before` against current state
     (`change_conflict`), apply, bump the version, persist, then return `{applied, version}` or
     `{armed, confirmAfter}`;
   - for core-held targets: return `{verified}` and log `change_verified`.
5. The core resyncs the mirror, or does a compare-and-swap plus apply in one SQLite transaction
   for core-held state (`PersistOptins.add(…, 'approval')`, `AgentRegistry.add` with an enum name
   and `created_by`, the TTL column, clears). It audits `change.applied` or `change.conflict`, and
   `wait` returns.

Tightening never goes through `apply_change`: signer-held → `policy_tighten`; core-held → applied
directly.

**Agent add:** the token is returned **to the requesting agent**, which writes the new host's
config. The card says so plainly ("Claude Code will receive the key for the new agent 'Codex' and
can act as it"). At most 2 active agent-created agents. Created agents inherit their creator's
blocks and count against the creator's budget.

## Rate limits, expiry, replay

| Limit | Value |
|---|---|
| Pending request lifetime (unanswered) | 10 min → `expired` |
| Statement lifetime | ≤ 60 s, from the tap |
| Pending class 3/4 per agent / overall | 1 / 3 |
| Loosening requests per agent | 3 per hour, 8 per day (20 per day overall) |
| After a deny | That agent is blocked from class 3/4 for 30 min. The same (op, target, after) is blocked for 24 h |
| 3 denies in 24 h | Quarantine until lifted (phone with UV, or `sudo aab request unblock`) |
| Tightening per agent | 30 per hour; phone notifications coalesced (≤ 1 push per 5 min) |
| Pushes per request | Exactly 1. `wait` / `show` never re-push. A delayed high-impact change: one more when it becomes ready to confirm |
| Restart | Core: pending → `expired {reason: 'restart'}`. Signer: arms and used ids are dropped, and `issued_before_signer_start` kills older statements |

Replay is blocked by: a `changeId` single-use set in signer memory; the binding to the exact
canonical statement through the challenge; the 60 s lifetime; `issued_before_signer_start`; the
WebAuthn counter; and compare-and-swap on `before`, which also catches races with root edits.

## Transport: CLI over a user-owned request socket, with the agent token

**Recommendation:** `/run/aab/request.sock`.

- Socket-activated by a new `aab-core-request.socket`, owned by the installing user, 0600, exactly
  like `intent.sock`, so a third uid can't `connect()`.
- HTTP on the socket, in the `intent-server.ts` style: strict JSON, ≤ 4 KiB, a 64 KiB cap.
- `Authorization: Bearer aab_agent_…`: the agent's own token, which the non-root `aab` reads from
  `AAB_AGENT_TOKEN` (`agent add` prints the host snippet). Cards then name the requesting agent,
  and limits are per agent.

Routes:

- `POST /v1/changes` → `200 {status: 'applied'}` (tighten) or
  `202 {changeId, status: 'pending', expiresAt, summary}`;
- `GET /v1/changes/<id>?wait=≤55` (long-poll; own requests only);
- `POST /v1/changes/<id>/cancel`;
- `GET /v1/read/{status, policy, sessions, agents, audit, passwords, changes, grants}`
  (filtered).

It is kept separate from `intent.sock`: a different credential, and a bug in one can't record
intents or file changes through the other.

Rejected:

- **An MCP tool.** CLAUDE.md: "no MCP tool input may reach policy or approvals". It would also
  grow the pinned tool list. Cost: MCP-only agents can't request changes (decision 3).
- **The MCP HTTP endpoint.** Loopback TCP is reachable by every uid; the socket adds the uid
  layer.
- **A user group socket.** It has the same effect but is weaker.

D3's original objection ("could mint agent identities or revoke yours") is answered: minting is
high-impact loosening, and revoking others is Confirm.

## Phone UI (web page and iOS app)

**Card** (`kind: 'change'` in `/api/state.pending`; old apps see `.unknown` and can't sign,
because they refuse unknown statement fields):

- **Colour band per class.** Grey "Confirm", amber "Loosen security", red "High-impact change".
  Tightening notifications have no card.
- **Headline sentence from a fixed wording table** in `approver/src/render.ts`, keyed by op ×
  before × after and shared with Swift. Examples:
  - "Let Claude Code sign in to github.com without asking for 1 hour after each approval."
  - High-impact wording is extra-plain: "Claude Code will stay signed in to chase.com even after
    the broker restarts. Anyone who gets this computer's broker data could use that session."
- **Rows:** **Now** and **After** (side by side); **Applies to** (agent name or "**all agents**",
  always written out); **Requested by**; **Setting made by** (owner with sudo on <date> / Claude
  Code 3 min ago / your approval); **Your last message** (verbatim and time, labelled "from your
  agent host's hook", visually secondary); **Expires in**.
- **Targets** are always raw punycode. Warnings come only from broker computations:
  - "uses non-Latin characters (shown in raw form)" for any `xn--` label;
  - "looks like paypal.com" (edit distance ≤ 2 or a homoglyph-folded match to a high-risk or
    credential domain);
  - "you have no saved login here" (should never happen, since it is refused).
- **Fixed lines on every loosening card:** "Your agent can't approve this. If your agent told you
  this is routine, deny it and make the change yourself with sudo."
- **Buttons:** **Deny** (primary), **Deny and pause this agent's requests for 24 h**, and
  **Approve with Face ID** (secondary). High-impact: a "Type chase.com to confirm" field enables
  the approve button. If a red flag fired, the card names it ("It's 3:12 a.m., inside your quiet
  hours") and the button reads "Start 5-minute wait", with "Nothing changes until you confirm after
  03:17". When ready: "Confirm change".
- No bundles, no "approve all", one card at a time. Never rendered on `/handoff`.

**Recent changes** (`/changes` on the web, a **Changes** tab in iOS; served from `change.*` audit
events, newest first):

- every applied change, whichever class or channel (agent, phone, **root/sudo**, migration), plus
  denied, expired and conflicted requests;
- **Undo** on a loosening entry: that is a tightening, so it is device-authenticated with no Face
  ID ("a forged undo is a DoS, never a loosening");
- iOS cross-checks its local `HistoryView` records and flags "This iPhone has no record of
  approving this" for any broker-claimed phone approval it didn't sign;
- daily digest push if anything changed ("Today: 1 approved, 4 automatic, 1 denied"; opt-out).

**Push:** Web Push `{"t":"change"}` / `{"t":"changed"}` / `{"t":"digest"}`; APNs categories
`CHANGE` (lock-screen **Deny** only; Approve opens the sheet), `CHANGED` and `DIGEST` (no
actions); text "Change request from <agent name>", fixed with `--apns-generic`.

**iOS:**

- `ReplayApproverCore/Change.swift`: parse with known fields only, enums, the stage logic, the
  60 s lifetime, target syntax, the native signing bytes, and the wording table. It **renders the
  card from the statement itself**, which closes the Phase B "page served by core" limit for
  changes.
- New views: `ChangeSheet.swift` (never reuses `RequestSheet`) and `ChangesView.swift`.
- `Statement.swift` gains `agentId` in `knownFields` and checks it against `display.agentId`.
- Fixtures in both directions.

## CLI UX (what the agent sees)

```
$ aab policy set github.com --allow-for 1h
Sent to the owner's phone as change request c-7f3a9e.
  github.com, agent "Claude Code": ask every time → ask, then allow for 1 hour
  Nothing changes until the owner approves it on their phone. Expires in 10 minutes.
  Wait for it:  aab request wait c-7f3a9e      Status: aab request show c-7f3a9e
  The owner decides. Don't ask them to approve it.
(exit 3)
```

- **Exit codes:** 0 applied, 3 pending or armed, 4 denied, 5 expired or cancelled, 6 conflict, 7
  refused (with a fixed reason code), 1 error.
- `request wait [--timeout 10m] [--json]` loops on the long-poll and prints one final line.
  Delayed high-impact: "approved once; the owner can confirm after 03:17. Nothing has changed yet." (exit
  3).
- Tightening: "Applied: deny on example.com for agent Claude Code. The owner's phone was
  notified." (exit 0).
- No token: "set AAB_AGENT_TOKEN to send this to the owner's phone, or run it with sudo." Root
  (sudo) is unchanged and immediate, but now also notifies the phone and appears in recent
  changes.

## Data model changes

| Where | Change |
|---|---|
| Signer key store | `policy` section (above). Rules carry `setBy` and `changeId` |
| Signer memory | `usedChangeIds`, `arms: Map<changeId, {statementHash, armedAt}>` |
| `ApprovalStatement` | **`agentId`** (signed); `display.agentId` for the app's check |
| Core SQLite | `policy_mirror(...)`. `policies.mode` is unused in service mode after migration |
| Core SQLite | `change_requests(id, requested_by, op, agent_scope, target, before_json, after_json, before_set_by, impact, class, status, intent_id, created_at, expires_at, decided_at, armed_at, confirm_after, approver_key_id)`. Intent ids are referenced, never their text |
| Core SQLite | `change_blocks(agent_id, until, reason)` (deny cooldowns, quarantine) |
| Core SQLite | `agents` gains `created_by` (agent id / 'root') and `name_source` ('owner' / 'enum') |
| Core SQLite | `persist_optins.via = 'approval'` (already reserved on `sessions-handoff`) |
| `/etc/aab/core.json` | `changes.agentRequests: 'on' \| 'tighten-only' \| 'off'` (default on). `cooldownMinutes` is not configurable (signer-enforced constant) |

## Audit events (identifiers, enums and validated sites only)

- `change.requested {changeId, op, agentScope, target, class, impact, requestedBy, via:
  'agent'|'root'|'phone', intentId?}`
- `change.refused {requestedBy, op, reason}`: the target is logged only once validated, never raw
  input.
- `change.applied {changeId?, op, agentScope, target, before, after, class, via, approverKeyId?,
  policyVersion?}`
- `change.denied`, `change.expired`, `change.cancelled`, `change.conflict`,
  `change.armed {changeId, confirmAfter}`
- `change.agent_blocked {agentId, until, reason}`, `change.agent_unblocked {agentId, via}`
- `policy.resync {version}`, `policy.mirror_mismatch {mirror, signer}`, `grant.ended {grantId,
  via}`
- Existing `policy.set` / `policy.removed` / `session.keep_set` / `agent.added` / `agent.revoked`
  / `session.cleared` gain `via` and `changeId`.
- Signer journal: `change_verified`, `policy_changed {version, op}`, `arm_recorded`.

## Build order

- **A1. Read surface, tightening, request socket** (needs SESSIONS P2 merged).
  - New: `core/src/{change-classify,changes,request-server}.ts`.
  - Changed: `core/src/{db,daemon,admin-ops,index}.ts`, `cli/src/{args,main,status,sessions,
    policy}.ts`, new `cli/src/request.ts`, `cli/src/service/{cli,paths,core-main,config}.ts`.
  - Install: `units/aab-core-request.socket`, `install.sh`, `uninstall.sh`.
  - Approver: `changed` push and `/changes` (read only).
  - Here all of class 3/4 is refused `not_yet`.
- **A2. Signer policy authority.**
  - Signer: new `signer/src/policy.ts`; `keystore.ts`, `server.ts` (floor and ops),
    `protocol.ts`, `client.ts`, `approval.ts` (`agentId`), `service.ts` (admin ops).
  - Core: `policy.ts` (mirror, strictest-of during migration), `broker.ts`, `grants.ts`.
  - Approver: `statement.ts` and types.
  - iOS `Statement.swift`; CLI root routing (modes → signer admin, TTL → core admin) and `policy
    migrate`; installer upgrade step.
- **A3. Loosening and Confirm on the web phone.**
  - Signer: new `signer/src/change.ts` and `server.ts` `apply_change`.
  - Approver: `phone.ts` (change view, challenge, decide, native endpoints), `render.ts`
    (wording), `page/{app.html,app.js,app.css,sw.js}`, `webpush.ts`, `apns.ts`.
  - Core: `changes.ts` apply path, `agents.ts` (enum names, `created_by`).
  - CLI: `request wait|show|list|cancel`.
- **A4. iOS.** `ReplayApproverCore/{Change,Models,BrokerClient}.swift`,
  `Views/{ChangeSheet,ChangesView}.swift`, `Services/Notifications.swift`, fixtures.
- **A5. Isolation, mutation pass, docs.**
- **Handoff gate:** `isHandoffOpen()` hook, a no-op until SESSIONS P3 lands.
- Each phase: `pnpm typecheck && pnpm lint && pnpm test && pnpm test:isolation`, plus the
  verify-aab skill's sandboxed run.

## Tests

| Test | Covers |
|---|---|
| `signer/test/inv6-signer-policy.test.ts` | deny / ask-strong / allow-for floor with a *valid phone approval* the core requested wrongly. Grant refused without a covering rule or with a longer window. Grant use refused right after the rule is narrowed or removed. Per agent vs `*`. `agentId` required and must match the grant's. `policy_tighten` refuses a loosening (`not_tightening`). Version monotonic; persists across restart. Phone-added high-risk raises to strong |
| `signer/test/inv6-change-approval.test.ts` | UV only (webauthn or native). **Domain separation** in both directions (login ↔ change ↔ handoff start). Replayed `changeId`; expired; > 60 s; issued before signer start; `before` mismatch → `change_conflict`; unknown op or field; non-enum duration; mislabelled impact or class (the signer recomputes); high impact without `typedConfirm`; a flag the signer computes itself (quiet hours) omitted; confirm before the 5-minute wait, after 1 h, without an arm, against a different arm, or after a restart; an undelayed high-impact change applies in one step |
| `signer/test/inv9-channel.test.ts` (ext.) | New ops refused without a valid MAC |
| `signer/test/admin-policy.test.ts`, `native-change-vectors.test.ts` | Root ops; Swift and TS byte equality |
| `core/test/change-classify.test.ts` | Exhaustive per-field table plus a property test: "tighten" ⇒ for random rule sets and sampled (agent, origin), the effective policy after is at least as strict as before |
| `core/test/change-requests.test.ts` | Gate order, every limit, expiry, one per intent, cooldown, quarantine, `handoff_open`, `approval_pending`, subject-from-state rules, warnings |
| `core/test/inv4-change-intent.e2e.test.ts` | No live intent → refused, no push, audited; with one → exactly one push; second loosening on the same intent → refused |
| `core/test/inv5-change-card.e2e.test.ts` | ZQX markers in every agent- and page-controlled channel (extra JSON keys, MCP args, page title and DOM, intent-free fields) never appear in `/api/state` or `/api/native/state`. Lookalike and punycode targets shown raw with the warning. Agent names come only from the enum |
| `core/test/inv6-change-loosen.e2e.test.ts` | Request → `policy list` and logins unchanged until approval. Deny → nothing applied, cooldown. A broken assertion → the core applies nothing. High-impact type-to-confirm applies in one step with no flags; each red flag (quiet hours, not in your words, recent deny, new agent) forces arm, 5-minute wait and confirm, with a fake clock. Keep-signed-in on a high-risk site persists only after approval. Tightening applies at once and notifies. Confirm class needs approval |
| `core/test/inv6-change-phone.e2e.test.ts` | Full web flow with the separate "phone" Chromium (virtual authenticator) |
| `core/test/inv10-audit.e2e.test.ts` (ext.) | Every `change.*` event in the chain; payloads hold no free text or intent hashes |
| `core/test/request-reads.test.ts` | Filtered `audit tail` / `sessions list` / `password list` / `approver list` |
| `approver/test/change-server.test.ts` | Endpoints, device auth, CSP, change challenge, Undo-as-tighten, pause, no change card on `/handoff` |
| `cli/test/request.test.ts`, `args.test.ts` | Non-root routing, `self` default, mixed-call refusal, exit codes, `wait` |
| `ios/ReplayApproverCore/Tests/ChangeStatementTests.swift` | Parsing, wording, stages, fixtures |
| `isolation/test/inv9-isolation.test.ts` (ext.) | Third uid: `connect(request.sock)` → EACCES. agentuser: request socket with no or revoked token → 401 |
| `isolation/test/inv6-change-isolation.test.ts` (new) | As agentuser: `aab policy set --allow-for` → pending, root view unchanged. A self-made P-256 "approval" posted to `/api/decide` and `/api/native/decide` (no device, or own key) → refused. Replaying a captured real approval → refused. agentuser can't reach either admin socket. After the phone approves → applied; `change.*` present |

**Mutation checks** (each must fail a test): drop the change domain prefix; skip `before`
compare-and-swap; trust the core's `impact`; allow a grant without a covering rule; skip the rule
re-check on grant use; classify "remove ask rule" as tightening; accept a revoked token on
`request.sock`; make `request.sock` 0666; skip the intent gate; pass an extra request field into
the view; ignore the wait period; disable rate limits; disable the `handoff_open` gate; unfilter
`audit tail`; have the core apply without `apply_change`.

## Invariant check (read first)

- **Inv 5: needs owner agreement (decision 4).** A change card's *subject* (domain, scope,
  duration) is chosen by the agent. It is not the credential prompt that inv 5 governs, but it is
  the same spirit. Mitigation: subjects only from existing broker state and enums, raw punycode,
  broker-computed warnings, no free text. Agent-added agents get **enum names**, because free
  names would later appear on credential prompts and *would* break inv 5.
- **Inv 4/5, existing accepted limit, higher stakes.** Service-mode agents can read the host token
  and forge "You said". Cards show it as secondary context, labelled by source; nothing depends on
  it except the one-per-intent rate limit (decision 5).
- **Inv 6: strengthened.** The signer floor for modes, grants ended at once on narrowing, and
  `agentId` signed.
- **CLAUDE.md "no MCP tool input may reach policy or approvals": respected** (CLI only). The
  bullet should be reworded to: "agent-originated changes go only through `request.sock` and apply
  only as monotonic tightening or after a signer-verified owner approval".

## Docs to update

- **ARCHITECTURE:** 6.1 (the request socket next to the admin CLI); 6.2 (new signer ops); 9 (modes
  are signer-authoritative in service mode, plus the change classes); 10 (new tables); 11 (rows for
  "agent loosens policy", "social engineering of approvals" and "compromised core vs policy").
- **IMPLEMENTATION_NOTES:** status entries and a new section "Agent-manageable administration".
  Deviations: M5's "read per request from SQLite" becomes "mirror of signer rules"; the M5 "signer
  grant outlives a narrowed rule" limit is fixed; the D3 implementation changed. Known limits:
  forgeable intents on cards, same-uid token attribution, and Phase B card rendering by the core.
- **ISOLATION_PLAN:** D3 "Later" is done; the Shape diagram gains `request.sock`; tests list.
- **SESSIONS_PLAN:** keep and unkeep via approval; `handoff_open` gates change requests.
- **integrations:** `service-mode.md` (request socket, `policy migrate`, `changes.agentRequests`);
  `claude-code.md` (`AAB_AGENT_TOKEN`, `request wait`, agent guidance); `phone-approver.md` and
  `ios-app.md` (cards, Changes, Undo, digest).
- **CLAUDE.md:** layout lines, commands, the non-negotiable rewording.

## Not in this plan

- Dev-mode request socket.
- An MCP tool for requests.
- Phone-initiated loosening (the phone as an admin console).
- App Attest.
- Moving password-source config into the signer store.
- A per-uid intent channel (the real fix for forged intents).

## Decisions for the owner

1. **Policy modes move into the signer in service mode** (B), with a core mirror and a migration
   step. *Recommend yes.* Without it, "a compromised core can't loosen" doesn't hold.
2. **`agentId` added to the signed `ApprovalStatement`.** iOS needs an update; older apps refuse
   new statements (fail closed). *Recommend yes.*
3. **Transport is CLI → user-owned `request.sock` + agent token; no MCP tool.** MCP-only agents
   can't request changes. *Recommend yes.*
4. **Change cards may show agent-*selected* subjects** from existing state and enums only (a
   parallel rule to inv 5). *Recommend accept.*
5. **Keep "You said" on change cards** despite forgeability, as a secondary, labelled line.
   *Recommend yes.*
6. **High-impact friction (decided 2026-10-13):** type-to-confirm plus Face ID, with no wait by
   default; a 5-minute signer-enforced wait (confirm within 1 h) only when a red flag fires: quiet
   hours, the target not in the owner's own words, a recent deny, or a new agent. The owner
   rejected a fixed wait on every change.
7. **Agents may add agents** (high impact, enum names, token to the requester, max 2). *Recommend
   yes;* the alternative is human-only.
8. **`password list` for agents shows no usernames.** *Recommend yes.*
9. **Filtered `audit tail` / `sessions list` for agents.** *Recommend yes.*
10. **Confirm class** for revoking other agents and clearing other agents' or all sessions.
    *Recommend yes.*
11. **Rate-limit defaults** as tabled. *Recommend yes.*
12. **Undo and pause from the phone without Face ID** (tightening only). *Recommend yes.*
13. **Root/sudo changes also notify the phone** and appear in recent changes (this exposes a
    captured sudo). *Recommend yes.*
14. **`changes.agentRequests` default `on`** for shipped installs. *Recommend on;* `tighten-only`
    for cautious users.
15. **Dev mode keeps M5 behaviour** (no request socket, SQLite authoritative). *Recommend yes.*
16. **Enabling password sources stays human-only.** *Recommend yes* (signer config plus a secret
    login).
17. **Daily digest push** when anything changed, opt-out. *Recommend yes.*
