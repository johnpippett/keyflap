# Security policy

Keyflap signs AI agents into websites with your passkeys and passwords. A bug in it can
hand an agent, or whoever controls a web page the agent visits, access to your accounts.
Please report security problems privately, as described below.

## Project status

Keyflap is an **early alpha** maintained by one person. **No outside party has audited it.**
The design is written down in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and every
security invariant has automated tests, but tests don't make up for an independent review.
Start with low-stakes accounts, and keep your normal way of signing in: a passkey Keyflap
creates is always an extra credential, never a replacement.

## Supported versions

Only the latest release and the `main` branch get security fixes.

## Reporting a vulnerability

**Don't open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/johnpippett/keyflap/security/advisories/new)
(the repository's *Security* tab, then *Report a vulnerability*). Only the maintainer
sees the report, and the fix can be worked on there with you.

Please include:

- what an attacker can do, and from which position (a hostile web page, a prompt-injected
  agent, another local user, a process running as the agent's OS user, …);
- the mode you ran: service mode (`install.sh` or the one command), the simple Mac install, or
  dev mode (`keyflap daemon --unprotected`), and on Linux or macOS;
- steps to reproduce, ideally against the bundled test relying party (`pnpm test-rp`);
- the commit or release you tested.

**Never put a real password, key, token or one-time code in a report.** Use the test RP
and its fake accounts instead.

### What happens next

The maintainer works on this alone, so these are targets rather than promises:

- acknowledgement within **7 days**;
- a first assessment (confirmed or not, and how severe) within **14 days**;
- a fix or mitigation within **90 days** of the report, sooner for serious issues.

Disclosure is coordinated: a GitHub security advisory is published once a fix is out, or
after 90 days, whichever comes first, unless we agree on another date. You'll be credited
in the advisory unless you'd rather not be.

## Scope

**In scope:** anything that breaks one of the security invariants in
[ARCHITECTURE.md section 5](docs/ARCHITECTURE.md#5-security-invariants), for example:

- an agent receiving a private key, password, TOTP seed or one-time code, through any tool
  output, saved browser state or log;
- a credential used for an origin it isn't bound to, or an origin taken from the agent or
  the page instead of the browser's trusted side;
- an approval prompt with no live intent from you, or with text that the agent or a page
  wrote;
- a signature or fill without an approval your policy requires, or a high-risk site
  approved without fresh user verification on your phone;
- an agent getting raw DevTools (CDP) access to the managed browser;
- anything other than the broker core getting requests accepted by the signer;
- the phone approver signing something other than what its card shows;
- an operation missing from the audit log, or an edit to it that `keyflap audit verify` doesn't
  catch (beyond the known limits below);
- in service mode, a process running as your OS user reading the broker's keys, memory,
  browser or files.

**Out of scope:**

- the known limits listed below and in
  [docs/IMPLEMENTATION_NOTES.md](docs/IMPLEMENTATION_NOTES.md), unless you find a way to
  make one worse than described there;
- attacks that need root or an already compromised operating system;
- **dev mode** (`--unprotected`) against an agent running as the same OS user, which it
  doesn't defend against by design (it prints a banner saying so; use service mode);
- a site blocking automated browsers or showing a CAPTCHA (Keyflap never disguises
  automation or solves human checks);
- bugs in Chromium, Playwright, Proton Pass's `pass-cli` or other upstream projects:
  report those upstream, and to us only if Keyflap makes them exploitable.

When you research, use your own installation and the bundled test relying party. Don't
test against other people's accounts, or against websites you don't own.

## Known limits

These are documented trade-offs, not open vulnerabilities:

- **Intent matching is judged by you.** The approval card proves you recently asked for
  *something*. It doesn't prove this sign-in serves that request, so read the card.
- **Claude Code hook inputs.** Claude Code also runs its prompt hook for scheduled tasks,
  background-subagent reports and messages between sessions, and model-written text can
  then appear as "You said" on a card. Don't combine those features with Keyflap, and deny
  any card whose words you didn't type
  ([docs/integrations/claude-code.md](docs/integrations/claude-code.md)).
- **Hermes Agent: gateway direct messages only, Docker backend required.** Only your own
  DMs to the Hermes gateway become intents (never `hermes chat` turns, groups, webhooks, or
  messages sent while Hermes is busy). With Hermes's default `local` terminal backend the
  model can read the host token; the integration requires `terminal.backend: docker`, and
  stdio MCP servers and plugins still run on the host
  ([docs/integrations/hermes.md](docs/integrations/hermes.md)).
- **Codex CLI hook inputs.** The model is kept from the host token only by a Codex
  permission profile that denies the data dir and an approval policy that rejects sandbox
  escalation. Codex's `/review` sub-agent and programmatic clients (`codex exec`,
  `codex mcp-server`) can submit text you didn't type
  ([docs/integrations/codex.md](docs/integrations/codex.md)).
- **Dev mode doesn't isolate the agent.** Use service mode
  ([docs/integrations/service-mode.md](docs/integrations/service-mode.md)) when an agent
  has shell access. The simple Mac install is dev mode packaged, and doesn't isolate it either.
- **Service mode on a Mac has fewer layers than on Linux.** No systemd sandbox: the signer has
  network access, and its key-encryption key is a file that FileVault protects, not a TPM. The
  uid boundary and root-owned code are the same
  ([service-mode.md, "On a Mac"](docs/integrations/service-mode.md#on-a-mac)).
- **The audit log has no external anchor.** It detects edits, insertions and deletions,
  but not a truncated tail or a rewrite of every row from some point onward.
- **Transformed copies of a secret aren't scrubbed.** Output scrubbing catches a filled
  secret as typed, not encoded or rewritten copies of it.
- **The human-handoff live view shows the website's own pixels**, so a hostile page can draw
  anything in it, including a fake "Approve" button. Approvals only happen on Keyflap's own
  approval card, never inside the live view.
- **Human-check detection is a list of known providers.** A site's own home-made check
  reads as a normal sign-in.
