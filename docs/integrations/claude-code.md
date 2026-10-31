# Claude Code integration (reference)

The reference agent-host integration ([ARCHITECTURE.md section 8](../ARCHITECTURE.md#8-intent-binding)). Claude Code
gets two connections to the broker:

| Connection | Who uses it | Credential | What it can do |
|---|---|---|---|
| MCP over HTTP, `http://127.0.0.1:8765/mcp` | the model (agent) | the **agent token** (`aab_agent_…`) | drive the managed browser through the eight broker tools; ask for a login or a human handoff |
| intent socket, `~/.keyflap/run/intent.sock` | the `UserPromptSubmit` **hook** (Claude Code itself, not the model) | the **host token** (`~/.keyflap/host-token`) | record what you typed as the live intent for that agent |

A login prompt appears only if there is a live intent, and the prompt shows that intent
verbatim. So everything depends on one thing: **the model must not be able to read the
host token.** If it can, a prompt-injected agent can record its own "intent" and the
approval prompt shows words you never typed (invariant 4). Read
[Security requirements](#security-requirements-read-this) before you use this.

## Setup

**Quickest path:** `keyflap setup --unprotected` (dev mode) or `sudo keyflap setup` (service
mode) creates the agent and writes everything below into your Claude Code config for you,
after showing the diff ([setup.md](setup.md)). It authenticates the MCP connection with a
`headersHelper` (`keyflap mcp-headers`) instead of `${KEYFLAP_AGENT_TOKEN}`, so the token is not
in the model's environment either. `keyflap doctor` checks the result. The manual steps:

Requires a patched Node (22.23.4+ on 22.x; see the README) and this repository (`pnpm install`). The CLI runs from source, so
put it on your `PATH` with a symlink:

```sh
ln -s "$PWD/packages/cli/src/main.ts" ~/.local/bin/keyflap   # any directory on PATH
```

### 1. Start the daemon

(In service mode there is nothing to start: the broker runs as system services, under systemd
on Linux and launchd on a Mac. Run `sudo keyflap agent add <name>` for step 2 (on a Mac,
`sudo keyflap agent add <name>`); its output has the service-mode hook command
(`/usr/local/bin/keyflap hook claude-code --agent <id> --service`) and sandbox paths
(`/var/lib/keyflap/hook`, on a Mac `/Library/Keyflap/hook`). See [service-mode.md](service-mode.md).)

```sh
keyflap daemon --unprotected   # same-user dev mode; --data-dir ~/.keyflap  --mcp-port 8765  --headed (show the browser)
```

It asks for the key-store passphrase on the terminal without echo (twice on first run),
or reads `KEYFLAP_PASSPHRASE`. **Prefer the prompt.** Do not export `KEYFLAP_PASSPHRASE` in a
shell that Claude Code is started from: the model can read its own environment.

It prints the MCP URL and the intent socket path. Keep this terminal open: approval
prompts appear here.

### 2. Register Claude Code as an agent

In another terminal:

```sh
keyflap agent add claude-code
```

This prints the agent token **once**, plus ready-to-paste config with your agent id and
data dir filled in. `keyflap agent list` shows agents (never tokens); `keyflap agent revoke <id>`
stops a token at once, also while the daemon runs.

### 3. MCP server: `.mcp.json` in the project root

```json
{
  "mcpServers": {
    "keyflap": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer ${KEYFLAP_AGENT_TOKEN}" }
    }
  }
}
```

Claude Code expands `${KEYFLAP_AGENT_TOKEN}` from its environment, so the token stays out of
the file (and out of git). Start Claude Code with `export KEYFLAP_AGENT_TOKEN=aab_agent_…`.

The agent token is the agent's *own* identity: it is fine for the model to know it (it
can see its environment anyway). What the agent can do with it is limited to the MCP
tools, and every login still needs a live intent and your approval. **Never put the host
token here.**

### 4. Hook and protections: `.claude/settings.json`

Merge this into the project's `.claude/settings.json` (or `~/.claude/settings.json` to
cover every project). `keyflap agent add` prints it with absolute paths filled in:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "/usr/bin/node /path/to/repo/packages/cli/src/main.ts hook claude-code --agent <agent-id>" }
        ]
      }
    ]
  },
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "filesystem": {
      "denyRead": ["~/.keyflap/**"],
      "denyWrite": ["~/.keyflap/**"]
    }
  },
  "permissions": {
    "deny": ["Read(~/.keyflap/**)", "Edit(~/.keyflap/**)"]
  }
}
```

The hook command uses absolute paths so it doesn't depend on the `PATH` Claude Code runs
hooks with. `keyflap hook claude-code --agent <id>` works too if `keyflap` is on that `PATH`.
**Never run the hook through `pnpm`/`npm run`**: they print a banner to stdout, and a
`UserPromptSubmit` hook's stdout goes into the model's context.

If you use a non-default `--data-dir`, add `--data-dir <dir>` to the hook command and
use that directory in the sandbox and permission paths. Absolute paths are written
differently in the two places: `"/srv/keyflap/**"` in `sandbox.filesystem`, but
`"Read(//srv/keyflap/**)"` in permission rules (a single leading `/` there means "relative
to the settings file").

## Security requirements (read this)

### Why this is needed

Claude Code runs hooks as **your OS user**, the same user the model's Bash tool runs as.
There are no separate credentials for the hook. The host token file is `0600`, which
stops other users, not the model. So the model must be kept away from `~/.keyflap` by
Claude Code's own controls:

- **`sandbox.filesystem.denyRead`**: OS-enforced (bubblewrap on Linux/WSL2, Seatbelt on
  macOS) for Bash commands and every process they start, including `python`/`node`
  scripts that open files themselves.
- **`permissions.deny` `Read(...)`/`Edit(...)`**: covers the built-in file tools (Read,
  Edit, Grep, …), which run *outside* the sandbox: per the docs, "a `denyRead` entry
  doesn't stop the Read tool". It also covers Bash file commands Claude Code recognizes
  (`cat`, `head`, `sed`, redirections) but not arbitrary programs; that's what the sandbox
  is for. You need **both**. (Claude Code also adds `Read(...)` deny paths to the
  sandbox's `denyRead`, but set both explicitly.)
- **`allowUnsandboxedCommands: false`**: without it, when the sandbox blocks a command,
  the model may retry it with `dangerouslyDisableSandbox`, which runs it **outside the
  sandbox** (after a permission prompt, or with none if an allow rule matches). One
  unsandboxed `cat ~/.keyflap/host-token` defeats everything.
- **`failIfUnavailable: true`**: otherwise, if bubblewrap/socat are missing, Claude Code
  silently runs commands unsandboxed. Check with `/sandbox` that the sandbox is active.

The data dir also holds the terminal approver's key and the signer's encrypted key store;
`~/.keyflap/**` covers all of it.

**Upgrading from before the rename (`aab`, `~/.aab`).** If only `~/.aab` exists, `keyflap`
keeps using it and says so on stderr (the hook stays silent). Your existing settings then
still deny `~/.aab/**`, which is right. When you move it (daemon stopped:
`mv ~/.aab ~/.keyflap`), change every `~/.aab` in these settings to `~/.keyflap` at the same
time, or the model can read the moved directory. Also rename `AAB_AGENT_TOKEN` to
`KEYFLAP_AGENT_TOKEN` and the hook command `aab hook …` to `keyflap hook …` (or re-run
`keyflap agent add` and copy its output). Existing agent tokens keep working.

### What still defeats it

- `sandbox.excludedCommands` entries, the `!` shell prompt (you, not the model, but
  output can end up in context), and `--dangerously-skip-permissions` /
  `bypassPermissions` mode.
- Letting the model edit Claude Code's configuration: `.claude/settings*.json`,
  `.mcp.json`, hooks, skills. Hooks and MCP servers run **outside the sandbox with your
  full access**, so a hook the model wrote could read the token. The sandbox blocks
  sandboxed commands from writing these files, and Claude Code asks before its file tools
  touch them; do not approve such edits.
- Other software running as your user that the model can drive.
- In dev mode, letting the model write to the Keyflap checkout. The hook and the MCP
  `headersHelper` are `<checkout>/packages/cli/src/main.ts`, run outside the sandbox, so a
  model whose workspace (or any writable path) includes the checkout can change them and
  read the host token and its agent token. Keep the checkout outside every agent's
  workspace; `keyflap doctor` warns when a Claude Code project contains it. Service mode runs them from the
  root-owned `/opt/keyflap`.

**Run Claude Code as a separate OS user if you can.** The daemon, the signer and
`~/.keyflap` then belong to your user, and the agent's user cannot read the key store, the
approver key, or the signer's memory (the same-uid limit in IMPLEMENTATION_NOTES.md).
Note what this does *not* solve on its own: the hook still has to reach the host token,
and whatever the hook can do as the agent's user (read a token file, call a `sudo` rule
that runs `keyflap hook` as you), that user's Bash can do too, with forged input. The thing
that separates the hook from the model is the sandbox: hooks run outside it, the model's
commands run inside it. So keep the sandbox settings above in either setup.

### The intent socket itself

Connecting to a unix socket needs *write* permission on the socket file, not read.
What we know from the docs:

- With `denyRead` on `~/.keyflap/**`, sandboxed commands can't read the token, and the
  socket answers `401` without it. The token is the real secret; the socket is a second
  layer.
- On **macOS** the sandbox blocks all unix sockets unless listed in
  `sandbox.network.allowUnixSockets`. Don't list this one.
- On **Linux/WSL2**, unix sockets are blocked by a seccomp filter **only if it is
  installed** (`npm install -g @anthropic-ai/sandbox-runtime`; `/sandbox` shows it under
  Dependencies). Without it the sandbox doesn't block unix-socket calls. Don't set
  `allowAllUnixSockets`.
- We have **not verified** whether `denyRead`/`denyWrite` on the directory stop a
  `connect()` to the socket inside it on either platform. That's why the snippet also
  sets `denyWrite`. Treat socket access as a defense-in-depth question: the host token
  is what must never leak.

## How it works for you

1. You type a prompt in Claude Code. The hook forwards your exact words to the broker
   for the `claude-code` agent (live for 10 minutes; each new prompt replaces it).
2. The agent browses through the broker's tools. When a site asks for a passkey (or the
   agent calls `auth_login` / `auth_enroll_passkey`), the broker checks the real origin
   and the live intent. On a password login page, `auth_login` makes the broker fill and
   submit the form itself (username, password, and a following one-time-code step) from
   a password you stored with `keyflap password add <site> [--username U] [--totp]` (run it
   while the daemon is stopped). The agent never sees the values: they are scrubbed from
   every tool result, and fields still holding them are cleared after the submit.
3. The daemon terminal shows the prompt:

   ```
   ┌─ Keyflap: approval requested ────────────────────────────
   │ You said (2026-10-05T09:12:44.000Z):
   │   "log me into the staging dashboard and check the build"
   │ Site:       https://dash.example.com
   │ Agent:      claude-code
   │ Credential: passkey (sign-in)
   └──────────────────────────────────────────────────────────
   Approve? [y/N]
   ```

   It shows only your words, the verified origin, the registered agent name and the
   credential type; never text from the page or the agent. Judge whether this login
   matches what you asked. Unanswered prompts deny after 60 s.
4. The agent sees only the outcome: success, denied, failed, challenge, timeout, not
   eligible or no credential. No keys, challenges or signatures ever reach it.
   `challenge` means the broker submitted the form and the site answered with a human
   check (a CAPTCHA or "confirm you are human" page); `auth_status` and `browser_snapshot`
   also say `humanCheck: true` while one is shown. The broker never solves these and the
   agent is told not to try. Instead it calls `browser_handoff`: with the phone approver
   (`--approver phone`), your phone gets "Human check on <site>", you open the live view
   of that one page (one Face ID), tap and type through the check yourself, and tap Done.
   See "Human checks: `browser_handoff`" below. With the terminal approver the tool
   answers `unsupported` and the agent should just tell you.
5. Sign-ins last: the daemon saves each agent's cookies and site storage (encrypted, in
   `<data-dir>/browser-state`) and restores them when it starts again, so a restart doesn't
   mean signing in again. `keyflap sessions list` shows what is saved, `keyflap sessions clear
   --agent ID [--site SITE]` ends it, `keyflap daemon --ephemeral-browser` turns it off.
   High-risk sites (banks, email, identity providers) are only kept if you ask with
   `keyflap sessions keep <site>`.

No intent (you haven't typed anything in 10 minutes, the hook failed, or the daemon
wasn't running when you typed) means an automatic denial. Type your request again.

### Human checks: `browser_handoff`

What the agent is told (tool descriptions and the server instructions):

- After `auth_login` returns `{"status": "challenge"}`, or when `humanCheck` is true, call
  `browser_handoff`. Never try to solve a check, and never click it.
- The call waits up to `timeoutMs` (default 45 s, at most 120 s, so it stays inside the MCP
  SDK's default 60 s request timeout). It returns:
  - `done`: you finished; take a `browser_snapshot` and continue;
  - `pending`: still open; **call `browser_handoff` again** to keep waiting (the broker
    ends a handoff after 5 minutes: `expired`);
  - `cancelled`, `expired`: tell you and stop;
  - `denied`: not now (no recent request from you, an approval is waiting, too many
    handoffs in a short time, or the site is denied by your policy);
  - `unsupported` with a reason: no phone approver (`not_available`), no eligible page
    (`not_eligible`), or no human check detected (`no_human_check`).
- While a handoff is open every other tool fails with "a human check is in progress on
  your page; call browser_handoff to wait for it". The agent never sees the live view,
  your taps or what you type; afterwards it sees the page as usual, with anything you
  typed (4+ characters) shown as `[redacted]`.

The broker only opens a handoff when it detects a known human check on the page and you
asked for something in the last 10 minutes (your words are shown on the live view). It
is never opened on its own: the agent has to ask.

**Check before the sign-in (one approval).** When the check sits in front of a sign-in
page (huggingface.co's WAF does this), the agent does the same thing: `browser_handoff`,
then `auth_login` after `done`. If the broker could sign that agent in there right now (one
password or passkey for the site, policy `ask` or `allow-for`, not high-risk), your phone
shows one approval card, "Human check, then sign in to <site>?", instead of the human-check
notification; one Face ID covers both, and the agent's `auth_login` after `done` succeeds
with no further prompt. The agent sees nothing different (same tool, same statuses; it
can't ask for this mode: the broker decides from its own state). A second `auth_login`
later asks as usual. If you deny the card, `browser_handoff` returns `cancelled`; if you
don't answer within about 90 s, `expired`.

## What the hook does exactly

`keyflap hook claude-code --agent <id>` reads the hook JSON from stdin (capped at 1 MiB),
takes `prompt`, and POSTs it to `<data-dir>/run/intent.sock` with the host token, with a
3 s timeout. Then:

- It **never writes to stdout** (it disables stdout entirely): on exit 0, Claude Code
  adds a `UserPromptSubmit` hook's stdout to the model's context.
- It **always exits 0**, even on bad arguments or a crash. Exit 2 would block your
  prompt; a broker problem should cost you a denied login, not your prompt.
- Failures go to stderr as one short line (stderr isn't shown to the model), never
  containing the token or the prompt.
- A prompt longer than 8000 characters is **not recorded** rather than truncated: the
  approval prompt shows your words verbatim or not at all. Large pastes count toward
  this. Send a short request as its own prompt.

What gets forwarded:

- **Typed prompts**, verbatim, including pasted text (Claude Code expands paste
  placeholders before the hook sees them).
- **Slash commands**, verbatim (e.g. `/review-pr 123`). They're words you typed, and the
  approval prompt shows exactly that text; the command file's expansion is not sent.
  (Older hook inputs carried `prompt_type: "user_input" | "slash_command"`; both are
  forwarded, and any other declared type is skipped.)
- **Skipped:** hook events other than `UserPromptSubmit`, input carrying `agent_id`
  (fired inside a subagent), and prompts that start with `<task-notification>`.

### Known limit: not every UserPromptSubmit is you

Claude Code also fires `UserPromptSubmit` for turns it starts on its own: a scheduled task
or `/loop` iteration, a **background subagent reporting back**, and a **message from
another session** (cross-session messaging). The hook input has no documented field that
tells these apart from typed prompts. The last two carry text written by a model, which
a prompt-injected subagent or session could steer; recorded as an intent, it would be
shown in the approval prompt as "You said". The hook skips the one shape we know
(`<task-notification>` reports), but that format is undocumented.

Until Claude Code marks the source of a turn: **in sessions connected to the broker, don't
use background subagents, cross-session messaging or scheduled tasks**, and if a prompt's
"You said" text isn't something you typed, deny it.

## Limits of the terminal approver (dev mode)

- **No user verification.** The terminal approver can't verify who pressed `y`, so
  assertions carry UV=0. Sites that require user verification reject the login. That's
  deliberate: claiming UV we didn't perform would lie to the relying party. The
  [phone approver](phone-approver.md) (Face ID, fingerprint or device PIN) fixes this.
- **Same-machine approvals.** The approver key lives in the data dir; development only.
- One daemon per data dir; restart Claude Code's MCP connection (`/mcp`) if you restart
  the daemon.
- Revoking an agent while the daemon runs stops its token on the next request, but the
  daemon only closes that agent's browser context when it restarts (see
  [IMPLEMENTATION_NOTES.md](../IMPLEMENTATION_NOTES.md)). In service mode
  `sudo keyflap agent revoke` closes it at once.
