# Codex CLI integration

OpenAI's [Codex CLI](https://github.com/openai/codex) as a Keyflap agent host
([ARCHITECTURE.md section 8](../ARCHITECTURE.md#8-intent-binding)). Checked against the Codex
source and docs as of 2026-10 (`codex-rs` on `main`). Same shape as Claude Code
([claude-code.md](claude-code.md)):

| Connection | Who uses it | Credential | What it can do |
|---|---|---|---|
| MCP over HTTP, `http://127.0.0.1:8765/mcp` | the model, through Codex's MCP client | the **agent token**, from `$KEYFLAP_AGENT_TOKEN` | the eight broker tools |
| intent socket | the `UserPromptSubmit` **hook** (Codex itself, outside the sandbox) running `keyflap hook codex` | the **host token** in the data dir | record what you typed as the live intent |

Everything depends on **the model not being able to read the host token**: in Codex that is
a permission profile that denies the data dir to sandboxed commands, plus an approval policy
that never lets the model run a command outside the sandbox
([Security requirements](#security-requirements-read-this)).

## Setup

**Quickest path:** `keyflap setup --unprotected --host codex` (or `sudo keyflap setup --host
codex` in service mode) creates the agent, stores its token in a 0600 file, merges the hook
into `~/.codex/hooks.json` after showing the diff (backup kept), and prints what it never
edits: the `config.toml` part (TOML) and the `export KEYFLAP_AGENT_TOKEN="$(cat <token file>)"`
line. `keyflap doctor` then checks the hook and that `config.toml` denies the data dir.

The manual steps:

### 1. Register the agent

```sh
keyflap agent add codex --host codex          # service mode: sudo keyflap agent add codex --host codex
```

It prints the agent token once and the config below with your agent id and paths filled in.

### 2. `~/.codex/config.toml`

```toml
default_permissions = "keyflap-protected"
approval_policy = { granular = { sandbox_approval = false, request_permissions = false, rules = true, skill_approval = true, mcp_elicitations = true } }

[permissions.keyflap-protected]
description = "Workspace editing; the Keyflap data dir is denied to commands"
extends = ":workspace"

[permissions.keyflap-protected.filesystem]
"/home/you/.keyflap" = "deny"      # service mode: "/var/lib/keyflap/hook" (Mac: "/Library/Keyflap/hook")

[mcp_servers.keyflap]
url = "http://127.0.0.1:8765/mcp"
bearer_token_env_var = "KEYFLAP_AGENT_TOKEN"
```

The two top-level keys must come before every `[table]` (a TOML rule). Permission profiles
replace the older `sandbox_mode` / `sandbox_workspace_write` settings: remove those if you have
them (the Codex docs say to configure one or the other, not both). Profiles are marked beta in the Codex docs.

Start Codex with the token in its environment (keep it out of committed files):

```sh
export KEYFLAP_AGENT_TOKEN=aab_agent_…
```

The agent token is the agent's own identity; the model can read it from its environment,
which is fine. **Never put the host token here.**

### 3. The hook: `~/.codex/hooks.json`

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/node /path/to/keyflap/packages/cli/src/main.ts hook codex --agent <agent id>",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

(Or the same as `[[hooks.UserPromptSubmit]]` / `[[hooks.UserPromptSubmit.hooks]]` tables in
`config.toml`; use one form per layer. Service mode: `/usr/local/bin/keyflap hook codex --agent
<id> --service`.) Absolute paths, so it doesn't depend on Codex's `PATH`. **Never run it
through `pnpm`/`npm run`**: they print a banner, and Codex adds a hook's plain stdout to the
model's context.

### 4. Trust the hook

Start Codex and run **`/hooks`**: Codex runs a new or changed non-managed hook only after you
review and trust its exact definition. Then `/mcp` shows the `keyflap` server connected. Hooks
are on by default (`features.hooks`).

## What the hook does exactly

Codex runs `UserPromptSubmit` hooks only for `TurnInput::UserInput`
(`codex-rs/core/src/hook_runtime.rs`, `inspect_pending_input`), through your shell
(`$SHELL -lc`, `codex-rs/hooks/src/engine/command_runner.rs`), outside the sandbox, with the
session cwd. The input (`codex-rs/hooks/schema/generated/user-prompt-submit.command.input.schema.json`)
is `hook_event_name`, `prompt`, `session_id`, `turn_id`, `cwd`, `model`, `permission_mode`,
`transcript_path`, plus `agent_id` / `agent_type` inside a spawned subagent.

`keyflap hook codex --agent <id>` (`packages/cli/src/hook-codex.ts`):

- records `prompt` verbatim when `hook_event_name` is `UserPromptSubmit` and there is no
  `agent_id` / `agent_type`;
- skips subagent turns (their prompt is written by the parent model), other events and empty
  prompts; malformed input records nothing;
- doesn't record prompts over 8000 characters (never truncated);
- **never writes to stdout** (plain stdout becomes developer context for the model) and
  **always exits 0** (exit 2 blocks your prompt); failures are one line on stderr, never the
  token or the prompt.

## Security requirements (read this)

The hook runs as your OS user, like the model's sandboxed commands. What separates them is
Codex's sandbox:

- **The permission profile's `"<data dir>" = "deny"`** blocks reads and writes under the
  data dir for every sandboxed command (bubblewrap/Landlock on Linux, Seatbelt on macOS),
  including scripts the model writes; the model reads files by running such commands.
  **Unverified:** whether a built-in tool that opens a local file itself (e.g. `view_image`)
  honours the profile; it only takes images, but treat it as a gap.
- **`sandbox_approval = false`** makes Codex reject a request to run a command outside the
  sandbox instead of asking you (`AskForApproval::Granular`, `codex-rs/core/src/safety.rs`).
  With `on-request`, one approved escalation (`cat ~/.keyflap/host-token`) defeats everything.
  `request_permissions = false` likewise refuses the model's requests for more filesystem
  access. If you prefer `approval_policy = "on-request"`, never approve an escalation or a
  permission request that touches the data dir.
- **Never** run a Keyflap-connected session with `--dangerously-bypass-approvals-and-sandbox`
  (`--yolo`), `--sandbox danger-full-access` or `default_permissions = ":danger-full-access"`.
- Codex's docs say profiles don't govern MCP servers, connectors, browser / computer-use
  surfaces or approved escalations. A **stdio MCP server** you configure runs as you outside
  the sandbox: don't give a Keyflap-connected Codex one that reads arbitrary local files.
- Don't let the model edit `~/.codex` (config, hooks). The `:workspace` profile only makes the
  workspace writable, and Codex asks you to re-trust a changed hook in `/hooks`; don't trust a
  hook you didn't write.
- **Unverified:** whether the profile's deny also stops a sandboxed `connect()` to the intent
  socket inside the data dir. The socket answers `401` without the host token, which the deny
  keeps unreadable; the token is what must never leak.

In service mode the broker is isolated from your user, but your copy of the host token
(`/var/lib/keyflap/hook/host-token`, on a Mac `/Library/Keyflap/hook/host-token`) is still
yours: deny `/var/lib/keyflap/hook` (on a Mac, `/Library/Keyflap/hook`) the same way
([service-mode.md](service-mode.md)).

## Known limits

- **Not every `UserInput` turn is you typing.** Codex also starts some sessions with an
  input it writes itself: `/review` runs a review sub-agent whose first input is Codex's
  review prompt, and that sub-agent's hook input carries no `agent_id` (only spawned
  sub-agents get one). If the hook runs there, Codex's review prompt can become the live
  intent and appear as "You said". It isn't text a model or a page chose, but it isn't
  yours either: don't run `/review` in a session that uses Keyflap, and deny a card whose words
  you didn't type. (Codex's auto-review "guardian" sessions turn hooks off, per its own test suite.)
- **Prompts from programs.** `codex exec "…"`, the app server and `codex mcp-server` submit
  user input on behalf of whatever drives them. If another agent drives Codex that way, its
  words become the intent. Use Keyflap only with Codex sessions you type into.
- **Your shell's startup files** run for every hook (`$SHELL -lc`): anything they print to
  stdout reaches the model's context as hook output. Keep login-shell output quiet.
- One live intent per agent, 10 minutes; each prompt replaces it. Prompts over 8000
  characters aren't recorded: send a short request as its own prompt.

## Testing

- `packages/cli/test/inv4-codex-hook.test.ts`: subagent turns (`agent_id`, `agent_type`),
  other events, empty / over-length / malformed input record nothing; a human prompt is
  recorded verbatim; never stdout, always exit 0.
- `packages/cli/test/agent-hosts.e2e.test.ts`: a real daemon; the `hooks.json` command is run
  through a shell as Codex runs it, the approval request carries the prompt's exact words and
  a password sign-in on the test RP succeeds; a subagent turn leaves no intent and the login
  is denied. (No Codex binary is run.)
