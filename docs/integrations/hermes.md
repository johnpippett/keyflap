# Hermes Agent integration

[Hermes Agent](https://github.com/NousResearch/hermes-agent) (Nous Research) as a Keyflap agent
host ([ARCHITECTURE.md section 8](../ARCHITECTURE.md#8-intent-binding)). Verified against
Hermes 0.22.2 (commit `d923a5e`, 2026-10). It gets two connections to the broker, as Claude
Code does ([claude-code.md](claude-code.md)):

| Connection | Who uses it | Credential | What it can do |
|---|---|---|---|
| MCP over HTTP, `http://127.0.0.1:8765/mcp` | the model, through Hermes's MCP client | the **agent token**, from `~/.hermes/.env` | the eight broker tools |
| intent socket | the **keyflap-intent plugin** (Hermes's gateway process, not the model) running `keyflap hook hermes` | the **host token** in the data dir | record what *you* sent as the live intent |

The plugin records **only your own direct messages to the Hermes gateway** (Telegram,
Discord, Slack, Signal, WhatsApp, Matrix, Mattermost, BlueBubbles), verbatim. Nothing else
Hermes sees becomes an intent. The whole scheme depends on one thing: **the model must not
be able to read the host token**, and with Hermes that means the Docker terminal backend
([Security requirements](#security-requirements-read-this)).

## Setup

**Quickest path:** `keyflap setup --unprotected --host hermes` (dev mode) or
`sudo keyflap setup --host hermes` (service mode). It creates the agent, asks for your chat
id(s), shows the plugin files as a diff and writes them after `y` (with a backup of anything
it changes), and prints the two things it never edits: the `.env` line (a command that reads
the agent token from its 0600 file, so the token is never printed) and the `config.yaml`
part. `keyflap doctor` then checks the plugin, `plugins.enabled` and the terminal backend.

The manual steps:

### 1. Register the agent

```sh
keyflap agent add hermes --host hermes --owner telegram:123456789   # service mode: sudo keyflap agent add …
```

It prints the agent token once and everything below with your agent id and paths filled
in. `--owner` takes `platform:user_id` and can repeat; it is the sender id Hermes reports for
you (the same id you put in the platform's allowlist, e.g. `TELEGRAM_ALLOWED_USERS`). Matrix
ids contain colons; that is fine (`matrix:@you:example.org`). Owner platforms are only chat
platforms whose sender ids come from the platform's own authentication: `webhook`,
`api_server`, `msgraph_webhook`, `relay`, `email`, `sms` and the CLI are refused.

**One Keyflap agent per Hermes profile.** Keyflap keeps one live intent per agent, so a second
Hermes profile (or a second machine) gets its own `keyflap agent add` and its own plugin
config. For a multiplexed profile, set `"profile": "<name>"` in the plugin's `config.json`
(it passes `--profile`); without it only messages routed to the default profile count.

### 2. `~/.hermes/.env` and `~/.hermes/config.yaml`

```sh
KEYFLAP_AGENT_TOKEN=aab_agent_…        # ~/.hermes/.env
```

```yaml
mcp_servers:
  keyflap:
    url: "http://127.0.0.1:8765/mcp"
    headers:
      Authorization: "Bearer ${KEYFLAP_AGENT_TOKEN}"
plugins:
  enabled:
    - keyflap-intent
terminal:
  backend: docker               # REQUIRED
  docker_forward_env: []
  docker_volumes: []            # never mount your home, the Keyflap data dir or ~/.hermes
  docker_mount_cwd_to_workspace: false
gateway:
  strict: true                  # attachments only from the Hermes cache / allowlisted dirs
```

Hermes expands `${KEYFLAP_AGENT_TOKEN}` from `.env` when it loads `config.yaml`
(`hermes_cli/config.py`, `_expand_env_vars`) and sends `headers` on every MCP request
(`tools/mcp_tool_transport.py`). The agent token is the agent's own identity; it is fine for
the model to know it. **Never put the host token anywhere in Hermes's config.**

### 3. The plugin

```sh
mkdir -p ~/.hermes/plugins
cp -r <keyflap checkout>/packages/cli/src/integrations/hermes/keyflap-intent ~/.hermes/plugins/keyflap-intent
# service mode: /opt/keyflap/app/packages/cli/src/integrations/hermes/keyflap-intent
cat > ~/.hermes/plugins/keyflap-intent/config.json <<'EOF'
{ "command": ["/usr/bin/node", "/path/to/keyflap/packages/cli/src/main.ts"],
  "agent": "<agent id>", "owners": ["telegram:123456789"],
  "profile": null, "dataDir": null, "service": false }
EOF
hermes gateway restart
```

(`keyflap agent add` prints these with the right paths; service mode uses
`"command": ["/usr/local/bin/keyflap"], "service": true`.) `hermes plugins list` should show
`keyflap-intent` enabled. Hermes loads a user plugin only if it is listed in
`plugins.enabled`. Send your bot a DM, then `keyflap audit tail` shows `intent.recorded`.

## What the plugin does exactly

`keyflap-intent` is ~90 lines of standard-library Python. It registers one hook,
`post_gateway_admission`, which Hermes's gateway fires once per admitted message that is not
an internal event, after authorization, pairing and slash-command dispatch
(`gateway/run_inbound.py`, `gateway/run_inbound_consumer.py`). On each call it runs
`keyflap hook hermes --agent <id> --owner … ` with the hook's arguments (`platform`,
`session_key`, `message_id`, `text`, `source`) as JSON on stdin, stdout and stderr to
`/dev/null`, killed after 5 s. It never reads the text, logs nothing about the message,
swallows every error and **always returns `None`**, so Hermes handles the message exactly as
without it (returning `{"action": "handled"}` would consume it). It runs as an `async`
callback, so a slow broker never stalls the gateway's event loop. A missing or invalid
`config.json` registers nothing (one warning without message content): no intents, so
logins are denied.

All decisions are made in `keyflap hook hermes` (TypeScript, tested in
`packages/cli/test/inv4-hermes-hook.test.ts`). A message is recorded only if **all** hold:

- the platform is one of the chat platforms above, and `source.platform` agrees;
- `(platform, source.user_id)` is one of your `--owner`s;
- `source.chat_type` is `dm` (groups, channels and threads with other people never count);
- `source.is_bot` is false if present (Hermes 0.22's `SessionSource.to_dict()` leaves it
  out; the owner allowlist is what keeps bots out);
- `source.profile` matches `--profile` (absent for the default profile);
- `message_id` is set: real inbound messages carry the platform's id, while Hermes's
  synthetic non-internal turns are built without one (`/retry` re-sends, `/goal`, heartbeat
  and loop prompts, Discord voice-channel transcripts, a leftover `/steer`);
- the text isn't Hermes's fixed goal kick-off line (`[Goal set] Continue with the goal …`);
- the text is non-empty and at most 8000 characters. Longer messages are **not recorded**
  rather than truncated: the approval card shows your words verbatim or not at all.

The text is recorded exactly as Hermes received it (invariant 5): nothing trimmed or added.
Hermes adds its reply-quote prefix (`[Replying to: "…"]`) and voice-note wrappers *after*
this hook, so they never reach the intent. Like `keyflap hook claude-code`, the command never
writes to stdout, always exits 0, and puts one short line on stderr on failure (never the
token or the text; the plugin discards it).

## Security requirements (read this)

### The Docker terminal backend is mandatory

Hermes runs as your OS user, and the plugin's `keyflap hook hermes` reads the host token as
you. With Hermes's default `terminal.backend: local`, the model's terminal tool **and** its
file tools (`read_file`, `write_file`, `patch`, which Hermes implements on top of the
terminal backend) also run as you on the host, so a prompt-injected model can read
`~/.keyflap/host-token` and record its own "intent"; the approval card would then show words
you never sent. Hermes's own `SECURITY.md` (section 2.2) says the only boundary against an
adversarial model is the operating system and that its command denylists and approval gates
are heuristics, not containment.

With `terminal.backend: docker`, shell commands, the file tools and `execute_code` run inside
a container that sees only what is mounted into it. Keep it that way:

- `docker_volumes: []` and `docker_mount_cwd_to_workspace: false`, or at least never mount
  your home directory, the Keyflap data dir (`~/.keyflap`, or `/var/lib/keyflap/hook` in service
  mode) or `~/.hermes` (the plugin and its config are code Hermes runs on the host).
- `docker_forward_env: []` (nothing from your environment).
- `keyflap doctor` fails the `hermes-backend` check while the backend is `local` (or unset).

Other backends that run commands off the host (`singularity`, `modal`, `daytona`,
`vercel_sandbox`) also keep the token out of reach; `ssh` does only if the remote host has
no access to it.

### What still defeats it

What the Docker backend does **not** confine (Hermes `SECURITY.md` 2.2): everything Hermes
does in its own process on the host.

- **Stdio MCP servers** you configure are spawned on the host as you. A filesystem-style MCP
  server the model can drive can read the host token. Don't give a Keyflap-connected Hermes
  an MCP server that reads arbitrary local files.
- **Plugins and skills** run in Hermes's process: only install ones you have reviewed, and
  don't let the model edit `~/.hermes` (with the Docker backend it can't, unless you mount it).
- **Plugins that rewrite messages** (`pre_gateway_dispatch` with `{"action": "rewrite"}`)
  change the text before this plugin sees it; their text would become the intent. Don't
  combine such plugins with Keyflap.
- **Attachments**: without `gateway.strict: true`, the model can make the gateway send any
  host file it names as an attachment to the chat. That doesn't give the model the content,
  but keep `strict` on.
- `whole-process` wrapping (Hermes's own Docker image) puts the plugin, and so the hook and
  the host token, in the same container as the model: **don't run a Keyflap-connected Hermes
  that way**; use the terminal backend instead.

In service mode the broker itself is isolated from your user; the hook's copy of the host
token (`/var/lib/keyflap/hook/host-token`) is still yours, so the Docker backend requirement
is the same ([service-mode.md](service-mode.md)).

## Known limits

- **Only gateway direct messages.** `hermes chat` (the CLI and TUI) never records an intent.
  Its turns don't go through the gateway, and the one hook that sees them, `pre_llm_call`,
  also fires for turns Hermes makes up itself (background-process completions, delegation
  results, `/goal` wake-ups). The CLI turns those into plain strings before the hook runs
  (`hermes_cli/cli_chat_turn_mixin.py` converts its `TimelineNotification` with `str()`), and
  it inlines `@file` references into the message, so a hook can't tell typed text apart.
  Rather than guess, Keyflap records nothing there: a login from a CLI session is denied.
- **Messages sent while Hermes is busy aren't recorded.** Hermes routes them to the running
  turn's steering lane or its queue and runs them without going through the admission hook.
  Send your request again when Hermes is idle.
- **One live intent per agent.** Each new DM from you replaces it (10 minutes). Two chats
  driving one Keyflap agent share it.
- **A rescued message is recorded late.** When Hermes finds a message it had queued and lost
  (its FIFO rescue), it runs it as the next turn and the hook sees that older message: still
  your words, but possibly not your latest.
- **`/goal` headlines.** When you set a goal, Hermes queues a turn whose text is the goal's
  headline (part of your `/goal` command, so your own words) with the command's message id;
  if that turn reaches the hook, the headline is recorded. Its fixed "already seen" variant
  is not.
- As with every host: the card proves you asked for *something* recently, not that this
  sign-in serves it. Read it, and deny a card whose words you didn't send.

## Testing

- `packages/cli/test/inv4-hermes-hook.test.ts`: the filters against fake payloads (webhook,
  `api_server`, `msgraph_webhook`, cron, subagent, group chat, bot, other sender, synthetic
  turns, over-length, malformed), verbatim recording, no stdout / exit 0; runs the plugin's
  Python unit tests (`packages/cli/test/hermes-plugin/`) when `python3` exists. Opt-in, it
  loads the plugin through a real Hermes checkout's plugin loader and fires the hook through
  Hermes's own `run_post_admission_hook` with a real `SessionSource` (no gateway, no model, a
  temp `HERMES_HOME`, no bytecode written):
  `KEYFLAP_TEST_HERMES_SRC=~/.hermes/hermes-agent KEYFLAP_TEST_HERMES_PYTHON=<its python3> KEYFLAP_TEST_HERMES_SITE=<its venv site-packages>`.
- `packages/cli/test/agent-hosts.e2e.test.ts`: a real daemon; the plugin delivers an owner DM,
  the approval request carries those words and a password sign-in on the test RP succeeds; a
  group message leaves no intent and the login is denied.
