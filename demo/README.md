# Keyflap demo container

**DEMO: test site only. Don't use it with real accounts.**

A throwaway container for trying Keyflap before you install anything. Inside it:

- the broker in dev mode (`keyflap daemon --unprotected`) with the **terminal approver**:
  every approval prompt appears in the terminal you started the container from, and you
  answer it there;
- the bundled test relying party (`packages/test-rp`): passkeys on
  `http://localhost:3000`, password + TOTP on `http://rp.localhost:3000`;
- headless Chromium (Playwright 1.64.1), driven by the broker;
- a pre-created agent, `demo-agent`, and one stored login: the test site's seeded user
  `alice` / `correct horse battery staple`, TOTP secret `JBSWY3DPEHPK3PXP` (public test
  values).

Your MCP client (for example Claude Code) runs on your host and connects to
`http://127.0.0.1:8765/mcp`.

## Three commands

You need podman or docker, and a clone of this repository.

```sh
demo/run.sh                                                    # terminal 1: build and run; approvals appear here
export KEYFLAP_AGENT_TOKEN=aab_agent_…                          # terminal 2: printed by terminal 1, new every run
podman exec -it keyflap-demo say "sign me in to the test site"  # terminal 3 (or 2): before each sign-in
```

`run.sh` uses podman, or docker if podman isn't installed (`ENGINE=docker demo/run.sh` to
choose). The first build pulls the Playwright image (about 2 GB). `demo/run.sh --no-build`
reuses the image. With docker, replace `podman exec` with `docker exec`.

The same thing by hand:

```sh
podman build -f demo/Containerfile --ignorefile demo/Containerfile.dockerignore -t keyflap-demo .
podman run --rm -it --init --name keyflap-demo -p 127.0.0.1:8765:8765 keyflap-demo
```

Then, in a new, empty directory on the host, write `.mcp.json` (terminal 1 prints it):

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

start `claude` there with `KEYFLAP_AGENT_TOKEN` exported, record your intent with `say`,
and ask:

> Go to http://rp.localhost:3000/password/login and sign in with my password.

Type `y` at the prompt in terminal 1. The agent gets `{"status": "success"}` and is signed
in as alice; it never sees the password or the code. For passkeys:

> Go to http://localhost:3000/signup, sign up as bob, and add a passkey.

then "log out and sign back in with the passkey". Each sign-in asks you again.

Keep host port 8765: the broker only accepts `Host: 127.0.0.1:8765` or `localhost:8765`.

## Telling the broker what you asked for (`say`)

Keyflap shows an approval prompt only while there is a live **intent**: your own words,
captured outside the agent's reach (invariant 4 in
[ARCHITECTURE.md](../docs/ARCHITECTURE.md#5-security-invariants)). The prompt shows those
words verbatim, so you can check that the sign-in matches what you asked for. Without one,
every sign-in is denied before you see anything.

In a normal install, a Claude Code hook forwards each message you type. In the demo the
broker is inside a container, so you say it yourself:

```sh
podman exec -it keyflap-demo say "sign me in to the test site"
podman exec -it keyflap-demo say        # asks for the words
```

An intent stays live for 10 minutes; the newest one counts.

`say` is the real hook (`keyflap hook claude-code`) with your words as its input: it posts to
the broker's intent socket with the host token, and both exist only inside the container.
The agent talks to the broker only through the MCP endpoint, and no MCP tool can record an
intent, so the agent can't put words in your mouth through Keyflap.

### Optional: forward your Claude Code prompts automatically

To get the real experience, where the prompt shows exactly what you typed into Claude Code,
add this to `.claude/settings.json` in the same scratch directory:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "podman exec -i keyflap-demo say --claude-code-hook" }] }
    ]
  }
}
```

Like the real hook, `say --claude-code-hook` never writes to stdout (Claude Code would feed
it to the model) and always exits 0.

## What it is not

- **Not for real accounts.** The browser can only reach the container's own loopback
  (`localhost` and `*.localhost`): every other site fails to load
  (`net::ERR_PROXY_CONNECTION_FAILED`, a dead proxy set in the image). The only credentials
  are the test fixtures above, bound to the test site's origins; a look-alike such as
  `http://evil.localhost:3000` gets `no_credential`.
- **Not a security boundary.** The demo shows the flow, not the isolation. An agent that can
  run commands as you can also run `podman exec` / `podman attach`: it could record an
  intent with `say` or type `y` into the approval terminal itself. Claude Code's sandbox and
  deny rules (see [claude-code.md](../docs/integrations/claude-code.md)) don't cover
  podman. Real protection is [service mode](../docs/integrations/service-mode.md) with phone
  approvals.
- **Not persistent.** No volumes. The key store, passkeys, audit log and browser state live in
  the container and are deleted when it stops (Ctrl-C in terminal 1). The key-store
  passphrase is a fixed, public demo value.
- **No phone approvals, no human-check handoff.** Terminal approvals can't verify you, so
  `ask-strong` and high-risk sites are always denied here.

## How it works

| File | What it does |
|---|---|
| `Containerfile` | Playwright 1.64.1 image (Chromium revision 1248), pinned by digest, plus checksum-pinned Node 22.23.4; `pnpm install --prod`; runs as `pwuser` |
| `entrypoint.sh` | starts the test RP, adds the demo login and agent, prints the token and `.mcp.json`, then runs the daemon in the foreground |
| `mcp-relay.ts` | relays the published port to the MCP endpoint, which stays bound to the container's loopback |
| `say.ts` | the `say` command: records your intent through the hook |
| `run.sh` | build and run with podman or docker |

The MCP server only ever binds to loopback, and it checks every request for a loopback
`Host`, no `Origin` and a valid agent token. A published port reaches the container on its
network interface, not its loopback (docker always; podman on a bridge network), so
`mcp-relay.ts` copies bytes between that interface's port 8765 and `127.0.0.1:8765`. It
doesn't touch the requests: the broker's checks apply exactly as for a local client. The
port is published on the host's loopback only (`-p 127.0.0.1:8765:8765`).

Other things you can do inside the container:

```sh
podman exec keyflap-demo keyflap audit tail       # every request and decision
podman exec keyflap-demo keyflap status
podman exec keyflap-demo cat test-rp.log
```
