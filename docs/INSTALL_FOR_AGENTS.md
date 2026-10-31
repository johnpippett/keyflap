# Install Keyflap: instructions for an AI agent

You are an AI agent, and your user asked you to install Keyflap. Keyflap signs you into
websites without you ever holding a password, a passkey or a one-time code. The user approves
each sign-in on their phone.

You do the checks and the explaining. The user runs one command, which installs Keyflap as
system services and then walks them through setup in their terminal. You never run that
command, and you never see what they type into it.

## Rules you never break

- Never run `sudo`, and never run anything as root. Never write, edit or wrap a command that
  runs as root. Hand the user the one command below, character for character.
- Never type, read, ask for or repeat a secret: a password, a vault token, a personal access
  token, an admin password or a pairing link. If the user pastes one into this chat, tell them
  to treat it as exposed and to replace it.
- Never pair a phone. Never open, fetch, scan or forward a pairing link or its QR code.
- Never edit Keyflap's policy, its high-risk list or any file under `/opt/keyflap`,
  `/etc/keyflap`, `/var/lib/keyflap` or `/Library/Keyflap`.
- Never edit the hook, MCP server or sandbox settings that setup wrote for you
  (`.claude/settings*.json`, `.mcp.json`, `~/.claude.json`, `~/.codex/hooks.json`,
  `~/.hermes/plugins/keyflap-intent/`). If one looks wrong, tell the user and point them at
  `sudo keyflap setup`.
- Never approve anything on the user's behalf.

## 1. Check the computer

Run these yourself. They only read.

| Check | How | Supported |
|---|---|---|
| System and processor | `uname -sm` | `Darwin arm64` (a Mac with Apple silicon: M1 or later), `Linux x86_64`, `Linux aarch64` |
| Intel Mac | `uname -sm` prints `Darwin x86_64` and `sysctl -n hw.optional.arm64` prints nothing or `0` | Not supported yet. Stop and tell the user. |
| Linux service manager | `ps -p 1 -o comm=` prints `systemd`, and `systemctl --version` is 250 or newer | Required on Linux |
| Tailscale on this computer | Mac: `/Applications/Tailscale.app/Contents/MacOS/Tailscale status`, and `ls -l /Library/Tailscale/ipnport` shows a link. Linux: `tailscale status` | Installed, signed in, connected. On a Mac, the standalone app from tailscale.com/download: with the App Store app there is no `/Library/Tailscale/ipnport`, and Keyflap's background service can't check the approval address. |
| MagicDNS and HTTPS certificates | `tailscale status --json --peers=false` (Mac: the app path above) has `"BackendState": "Running"`, a `Self.DNSName` ending in `.ts.net.`, and that name (without the final dot) in `CertDomains` | Both turned on for the tailnet |
| Xvfb (Linux only) | `command -v Xvfb` | Recommended. Without it the browser runs headless and more sites show human checks. |

Node.js, pnpm and a copy of this repository are not needed. The install brings its own Node
and browser.

Ask the user two things you can't check:

- Is Tailscale installed on their phone and signed in to the same tailnet?
- Which password manager holds the logins you should use: 1Password, Proton Pass, Apple
  Passwords (or another manager they can export from), or none for now?

If Tailscale is missing or not connected, help the user install it and sign in on both
devices (tailscale.com/download). If MagicDNS or HTTPS certificates are off, tell them to turn
both on in the Tailscale admin console, on the DNS page. These are the only prerequisites for
the phone.

For 1Password, the user needs a service account token (1Password.com, Developer, Service
accounts) with read access to a vault for agents, and the `op` command-line tool installed from
1Password's own installer or package repository, so that it is in `/usr/local/bin` or
`/usr/bin` and owned by root. For Proton Pass, the user needs a personal access token and
Proton's `pass-cli` in the same kind of place. Keyflap refuses a tool in a user-owned folder
such as Homebrew's `/opt/homebrew/bin` or `~/.local/bin`, because anything running as the
user, including you, could replace it. You may help install the tool; the token stays with
the user.

## 2. Tell the user what happens

Say this in your own words, briefly:

- Keyflap installs as system services that run as their own users. That separation is what
  keeps the logins away from you, the agent.
- They will paste one command into a terminal window on this computer. It asks for the
  computer's admin password, because it installs system services.
- The command downloads Keyflap, checks the download against fingerprints built into the
  command's own script, installs it, then starts a guided setup in the same window.
- You can't do these steps for them, on purpose. You must never set up your own guardrails.

## 3. Hand over the one command

Give the user exactly this, unchanged. It is the same text that keyflap.com shows, so they
can compare it.

```sh
curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | sudo bash
```

Tell them to run it in a terminal window of their own (on a Mac, the Terminal app), not
through you. Then wait until they say it has finished.

### Only if the user says they can't use an admin password

Don't suggest this yourself, and don't offer it to get around an error from the command above.
Only if the user tells you they can't use an admin password on this computer, and it is a Mac,
offer the simple install. Tell them this sentence word for word first:

> The simple install protects less: an agent that can run commands as you can read Keyflap's files and change its code. The full install stops that.

If they still want it, give them this command, unchanged, to run themselves in Terminal:

```sh
curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | bash -s -- --simple
```

It shows the same notice and installs nothing unless they type `y`. Afterwards, run
`"$HOME/Library/Application Support/Keyflap/bin/keyflap" doctor` in step 5, without `sudo`, in place
of the `/usr/local/bin/keyflap` commands. Details:
[simple-mac-install.md](integrations/simple-mac-install.md).

## 4. What the user will be asked

Most answers are already filled in, so the user mostly presses Enter.

1. The admin password, by `sudo`.
2. The phone approver address, only if Tailscale did not provide one.
3. Which password manager to use. For 1Password, the service account token, which is not
   shown on screen. On Linux without Xvfb, whether to go on with a headless browser.
4. Guided setup (`keyflap setup`), six steps. Each change is shown before it is made.
   1. A preflight check of the services.
   2. The phone approver address. If Tailscale is not serving it yet, setup shows a
      `tailscale serve` command and runs it after the user types `y`.
   3. Pairing the phone. The user scans a QR code with the iPhone camera, opens the link in
      Safari, taps "Pair this phone", then Share, Add to Home Screen.
   4. The agent. Setup picks the agent host it found (Claude Code, Codex or Hermes), creates
      your agent identity and shows the config changes before writing them. The user types `y`
      to write them.
   5. Passwords. Proton Pass: log in with the personal access token, not shown on screen.
      Apple Passwords: export from the Passwords app (File, Export All Passwords), then drag the
      file into the terminal window and choose the sites. Setup then reminds them to delete
      the export file.
   6. A health check.

## 5. After the install

1. Run the health check as the user, without `sudo`:

   ```sh
   /usr/local/bin/keyflap doctor
   ```

   As the user it skips the checks that need root, and says so in a `not root` line. For
   those checks (phone paired, agents, audit log, passwords), ask the user to run
   `sudo keyflap doctor` and tell you the result. If your sandbox blocks the
   command, ask the user to run both.

2. Ask the user to restart you, so you load the new MCP server and hook. You can't do this from
   inside your own session.
   - Claude Code: quit, then start `claude` again in the project setup configured (or anywhere,
     if setup wrote the config for all projects). `/mcp` lists `keyflap` as connected, and
     `/sandbox` says the sandbox is active.
   - Codex: start it again, run `/hooks` and trust the keyflap hook, then `/mcp`.
   - Hermes Agent: restart the gateway.

3. Do a test sign-in. Ask the user which site to use, and ask them to type the request
   themselves, for example "Sign in to github.com". Keyflap only signs in after a message from
   the user in the last 10 minutes, and the phone shows that message. Then use the `keyflap`
   tools: `browser_open` the site's sign-in page, then `auth_login`. The user approves on the
   phone. If `auth_login` reports a human check, call `browser_handoff` and let the user solve
   it on the phone. Never try to solve a human check yourself.

4. If anything fails, run `/usr/local/bin/keyflap doctor` again and use the table below.

## Troubleshooting

Each row is a line `keyflap doctor` prints. You tell the user what to run; they run it.

| doctor says | What it means | What to do |
|---|---|---|
| `not root: the admin-socket checks are skipped` | You ran it as the user. Expected. | Ask the user to run `sudo keyflap doctor` for the rest. |
| `… not active` (units) | A Keyflap service is not running. | The user runs the status and log commands doctor prints after `fix:`. |
| `intent socket missing` or `… is <mode>/uid <n>` (sockets) | The service sockets are missing or have the wrong owner. | The user runs the command doctor prints, or the one install command again. |
| `no phone paired: every sign-in would be denied` | Pairing did not finish. | The user runs `sudo keyflap setup` and does the pairing step. |
| `no agents` | Setup did not create your agent identity. | The user runs `sudo keyflap setup` and does the agent step. |
| `MCP endpoint on 127.0.0.1:8765: …` | The broker's MCP server does not answer. | The user checks the core service log with the command doctor prints. |
| `… unreachable from this machine` (approver-origin) | The phone approver page does not answer at its address. | If it is a `.ts.net` address, the user runs the `tailscale serve --bg --https=8766 http://127.0.0.1:8766` command doctor prints (Mac: the Tailscale app path in place of `tailscale`). |
| `…: certificate not valid` | HTTPS certificates are off for the tailnet. | The user turns on HTTPS Certificates in the Tailscale admin console (DNS page). |
| `no Claude Code MCP server points at this broker (project … or user scope)` | Claude Code has no `keyflap` server for this folder. | You are in another project than the one setup configured. Ask the user to start you there, or to run setup again and pick "All your projects". |
| `no UserPromptSubmit hook forwards your prompts (every sign-in would be denied)` | The hook is missing, so Keyflap never sees the user's requests. | The user runs `sudo keyflap setup` and does the agent step. |
| `the keyflap hook names an agent that is revoked or unknown` | The config points at an old agent. | Same: the agent step of setup. |
| `!! THE MODEL CAN READ …` | The sandbox or deny rules that keep you away from Keyflap's files are missing. | Stop. Tell the user, and don't use Keyflap until they rerun the agent step of setup. |
| `could not parse … as JSON (comments?)` | A settings file has comments, so setup left it alone. | The user merges the settings by hand (`docs/integrations/claude-code.md`). Don't edit it yourself. |
| `not read: … is a symbolic link` (user-files) | A settings path is a link, which Keyflap refuses to follow. | The user replaces the link with a regular file. |
| `no passwords and no password source (passkeys only)` | Nothing to sign in with except passkeys. | The user runs `sudo keyflap setup` and adds a password manager or imports an export. |
| `the signer refuses to run …` (password-tool) | The password manager's command-line tool is in a place Keyflap does not trust, or it changed. | The user runs the command doctor prints after `fix:`. After updating the tool: `sudo keyflap password-source trust pass-cli` (or `op`). |
| `audit hash chain BROKEN at seq …` | The audit log was changed. | Stop and tell the user. |
| `headless browser: many sites' bot walls refuse headless Chromium` | Linux without Xvfb. | Optional: the user installs Xvfb and runs the one command again. |

If the install command itself stops with a message, it changed nothing on the computer
unless it says otherwise. Tell the user what the message asks for, help them fix it, and
have them run the same command again.
