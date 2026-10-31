# The simple Mac install

The full install ([service-mode.md](service-mode.md)) is the default, and the one to use.
The simple install runs Keyflap as you, with no admin password, so you can try it first.

**The simple install protects less: an agent that can run commands as you can read Keyflap's
files and change its code. The full install stops that.** Keyflap says this before it installs
anything, and again in `keyflap status`, `keyflap doctor` and at the end of setup.

It needs a Mac with Apple silicon and macOS 14 or later.

## Install

```sh
curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | bash -s -- --simple
```

Run it without `sudo` (it refuses `sudo`). It shows the notice above and asks first; the
answer is no unless you type `y`. Then it downloads the release, checks it against the
hashes pinned in the script, installs it, and runs the guided setup: the phone approver
origin, pairing your phone, your agent (it writes the Claude Code config after you say
yes), and your passwords. Its last step starts Keyflap in the background.

| What | Where |
|---|---|
| Code, Node, headless Chromium | `~/Library/Application Support/Keyflap` |
| The `keyflap` command | `~/Library/Application Support/Keyflap/bin/keyflap` |
| Key store, database, phones, agents | `~/.keyflap` |
| The key that unlocks the key store | `~/.keyflap/unlock.key` (yours, 0600) |
| The background job | `~/Library/LaunchAgents/com.keyflap.simple.plist` |
| Its log | `~/Library/Logs/Keyflap/daemon.log` |

The job starts when you log in and again if it crashes. No Terminal window needs to stay open.
macOS shows a "Background Items Added" notification for it.

## What it protects, and what it doesn't

The broker still keeps passwords and passkeys out of your agent's context, and every sign-in
still needs your approval on your phone. What it can't do is keep an agent that runs commands
as you away from its own files: that agent can read `~/.keyflap` (the key file opens the key
store), change the code in `~/Library/Application Support/Keyflap`, or read the broker's
memory. The Claude Code sandbox rules that setup writes stop the model's own file tools from
reading `~/.keyflap`; a command that runs outside the sandbox is not stopped.

Anyone with a copy of `~/.keyflap` (a backup, for example) can open the key store. Keep
FileVault on.

Not in the simple install: 1Password (its service account token would sit where an agent
could read it; use Proton Pass, an export, or the full install), and a visible browser window.

## Day to day

```sh
K="$HOME/Library/Application Support/Keyflap/bin/keyflap"
"$K" status
"$K" doctor
"$K"                # the console: manage passwords, phones, agents and rules in one screen
"$K" setup          # change anything; it stops and restarts the background job as needed
launchctl kickstart -k gui/$(id -u)/com.keyflap.simple     # restart it
```

## The console

`"$K"` with no command, in a terminal, opens the same full-screen console as `sudo keyflap` in
the full install (see [service-mode.md](service-mode.md#using-it)). It starts with a warning
screen, a big `!` and "This is the unprotected version of Keyflap.", and every screen after it
says `! UNPROTECTED` at the top, so you can't mistake it for the protected one.

It runs as you and reads `~/.keyflap` with the key file, so there is no password to type.
Adding, importing and removing passwords, pairing a phone, and listing or removing phones need
Keyflap's background job stopped (it holds the key store). The console asks first, with "no" as
the default, stops the job, does the work, and starts the job again when you go back to the
menu. Rules, saved sessions, agents and the status checks work while the job runs. Trusting an
updated password tool is not in this console: the simple install runs your own tool as you.

In dev mode (`keyflap daemon --unprotected`) the same console opens from `keyflap` when
`~/.keyflap` exists. It asks for the key-store passphrase once, in its own hidden input, the
first time something opens the key store. It can't stop a daemon running in another terminal:
it says which action needs that, waits for you to press Enter after stopping it, and prints the
command to start it again afterwards.

## Remove it

```sh
"$HOME/Library/Application Support/Keyflap/uninstall.sh"            # keeps ~/.keyflap
"$HOME/Library/Application Support/Keyflap/uninstall.sh" --purge    # deletes it too
```

Claude Code keeps the `keyflap` MCP server and hook that setup added: `claude mcp remove
keyflap`, and delete the hook from your Claude Code settings.

## Move to the full install

Run the uninstaller, then the full install:

```sh
curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | sudo bash
```

The full installer refuses while the simple install is there. Nothing moves across: the full
install starts a new key store, because keys an agent could have read should not be carried
into the install that promises they were never readable. Pair your phone again, add your logins
again, and add new passkeys for the sites you used.
