# Guided setup: `keyflap setup` and `keyflap doctor`

`keyflap setup` walks you from nothing to a working agent: a phone approver origin, a paired
phone, an agent with its Claude Code config written for you, a password or Proton Pass, and
a final health check. `keyflap doctor` is that health check on its own, any time.

## The one command

On a Mac with Apple silicon or on Linux, the real install and its setup are one command. It is
the same on keyflap.com and in [INSTALL_FOR_AGENTS.md](../INSTALL_FOR_AGENTS.md), the guide an
agent follows when the user asks it to install Keyflap:

```sh
curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | sudo bash
```

`install-keyflap.sh` is a release asset, listed in the release's `SHA256SUMS` and covered by
its attestation. It holds the SHA-256 of each of that release's tarballs. As root it picks the
tarball for this machine (Intel Macs are refused), downloads it into a new root-only directory
under `/opt/keyflap-release`, refuses it unopened if the hash differs, unpacks it, takes the
approver origin from Tailscale (`https://<machine>.<tailnet>.ts.net:8766`, asking only if it
can't), asks which password manager to use, runs that release's `install.sh`, then runs
`keyflap setup` on the terminal. On a terminal it asks its questions first, then shows one
progress bar from the download to the started services, and ends with a short summary; the
detail goes to the install log (macOS `/Library/Keyflap/log/install.log`, Linux
`/var/log/keyflap/install.log`, root-only). Piped or run by an agent, it prints plain lines. It reads every answer from `/dev/tty`, because its stdin is
the download. Re-running it upgrades with the same answers. It refuses to upgrade an install
it did not make, because it would rewrite that install's options. `bash install-keyflap.sh
--dry-run`, as any user, downloads, checks and unpacks into a temporary directory and prints
the install command without running it. Decisions: IMPLEMENTATION_NOTES, "Agent-led setup
and the one-command install".

## Running setup yourself

```sh
sudo keyflap setup                 # service mode (after install.sh): the real install
keyflap setup --unprotected        # dev mode: same-user broker from a checkout
keyflap doctor [--json] [--project DIR]
```

The service-mode paths on this page are the Linux ones; a Mac has them under `/Library/Keyflap` (for example the
hook dir `/Library/Keyflap/hook`), listed in [service-mode.md](service-mode.md#what-you-get).

Setup is interactive and needs a terminal; it refuses to run with piped input (use the
individual commands for scripts: `keyflap agent add`, `keyflap password add`,
`keyflap daemon --pair`, `keyflap doctor`). Every step can be skipped, nothing is changed or
run without showing it and asking first, and re-running it picks up what is already done
(choices are kept in `<data-dir>/setup.json`, or `/var/lib/keyflap/hook/setup.json` in
service mode; no secrets in there).

## On the screen

In a terminal, setup takes the whole window and shows one step at a time: a header with the
step and a progress bar that fills as steps are done, the essential sentence, and the question.
Choices are lists you move through with the arrow keys. `Tab` shows what a screen leaves out (the exact file changes as a
diff, paths, commands); the same detail goes to a setup log, `<data-dir>/setup.log` (service
mode: `/var/lib/keyflap/hook/setup.log`, on a Mac `/Library/Keyflap/hook/setup.log`), written
as you, 0600. The log never holds a secret: no password, token or TOTP seed, no pairing code
(it is cut from the link), and no password export listing. When setup ends, its last screen
stays in the terminal. Without a terminal, or with `TERM=dumb`, setup prints plain lines.

To try the screens without installing anything, from a checkout:

```sh
pnpm setup:preview [--scenario mac-fresh|linux-fresh|mac-rerun|mac-agents] [--platform darwin|linux]
pnpm setup:preview --capture /tmp/screens [--size 80x24]   # every screen as ANSI + HTML
```

The preview runs setup's own steps against the fake system and broker the setup tests use. It
needs no root and no network, changes nothing on the machine, and cannot reach a key store, an
admin socket, a vault, Tailscale or a Claude config.

## The steps

1. **Preflight.** Node version, Chromium, the mode (warns if service mode is installed but
   you ran the dev variant), the data dir (created 0700 if new), and whether the daemon is
   running. In service mode it checks that `keyflap-signer`, `keyflap-core` and
   `keyflap-approver` are active and whose Claude Code it configures: the install user (the
   owner of `/var/lib/keyflap/hook`), whoever ran `sudo`.
2. **Phone approver origin.** Dev mode: phone (recommended) or the terminal approver. For
   the phone it runs `tailscale status --json`; if the node is logged in with MagicDNS and
   HTTPS certificates, it shows
   `tailscale serve --bg --https=8766 http://127.0.0.1:8766` and runs it only if you answer
   `y` (default no), then uses `https://<machine>.<tailnet>.ts.net:8766`. Otherwise you type
   an origin, and optionally a certificate and key for the approver to serve itself (it
   then listens on `0.0.0.0:<port>`; without one, on loopback behind your proxy). Service
   mode: the origin was fixed by `install.sh`; setup shows it and checks that it answers
   over HTTPS with a valid certificate, and if a `.ts.net` origin doesn't, offers the same
   `tailscale serve` command. On a Mac the Tailscale CLI is the app's
   (`/Applications/Tailscale.app/Contents/MacOS/Tailscale`) when `tailscale` is not on `PATH`.
   As root, setup runs only a root-owned Tailscale CLI in a root-only directory (`/usr/bin`,
   `/usr/sbin`, `/usr/local/bin` or the app), never one found on your `PATH`. From then on
   Keyflap's signer watches that `tailscale serve` setting and refuses approvals while it
   points anywhere else ([phone-approver.md](phone-approver.md#the-approval-address-is-watched)).
3. **Pair your phone.** Shows the one-time link and its QR code and waits (up to 10 minutes)
   until the phone is paired. Dev mode needs the daemon stopped (the key store is in use
   while it runs; setup asks you to stop it): setup asks for the key-store passphrase
   (without echo, or `$KEYFLAP_PASSPHRASE`), starts a pairing-only approver on the chosen
   listener, and checks the origin answers from this machine. Service mode uses the same
   admin call as `sudo keyflap approver pair`, which first re-checks the approval address and
   clears an earlier trip when the setting is right again. A second phone needs the first
   one's approval, as always.
4. **Agents.** Sets up every agent app on the machine, one after another. Claude Code is
   always offered; Codex and Hermes Agent are offered too when `~/.codex` or `~/.hermes` exists.
   Each host gets its own screens, its own agent (default name `claude-code`, `codex`,
   `hermes`), its own preview of the files it writes, and its own `y`; say no to skip one.
   With one host the step is called "Agent and Claude Code" (or the host); with several, each
   host's screens are headed "Codex (2 of 2)" and so on. `keyflap setup --host codex` (or
   `claude-code`, `hermes`) sets up only that host.
   **Claude Code.** Creates the agent, stores its token in a 0600 file the model is denied
   (below), and offers to write the Claude Code config: one project or all your projects. The
   Claude desktop app's Code tab reads the same user config as the terminal, so all projects
   covers both; one project covers the desktop app only when you open that project there.
   It shows exactly which files and keys change, as a diff, and writes only after `y`; it
   backs up every file it modifies (`<file>.keyflap-backup-<UTC time>`) and merges into
   existing JSON without touching other settings. A file that isn't plain JSON (comments) is
   left alone, with a message.
   **Other hosts.** Run from your home directory, setup offers the all-projects Claude Code
   config first; from any other directory, that one project. Hermes: it asks for your chat
   id(s) and writes the `keyflap-intent` plugin and its `config.json` into
   `~/.hermes/plugins/` ([hermes.md](hermes.md)). Codex: it merges the hook into
   `~/.codex/hooks.json` ([codex.md](codex.md)). Same preview, backup and `y` as above. It
   never edits `config.yaml`, `.env` or `config.toml` (YAML/TOML with comments): it says what
   is left for you, and Tab shows what to merge, including the setting that keeps the model
   away from the host token, and a `$(cat <token file>)` command that puts the agent token
   where the host reads it. `keyflap doctor` (the Finish health check) fails until the Codex
   profile or the Hermes Docker backend is in place.
   **Re-running.** The hosts already set up are recorded in `setup.json`. On a re-run each
   host's agent name defaults to the agent it already uses, and "Use the existing agent"
   reuses it (nothing is created twice; files already up to date are not rewritten). A host
   cannot take the agent another host uses: Keyflap keeps one live intent per agent. Finish
   lists every host that was set up.
5. **Credentials.** A password (and TOTP) for one site, entered without echo (dev mode:
   daemon stopped); an export file (Apple Passwords, Chrome, Firefox, 1Password, Bitwarden
   CSV): setup reads it as you (the same symlink rules as below), shows each site, username
   and whether it has a TOTP, never a password, asks which sites your agents need (blank: all)
   and stores them only after `y`, then reminds you to delete the file; or Proton Pass: setup checks `pass-cli vault list`, offers to log it in
   with a personal access token that it reads without echo and passes in
   `PROTON_PASS_PERSONAL_ACCESS_TOKEN` (never on a command line; see
   [proton-pass.md](proton-pass.md)), and asks which vault. In service mode, setup and the
   console connect Proton Pass or 1Password on the spot (the same routine as `sudo keyflap
   password-source add`): it finds the root-only tool and pins it, checks the credential as
   the signer, asks which vault, and restarts the services. Every change defaults to no, and
   connecting one replaces the other after a question. In service mode the default is the password source the
   install configured, else the import when nothing is stored yet.
6. **Finish.** Dev mode: asks about `--headed`, prints the `keyflap daemon` command for your
   choices, and offers to start it right there (it keeps running in that terminal). Then
   `keyflap doctor`, and the test-RP walkthrough from the README.

## What gets written for Claude Code

| | One project | All projects |
|---|---|---|
| MCP server `keyflap` | `claude mcp add-json keyflap … -s local` if the `claude` CLI is on PATH (dev mode), else `<project>/.mcp.json` | `claude mcp add-json … -s user`, else `~/.claude.json` |
| Hook, sandbox, deny rules | `<project>/.claude/settings.local.json` | `~/.claude/settings.json` |

The MCP entry is `{"type": "http", "url": "http://127.0.0.1:8765/mcp", "headersHelper":
"<node> <repo>/packages/cli/src/main.ts mcp-headers --agent <id>"}` (service mode:
`/usr/local/bin/keyflap mcp-headers --agent <id> --service`). Claude Code runs the
`headersHelper` itself, outside the model's sandbox, when it connects; `keyflap mcp-headers`
prints `{"Authorization": "Bearer …"}` from the token file and nothing else, and exits 1
on any problem (no connection: fail closed). So the agent token is in no config file, no
environment variable and no output; it lives only in
`<data-dir>/agents/<id>.token` (dev) or `/var/lib/keyflap/hook/agent-<id>.token` (service
mode), both 0600 and inside the directory the deny rules cover.

The settings get the hook and the protections from
[claude-code.md](claude-code.md#security-requirements-read-this): the `UserPromptSubmit`
hook with absolute paths (never through `pnpm`), `sandbox.enabled`,
`failIfUnavailable: true`, `allowUnsandboxedCommands: false` (setup overrides other values
and says so), and `denyRead`/`denyWrite` plus `permissions.deny` `Read(...)`/`Edit(...)` for
the data dir (dev) or `/var/lib/keyflap/hook` (service mode). An earlier keyflap hook is
replaced in place, not duplicated.

In service mode setup runs as root but reads and writes the user's files as the user (it
switches to the install user's uid, gid and groups for each file operation), and never runs
the `claude` CLI (it would edit root's config). It refuses any symbolic link at those paths
(and in any directory the user owns on the way) instead of following it, in both modes: a
link someone planted there can't make it read or overwrite a file elsewhere. Backups are
new files holding the text you saw in the preview.

After writing, restart Claude Code in that project, check `/mcp` (the `keyflap` server is
connected; Claude Code may ask you to approve the project's MCP server or its
`headersHelper`) and `/sandbox` (active; on Linux it needs bubblewrap and socat).

## `keyflap doctor`

Non-interactive and read-only; exit 1 if any check fails, `--json` for a machine-readable
report. One line per check (`✓` ok, `!` warning, `✗` failure, `-` skipped) with a one-line
fix for each problem:

| Check | Dev mode | Service mode |
|---|---|---|
| mode, node | same-user dev mode, Node ≥ 22.23.4 (or 24.22.1+, 26.12.1+) | service mode |
| units | | `systemctl is-active` keyflap-signer, keyflap-core, keyflap-approver; on a Mac `launchctl print system/com.keyflap.{signer,core,approver}` |
| data-dir, sockets | data dir 0700; intent socket and host token yours, 0600 | intent socket (install user, 0600), admin sockets (root, 0600) |
| daemon, signer, mcp | intent socket answers (else the exact `keyflap daemon` command); signer socket; MCP answers 401 without a token | signer admin socket; MCP |
| approver-origin, phone | the origin answers over HTTPS with a valid certificate; a phone is paired | same (origin from `/etc/keyflap/approver.json`) |
| agents, claude-mcp, claude-hook, claude-deny | an agent; an MCP entry pointing at this broker; the hook for an active agent (not via a package manager); the deny rules, loudly if the data dir isn't denied | same, for `/var/lib/keyflap/hook` |
| hermes-plugin, hermes-backend, hermes-enabled | only if the keyflap-intent plugin is installed: its config names an active agent and owners; `terminal.backend` is a container backend (fails on `local`); `plugins.enabled` lists it | same |
| codex-hook, codex-deny | only if `~/.codex/hooks.json` has the keyflap hook: it names an active agent; `config.toml` has a permission profile denying the data dir | same, for `/var/lib/keyflap/hook` |
| chromium, headed | Chromium launches; a warning when headless (bot walls) | keyflap-core runs it; `--xvfb` or not (on a Mac headless is the design, not a warning) |
| audit, passwords | the audit hash chain verifies; a password or password source exists (warning) | same, over the admin socket |
| password-tool | | only with a password source: the signer would run `pass-cli` (root-only path, allowed place, pinned hash), with the exact fix otherwise |
| user-files | a config file it would read is a symbolic link (refused, never followed; replace the link with a file) | same |
| hook-code | the project contains the Keyflap checkout the hook runs from, or lies inside it (warning) | |

It reads the Claude Code settings of `--project DIR` (default: the current directory) and
your user settings. In service mode run it with `sudo` for the admin-socket checks; as
your own user those are skipped. It never reads the host token or an agent token (only
their metadata) and never prints a secret, a token, a challenge or a signature.
