# Getting started

The technical setup guide: the one-command install, the same install by hand on Linux and on
a Mac, the simple Mac install, the demo container, dev mode for contributors and the
requirements. For an overview, see the [README](../README.md).

## Real install (service mode)

Service mode is the way Keyflap is meant to run. It runs the broker as separate system users,
so an agent that runs as you cannot read its keys, its memory or its browser. On a Mac with
Apple silicon or on Linux, one command installs it and runs the guided setup (phone, agent,
password manager).

Before you run it, set up [Tailscale](https://tailscale.com/download) on this computer and on
your phone, in the same tailnet, with MagicDNS and HTTPS certificates turned on (Tailscale admin
console, DNS page). On a Mac, use the standalone app from tailscale.com/download, not the App
Store app: Keyflap's background service can't read the App Store app's settings. Run the command
from your own account, the one your agents run as, not from a root shell:

```sh
curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | sudo bash
```

It checks the download against hashes pinned in its own script before it unpacks anything
([setup.md](integrations/setup.md#the-one-command)). To try the download first without
installing anything, save the script and run it with `--dry-run`:

```sh
curl -fsSLO https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh
bash install-keyflap.sh --dry-run
```

To have your agent check the machine and hand you the one command, paste this into your agent:

> Install Keyflap for me. Follow https://github.com/johnpippett/keyflap/blob/main/docs/INSTALL_FOR_AGENTS.md, then give me the one command to run myself.

The agent follows [INSTALL_FOR_AGENTS.md](INSTALL_FOR_AGENTS.md). It never runs the command
itself. The rest of this section is the same install by hand.

### By hand on Linux

You need Linux (x86_64 or aarch64) with systemd ≥ 250, root, Xvfb (the managed browser runs
headed on a private display; or `--headless`), and an HTTPS origin your phone can reach (for
example `tailscale serve`). Download `keyflap-<version>-linux-<arch>.tar.xz` and `SHA256SUMS`
from the [releases](https://github.com/johnpippett/keyflap/releases). The installer runs as
root, so check and extract the release where only root can change it (`install.sh` refuses to
run from your home or `/tmp`, where your uid, or an agent running as you, could edit it first):

```sh
V=<version>
sudo install -d -m 0755 /opt/keyflap-release
sudo install -m 0644 keyflap-$V-linux-x64.tar.xz SHA256SUMS /opt/keyflap-release/
cd /opt/keyflap-release
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify keyflap-$V-linux-x64.tar.xz --repo johnpippett/keyflap \
  --signer-workflow johnpippett/keyflap/.github/workflows/release.yml
sudo tar -xJf keyflap-$V-linux-x64.tar.xz
sudo ./keyflap-$V-linux-x64/install.sh --approver-origin https://HOST:8766
sudo keyflap setup     # pairs your phone, sets up each agent app it finds, adds passwords, runs keyflap doctor
```

On aarch64, use `linux-arm64` in place of `linux-x64`.

### By hand on a Mac

You need a Mac with Apple silicon and macOS 14 or later, an admin account, and an HTTPS origin
your phone can reach (for example `tailscale serve`). Intel Macs are not supported yet. The
browser runs headless: a macOS service has no display, so human checks go to the live view on
your phone. Download `keyflap-<version>-darwin-arm64.tar.xz` and `SHA256SUMS`, then check and
extract them where only root can change them, as on Linux:

```sh
V=<version>
sudo install -d -m 0755 /opt/keyflap-release
sudo install -m 0644 keyflap-$V-darwin-arm64.tar.xz SHA256SUMS /opt/keyflap-release/
cd /opt/keyflap-release
grep " keyflap-$V-darwin-arm64.tar.xz\$" SHA256SUMS | shasum -a 256 -c
gh attestation verify keyflap-$V-darwin-arm64.tar.xz --repo johnpippett/keyflap \
  --signer-workflow johnpippett/keyflap/.github/workflows/release.yml
sudo tar -xJf keyflap-$V-darwin-arm64.tar.xz
sudo ./keyflap-$V-darwin-arm64/install.sh --approver-origin https://HOST:8766
sudo keyflap setup
```

### After the install

`sudo keyflap setup` replaces the manual `sudo keyflap approver pair && sudo keyflap agent add`
([guide](integrations/setup.md)); `sudo keyflap doctor` checks the install any time.
`sudo keyflap`, with no command, opens the management console: phones, agents, passwords,
password managers, rules, saved sessions and health.
`sudo keyflap password-source add proton-pass|1password [--vault V]` connects a password
manager later, and `sudo keyflap password-source remove` disconnects it.

To upgrade, run the one command again: it keeps your answers. To remove Keyflap, run the
`uninstall.sh` command the installer printed at the end
(`sudo /opt/keyflap-release/keyflap-<version>-<os>-<arch>/uninstall.sh`).

The docs also cover the from-source path
(`build-bundle.sh` + `install.sh --bundle`, both copied somewhere root-only first). Details,
options, the differences between Linux and a Mac, and limits:
[docs/integrations/service-mode.md](integrations/service-mode.md).

## The simple Mac install (no admin password)

On a Mac where you can't use an admin password, the
[simple install](integrations/simple-mac-install.md) runs Keyflap as you:

```sh
curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | bash -s -- --simple
```

The simple install protects less: an agent that can run commands as you can read Keyflap's
files and change its code. The full install stops that. It is never the default. Use it to
try Keyflap, then move to the full install.

## Try it in a container

To see a sign-in before you install anything, run the demo container: the broker in dev
mode, the bundled test site and Chromium, with approvals in your terminal. You need podman
or docker.

```sh
demo/run.sh                                                    # prints the agent token and .mcp.json
podman exec -it keyflap-demo say "sign me in to the test site"  # in a second terminal: your intent
```

Point an MCP client such as Claude Code at `http://127.0.0.1:8765/mcp`, ask it to sign in
at `http://rp.localhost:3000/password/login`, and type `y` at the prompt. **Test site only:**
the container's browser can't reach real sites, and the demo is not a security boundary.
Details: [demo/README.md](../demo/README.md).

## Dev mode (for contributors)

Run Keyflap from a clone against the bundled test site, to work on it or to try it. **Dev mode does not isolate the agent:** the
broker runs as your own OS user, so an agent with shell access can read its files. It
relies on Claude Code's sandbox settings (printed by `keyflap agent add`; see the
[security section](integrations/claude-code.md#security-requirements-read-this)).
Use it to try Keyflap, not to protect real accounts.

```sh
git clone https://github.com/johnpippett/keyflap && cd keyflap
pnpm install
pnpm --filter @aab/shim exec playwright install chromium
ln -s "$PWD/packages/cli/src/main.ts" ~/.local/bin/keyflap   # or run: pnpm keyflap <command>
```

**Quickest path: `keyflap setup --unprotected`.** It asks for an approver (phone via Tailscale,
or this terminal), pairs your phone, creates an agent and writes the config for Claude Code and
any other agent app it finds (after showing you the diff), offers a password, a password manager
or an import, starts the daemon and runs `keyflap doctor` ([guide](integrations/setup.md)). The
manual steps below do the same by hand.

Terminal 1, the test relying party on `http://localhost:3000`:

```sh
pnpm test-rp
```

Terminal 2, the broker (signer, managed browser and MCP on `127.0.0.1:8765`):

```sh
keyflap daemon --unprotected --headed
```

It asks for a key-store passphrase (twice on first run). Keep it open: in dev mode,
approval prompts appear in this terminal.

Terminal 3, register Claude Code as an agent:

```sh
keyflap agent add claude-code
```

This prints the agent token once, plus a `.mcp.json` and a `.claude/settings.json`
snippet (the intent hook and the sandbox rules). Put both in a project directory, then
start Claude Code there with `export KEYFLAP_AGENT_TOKEN=aab_agent_…`. On Linux the sandbox needs
bubblewrap and socat; check with `/sandbox`. Then ask:

> Go to http://localhost:3000, sign up as bob, and add a passkey.

Approve in terminal 2, then ask the agent to sign out and sign back in with the passkey.

To try a password + TOTP sign-in, store the test RP's seeded login. Passwords are bound
to a registrable domain and bare `localhost` has none, so use the same server as
`rp.localhost` (Chromium resolves it to loopback). Stop the daemon first (Ctrl-C in
terminal 2), then:

```sh
keyflap password add rp.localhost --username alice --totp
# password: correct horse battery staple   TOTP secret: JBSWY3DPEHPK3PXP
keyflap daemon --unprotected --headed
```

> Go to http://rp.localhost:3000/password/login and sign in with my password.

Full walkthrough: [docs/integrations/claude-code.md](integrations/claude-code.md).

Without an agent, the dev runner opens one page with the intent given on the command line:

```sh
KEYFLAP_DEV_PASSPHRASE=dev pnpm --filter @aab/core dev \
  --url http://localhost:3000/signup --intent "make me an account on the test RP and add a passkey"
```

Other commands you'll want:

```sh
keyflap password add <site> [--username U] [--totp] # daemon stopped; secrets via no-echo prompt
keyflap password import Passwords.csv               # what an Apple / Google / Chrome export holds
keyflap password import Passwords.csv --expect <fingerprint> --site github.com   # store just that one (or --all); daemon stopped
keyflap policy set example.com --deny
keyflap policy set https://app.example.com --allow-for 30m --session-ttl 8h
keyflap sessions list
keyflap status                                      # agents, credentials, policies, audit check
keyflap --help
```

## Requirements

- Service mode: Linux (x86_64 or aarch64) with systemd ≥ 250, or a Mac with Apple silicon and
  macOS 14 or later (tested on macOS 26). Intel Macs are not supported yet. The install brings
  its own Node and Chromium.
- For phone approval: a phone browser with passkey support (iOS 16+ Safari, Android
  Chrome) and an HTTPS origin with a real hostname. Notifications on an iPhone need iOS 16.4
  or later and the page added to the Home Screen.
- Dev mode, from a clone: Node.js 22.23.4 or newer on 22.x (24.x: 24.22.1+, 26.x: 26.12.1+;
  older releases have CVE-2026-111497), pnpm 10, and Chromium through Playwright (installed by
  the commands above). TypeScript runs directly through Node's type stripping, no build step.
  Dev mode runs on Linux and on a Mac with Apple silicon (tested on a real Mac on 2026-10-29;
  CI workflow `.github/workflows/macos.yml`).
