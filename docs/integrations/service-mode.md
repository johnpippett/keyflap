# Service mode (Linux and macOS)

Run the broker as its own system users, so an agent with shell access as you can't read
its keys, its memory or its browser, and can't edit its code. This is the mode the broker
is meant to run in; `keyflap daemon --unprotected` is for development only. Design and
decisions: [ISOLATION_PLAN.md](../ISOLATION_PLAN.md).

It runs on Linux with systemd and on a Mac with launchd. A Mac needs Apple silicon and macOS 14
or later; Intel Macs are not supported yet. The design is the same on both: three service
users, the same sockets, the same admin commands. This page gives the Mac value next to the
Linux one wherever they differ, and [On a Mac](#on-a-mac) lists every difference. The quickest
install on either system is the one command in [setup.md](setup.md#the-one-command).

## What you get

| | Who (Linux, macOS) | Linux | macOS |
|---|---|---|---|
| Code and runtime (Node 22.23.4, Chromium 1248) | root, read-only to everyone | `/opt/keyflap` | `/opt/keyflap` |
| `keyflap` command | root | `/usr/local/bin/keyflap` | `/usr/local/bin/keyflap` |
| Core: MCP, intents, audit, managed Chromium, phone approver API | `keyflap-core`, `_keyflap-core` | `/var/lib/keyflap/core` (0700) | `/Library/Keyflap/data/core` (0700) |
| Approver front: serves the phone's approver page, forwards its API to the core | `keyflap-web`, `_keyflap-web` | no state | `/Library/Keyflap/data/approver` (0700; home and tmp only) |
| Signer: key store, approval checks, password-manager CLI | `keyflap-signer`, `_keyflap-signer` | `/var/lib/keyflap/signer` (0700) | `/Library/Keyflap/data/signer` (0700) |
| Configuration (no secrets) | root, 0644 | `/etc/keyflap/{core,signer,approver}.json` | `/Library/Keyflap/etc/{core,signer,approver}.json` |
| Secrets | Linux: root, 0700, sealed with `systemd-creds` (TPM2 if present). macOS: each service's own dir, 0500, files 0400 | `/etc/keyflap/credentials/*.cred` | `/Library/Keyflap/credentials/<service>/` |
| Your hook's copy of the host token | you, 0600 | `/var/lib/keyflap/hook/host-token` | `/Library/Keyflap/hook/host-token` |
| Services | root | systemd units `keyflap-{signer,core,approver}` | LaunchDaemons `/Library/LaunchDaemons/com.keyflap.{signer,core,approver}.plist` |
| Logs | root | the journal | `/Library/Keyflap/log/<service>/<service>.log` |

On a Mac the service users are hidden (uid below 500, shell `/usr/bin/false`, no password), and
each also answers to its name without the `_` (`id keyflap-core` works).

The service manager creates every socket with its final owner and mode before any broker code
runs. On Linux that is systemd socket activation. On a Mac launchd creates them from the plists'
`Sockets`, and `keyflap-launch`, a small root-owned program, hands them to Node the way systemd
does.

| Socket (Linux) | Socket (macOS) | Who can connect | For |
|---|---|---|---|
| `/run/keyflap/intent.sock` | `/Library/Keyflap/run/core/intent.sock` | you (owner, 0600) | your Claude Code hook |
| `/run/keyflap/admin.sock` | `/Library/Keyflap/run/core/admin.sock` | root (0600) | `sudo keyflap agent/password/approver pair/status` |
| `/run/keyflap-signer/signer.sock` | `/Library/Keyflap/run/signer/signer.sock` | the core user (group, 0660; dir `root:keyflap-core` or `root:_keyflap-core`, 0750) | the core, plus the HMAC channel key |
| `/run/keyflap-signer/admin.sock` | `/Library/Keyflap/run/signer/admin.sock` | root (0600) | `sudo keyflap approver list/remove` |
| `/run/keyflap-approver/api.sock` | `/Library/Keyflap/run/approver/api.sock` | the web user (group, 0660; dir `root:keyflap-web` or `root:_keyflap-web`, 0750) | the approver front, forwarding the phone's API calls to the core |
| `127.0.0.1:8765` (TCP) | same | anyone with an agent token | the agent's MCP endpoint |
| `127.0.0.1:8766` (TCP) | same, plus `[::1]:8766` | your phone, through your TLS proxy | the approver page (systemd or launchd holds the port) |

On a Mac launchd also holds `[::1]:8766` when the listener is the default `127.0.0.1`, so no other
uid can take the IPv6 twin and answer whoever dials `localhost`.

The approver page comes from its own service, never from the core: the code your phone
runs is the root-owned copy in `/opt/keyflap`, and the core can't bind the approver's port or
put a script on its origin. The page also checks every request against the card it shows
before Face ID, and computes what it signs itself (design:
[APPROVER_INTEGRITY_PLAN.md](../APPROVER_INTEGRITY_PLAN.md)). So
even a compromised core (say, a browser exploit) can't show you one site and get your
approval for another. Nothing changes for you: same port, same `tailscale serve` line.

The key store unlocks itself at boot. There is no passphrase to type, and so no prompt for an
agent to fake. On Linux its key-encryption key (KEK) is a systemd credential only
`keyflap-signer` can read, sealed to this machine. Disk theft is covered by the TPM, or by your
disk encryption on machines without one. On a Mac the KEK is a 0400 file in
`/Library/Keyflap/credentials/signer/` that only `_keyflap-signer` can read. It is not sealed to
the machine, so FileVault is what covers disk theft. Keep FileVault on: the installer reports
when it is off, and does not refuse.

Service mode only runs with a phone approver; there is no terminal approver and no
approval key on the machine. Set up the approver origin first: see
[phone-approver.md](phone-approver.md) (`tailscale serve` is the easy path).

## Install from a release

The one command in [setup.md](setup.md#the-one-command) does all of this section and then runs
setup. These are the same steps by hand.

### On Linux

You need Linux on x86_64 or aarch64 with systemd ≥ 250 (`systemd-creds`), `xz`, and Xvfb
(below; or install with `--headless`). The installer checks all of this first and changes
nothing if something is missing. It downloads one thing: Playwright's Chromium 1248 for
your architecture (Node 22.23.4 is in the tarball).

Set up the phone approver origin first (example: Tailscale; see
[phone-approver.md](phone-approver.md)):

```sh
tailscale serve --bg --https=8766 http://127.0.0.1:8766
```

Download `keyflap-<version>-linux-x64.tar.xz` (or `-linux-arm64`) and `SHA256SUMS` from the
[GitHub releases](https://github.com/johnpippett/keyflap/releases). The installer runs as
root on what you extract, so copy the download somewhere only root can change before you
check it, and install from there. `install.sh` checks this itself: it refuses to run from a
directory (or take a `--bundle`, `--node-*`, `--browsers-dir`, TLS or APNs input from a path)
that anyone but root could change, such as your home or `/tmp`, because your uid, and so any
agent running as you, could edit it before root runs it.

```sh
V=0.1.0 ARCH=x64                     # the release you downloaded; arm64 on aarch64
sudo install -d -m 0755 /opt/keyflap-release
sudo install -m 0644 ~/Downloads/keyflap-$V-linux-$ARCH.tar.xz ~/Downloads/SHA256SUMS /opt/keyflap-release/
cd /opt/keyflap-release

# 1. Integrity: the file matches the published checksum.
sha256sum -c SHA256SUMS --ignore-missing
# 2. Authenticity: GitHub Actions built it from this repository's release workflow
#    (a Sigstore-signed SLSA provenance attestation; needs the GitHub CLI, `gh auth login`).
gh attestation verify keyflap-$V-linux-$ARCH.tar.xz --repo johnpippett/keyflap \
  --signer-workflow johnpippett/keyflap/.github/workflows/release.yml

# 3. Extract (as root, so the files stay root-owned) and install.
sudo tar -xJf keyflap-$V-linux-$ARCH.tar.xz
sudo ./keyflap-$V-linux-$ARCH/install.sh --approver-origin https://broker.tail1234.ts.net:8766

# 4. Pair your phone and add an agent.
sudo keyflap setup
```

`sudo keyflap setup` walks you through pairing and adding an agent. The same by hand:

```sh
sudo keyflap approver pair            # one-time link: open it on your phone
sudo keyflap agent add "Claude Code"  # token (shown once) + Claude Code config
sudo keyflap status
```

`sha256sum -c` alone only proves the download wasn't damaged: whoever could change the file
could change `SHA256SUMS` too. The attestation is the check that matters. It says which
repository, workflow, tag and commit produced exactly this file, signed with a short-lived
Sigstore certificate issued to that workflow run, and logged in Sigstore's public
transparency log. `gh attestation verify` exits non-zero if any of that doesn't match.
To check on a machine without network access, save the attestation first with
`gh attestation download keyflap-$V-linux-$ARCH.tar.xz --repo johnpippett/keyflap` and pass
it to `gh attestation verify --bundle FILE`; it is a standard Sigstore bundle, so other
Sigstore clients can check it too.

The one command pipes `install-keyflap.sh` into `sudo bash`. That script checks each tarball
against hashes pinned inside it, but the script itself is only as trustworthy as the download
that your shell made. For the stronger check, download `install-keyflap.sh` first, run
`gh attestation verify install-keyflap.sh --repo johnpippett/keyflap`, then run
`sudo bash install-keyflap.sh`.

What's in a release tarball (`keyflap-<version>-linux-<arch>/`):

| Path | What |
|---|---|
| `install.sh`, `uninstall.sh` | the installer and uninstaller (the same files as `packages/install/linux/`) |
| `runtime-pins.sh` | pinned Node version and SHA-256s, Chromium revision |
| `units/`, `sysusers.conf`, `tmpfiles.conf`, `keyflap-wrapper.sh` | systemd units and configs, the `keyflap` command |
| `bundle/app/` | the broker's code: sources, docs and production `node_modules` (no install scripts run) |
| `node-v22.23.4-linux-<arch>.tar.xz` | the official Node tarball, checked against the pinned SHA-256 at build and at install |
| `RELEASE` | version, OS, architecture, commit, Node version, Chromium revision |

### On a Mac

You need a Mac with Apple silicon and macOS 14 or later, and an admin account. The installer
checks the processor, the macOS version, its tools and every input first, and changes nothing
if something is wrong. It uses only macOS's own tools (bash 3.2, BSD `tar`, `dscl`, `launchctl`);
it needs no Homebrew and no Xcode Command Line Tools. It downloads Playwright's Chromium 1248
(the full browser, not the headless shell). There is no Xvfb on a Mac: the browser runs
headless, and human checks go to the live view on your phone.

Set up the phone approver origin first, as on Linux. On a Mac the Tailscale command is
`/Applications/Tailscale.app/Contents/MacOS/Tailscale`, and `keyflap setup` offers the
`tailscale serve` line itself if the origin doesn't answer yet.

```sh
V=0.1.0                              # the release you downloaded
sudo install -d -m 0755 /opt/keyflap-release
sudo install -m 0644 ~/Downloads/keyflap-$V-darwin-arm64.tar.xz ~/Downloads/SHA256SUMS /opt/keyflap-release/
cd /opt/keyflap-release
grep " keyflap-$V-darwin-arm64.tar.xz\$" SHA256SUMS | shasum -a 256 -c
gh attestation verify keyflap-$V-darwin-arm64.tar.xz --repo johnpippett/keyflap \
  --signer-workflow johnpippett/keyflap/.github/workflows/release.yml
sudo tar -xJf keyflap-$V-darwin-arm64.tar.xz
sudo ./keyflap-$V-darwin-arm64/install.sh --approver-origin https://broker.tail1234.ts.net:8766
sudo keyflap setup
```

The installer creates `/usr/local/bin` (root:wheel 0755) if the Mac has none, and refuses when
`/usr/local` or `/usr/local/bin` is not root-only (Intel Homebrew made it user-owned), because a
`keyflap` there runs as root. It removes the `com.apple.quarantine` attribute from every copy
before anything in it runs. macOS may show a "Background Items Added" notification for the
services.

The macOS release (`keyflap-<version>-darwin-arm64/`) holds the same `install.sh`,
`uninstall.sh`, `runtime-pins.sh`, `bundle/` and `RELEASE`, with `launchd/` (the three
LaunchDaemon plist templates), `keyflap-launch` (the launchd socket handover program,
`packages/install/macos/launcher/`) and `keyflap-wrapper.sh` in place of the systemd files, and
`node-v22.23.4-darwin-arm64.tar.xz`. Design and every measurement: IMPLEMENTATION_NOTES "Service
mode on macOS (S5): the installer".

### Upgrading

Download and check the new release the same way, then run its
`install.sh` with the same options as the first time (the configuration is rewritten from
them). It stops the services, replaces `/opt/keyflap`, keeps the key store, its KEK, the
channel key, the database (phones, agents, passwords, policies) and saved sessions, and
restarts everything. It issues a fresh host token each time (both copies; the hook reads
the new one).

**Reproducing a release.** `build-bundle.sh --release` sorts files, sets owner 0:0,
normalises modes and sets every mtime to `SOURCE_DATE_EPOCH` (the commit time), and drops
pnpm's files that hold build paths or times. Building the same tag with the same pnpm and
xz versions gives byte-identical tarballs: compare with the release's `SHA256SUMS`. With
a different xz version the compressed bytes can differ while the tar inside is the same
(`xz -dc FILE | sha256sum`).

```sh
git checkout v$V && pnpm install --frozen-lockfile
packages/install/linux/build-bundle.sh --release /tmp/keyflap-release --version $V
```

## Install from source

You need the same as above, plus `curl`, pnpm and a checkout you trust: the installer
copies it into `/opt/keyflap` as root. Install from a clean clone, before you give agents
shell access, not from a working copy an agent can write to. As with a release, the
installer and the bundle must sit where only root can change them, so copy both there
first (`install.sh` refuses to run from your checkout or take a bundle from `/tmp`):

```sh
# 1. As yourself: stage the code (sources + production node_modules, no install scripts run)
packages/install/linux/build-bundle.sh /tmp/keyflap-bundle

# 2. As root: root-owned copies of the installer and the bundle
sudo install -d -m 0755 /opt/keyflap-release
sudo rm -rf /opt/keyflap-release/installer /opt/keyflap-release/bundle
sudo cp -r packages/install/linux /opt/keyflap-release/installer
sudo cp -r /tmp/keyflap-bundle /opt/keyflap-release/bundle

# 3. Phone approver origin (example: Tailscale)
tailscale serve --bg --https=8766 http://127.0.0.1:8766

# 4. As root: users, /opt/keyflap (downloads Node 22.23.4, checksum-pinned, and Playwright's
#    Chromium 1248), credentials, units; starts the services
sudo /opt/keyflap-release/installer/install.sh --bundle /opt/keyflap-release/bundle \
  --approver-origin https://broker.tail1234.ts.net:8766

# 5. Pair your phone, add an agent
sudo keyflap setup                    # or: sudo keyflap approver pair / agent add as above
```

On a Mac the source install is `packages/install/macos/install.sh --bundle DIR --launcher FILE
--approver-origin URL`, run from a root-only copy of `packages/install` (it reads
`runtime-pins.sh` from `../linux/`). `packages/install/macos/launcher/build.sh OUT_DIR` builds
`keyflap-launch` in a pinned Linux container; pass `--node-tarball` for an offline install. The
macOS isolation suite installs this way (IMPLEMENTATION_NOTES "Isolation suite on macOS").

## Install options

`--user NAME` picks who may use the intent socket (default: the user running sudo).
Other options: `--mcp-port N`, `--high-risk DOMAIN` (repeatable), `--approver-listen IP:PORT`
(the approver page's listener, default `127.0.0.1:8766`), `--tls-cert/--tls-key`
(your own certificate instead of a proxy; stored as sealed credentials that only the
approver front loads),
`--password-source proton-pass` (below), `--password-source 1password`
([1password.md](1password.md#service-mode)), `--headless` / `--xvfb PATH` (below; Linux only,
refused on a Mac), `--no-start` (write everything, start nothing),
`--ephemeral-browser` (below), `--node-tarball FILE` / `--browsers-dir DIR` for offline
installs, `--tailscale-bin PATH` (the Tailscale CLI the signer runs to watch the approval
address; the default for a `.ts.net` origin is the first of `/usr/bin/tailscale`,
`/usr/sbin/tailscale`, `/usr/local/bin/tailscale` that only root can change; on a Mac with the
standalone Tailscale app the signer reads Tailscale's setting without a CLI, see below; the
installer refuses a `.ts.net` origin it has no way to read). `install.sh --help` lists them all.

**iOS app (parked).** The native iPhone approver ([ios-app.md](ios-app.md)) is parked:
the broker side is tested, but the app isn't shipped. The web approver above is the
supported path. Its install options stay for anyone building the app themselves:
`--apns-key FILE --apns-key-id ID --apns-team-id ID --apns-bundle-id ID [--apns-sandbox]
[--apns-generic]` (push to the app through APNs; the .p8 key becomes a sealed credential,
`apns-key`). On a terminal, `sudo keyflap approver pair` also shows the pairing link as a QR
code, for the app's scanner; the web approver just uses the link.

Re-running `install.sh` upgrades the code and keeps the key store, its KEK, the channel
key and the database (see "Upgrading" above). It issues a fresh host token each time
(both copies).

## Using it

- **Agents** reach the broker exactly as before: MCP at `http://127.0.0.1:8765/mcp` with
  their token. `sudo keyflap agent add` prints the `.mcp.json` and the Claude Code settings.
  The hook command is `/usr/local/bin/keyflap hook claude-code --agent <id> --service`, and the
  sandbox settings deny the model `/var/lib/keyflap/hook/**` (on a Mac,
  `/Library/Keyflap/hook/**`), where your copy of the host token lives. The rest of
  [claude-code.md](claude-code.md) applies unchanged.
- **Admin commands** need root and go to the running services, so they take effect at
  once (a revoked agent's browser session closes immediately; a password added is usable
  without a restart):

  ```sh
  sudo keyflap agent add|list|revoke …
  sudo keyflap password add <site> [--username U] [--totp]   # secrets from a no-echo prompt
  sudo keyflap password import <file.csv> [--expect F] [--site S]... [--all]   # Apple / Google / Chrome CSV export
  sudo keyflap password list|remove …
  sudo keyflap approver pair|list|remove …
  sudo keyflap policy set|list|remove …
  sudo keyflap sessions list|clear|keep|unkeep …
  sudo keyflap status [--json]
  sudo keyflap audit verify|tail …
  ```

  As your own user (or any agent) these fail with "root-only: run this with sudo". On Linux, if
  `sudo keyflap` says "command not found", your sudo's `secure_path` lacks `/usr/local/bin`: run
  `sudo /usr/local/bin/keyflap …`.
  `keyflap daemon` and `--data-dir` are dev-mode only.
- **The console:** `sudo keyflap` with no command, in a terminal, opens a full-screen console
  with the same look as `sudo keyflap setup`. Its first screen says how many phones are paired,
  whether the approval address is right, and how many agents and passwords there are. From
  there you reach every admin command above without typing it:

  | Section | What it does |
  |---|---|
  | Passwords | list them, add one (no-echo prompts), import another CSV export, remove one |
  | Password managers | Proton Pass or 1Password: log the signer's Proton Pass session in, or say which install option turns one on; trust an updated `pass-cli` or `op` |
  | Phones | list them, pair one (QR code), remove one |
  | Agents | list them, add one and set up its app (as setup does), revoke one |
  | Sign-in rules | list them, set one, remove one |
  | Saved sessions | list them, sign agents out, keep a high-risk site signed in, stop keeping one |
  | Health | status, the doctor checks, the audit chain check, recent audit entries |

  Arrow keys or a number choose, Enter selects, Tab shows the details a screen leaves out, and
  Esc goes back (at the first screen it quits, as Ctrl-C does). Every change asks first; a
  removal, or a change that loosens a rule, defaults to no. The console runs the same code as the commands, as root, and shows no
  secret: a new agent's token goes straight to its file, as in setup. The Password managers
  section connects Proton Pass or 1Password on the spot (below). Without a terminal, or without
  `sudo`, `keyflap` prints its usage as before. Dev mode and the simple install have an
  unprotected version of this console (see
  [simple-mac-install.md](simple-mac-install.md#the-console)).
- **The pairing link** is only ever printed by `sudo keyflap approver pair` (and kept in
  `/var/lib/keyflap/core/approver/pairing-url`, on a Mac
  `/Library/Keyflap/data/core/approver/pairing-url`). It is never written to the logs. On Linux
  members of `wheel`, `adm` or `systemd-journal` can read the journal on many distributions.
- **Removing a lost phone:** `sudo keyflap approver remove <id>`. Removing the last phone
  reopens first-use pairing; only root can do that (the core can't).
- **The approval address is watched.** With a `.ts.net` origin (or `--tailscale-bin`), the
  signer runs `tailscale serve status --json` every 2 seconds and expects the origin proxied to
  the approver listener and nothing else on that port
  ([phone-approver.md](phone-approver.md#the-approval-address-is-watched)). When the setting
  points anywhere else, the signer removes every phone and refuses approvals and pairing, the
  core cancels pending approvals, signs the phones out, warns them by push and audits
  `approver.address_tripped`. `sudo keyflap status` then shows
  `Address:     off: it was changed at <time> (<what it saw>), so phones were signed out to be
  safe`, then what is there now, with the fix on the next line, and `sudo keyflap doctor` fails
  the check `approver-address`. Nothing served while this machine is off the tailnet (what
  Tailscale reports while it restarts) is not a change: approvals pause and resume by
  themselves, and a pause shorter than 30 seconds cancels nothing. Nothing served while it is on
  the tailnet is a change: anything listening on that port would get the address. The fix is at the machine, as root
  (on a Mac, run the Tailscale lines without `sudo`, as yourself):

  ```sh
  sudo tailscale serve reset            # only when more than the proxy target changed: clears every serve setting
  sudo tailscale serve --bg --https=8766 http://127.0.0.1:8766
  sudo keyflap approver pair            # re-checks the setting, clears the latch, prints the pairing link
  ```

  While the setting is still wrong, `approver pair` refuses and prints what it saw. Only root
  can clear the latch: the core gets `admin_required`. Before pairing again, delete the
  Keyflap icon on the phone and clear its website data for the address
  ([phone-approver.md](phone-approver.md#the-approval-address-is-watched)). When the signer
  cannot read the setting at all (`Address:     unreadable: …`), approvals pause and resume on
  the next good read, with the phones kept.
- **Logs:** identifiers only, never secrets. Linux: `journalctl -u keyflap-core -u keyflap-signer`.
  Mac: `sudo tail -n 50 /Library/Keyflap/log/core/core.log` (also `signer/signer.log` and
  `approver/approver.log`). The Mac log files are not rotated yet.
- **Install log:** on a terminal, `install.sh` shows a progress bar and a short summary, and
  writes everything it used to print, and its commands' output, to `/var/log/keyflap/install.log`
  (Linux) or `/Library/Keyflap/log/install.log` (Mac), root-only (0600): `sudo less` it. Each run
  appends a section. Without a terminal (piped, an agent, CI) it prints the plain `==>` lines and
  writes no log.
- **Status and restart.** Linux: `systemctl status keyflap-core`,
  `sudo systemctl restart keyflap-core`. Mac: `sudo launchctl print system/com.keyflap.core`,
  `sudo launchctl kickstart -k system/com.keyflap.core`. launchd restarts a service that
  exits with an error, as systemd does.

## Saved browser sessions

Each agent's cookies and site storage (localStorage, IndexedDB) survive a restart of
`keyflap-core` or the machine, so an agent that was signed in stays signed in without a new
approval (design: [SESSIONS_PLAN.md](../SESSIONS_PLAN.md) section 2).

- **Where:** `/var/lib/keyflap/core/browser-state/<agentId>.state` (Mac:
  `/Library/Keyflap/data/core/browser-state/`), the core user only (0700 dir,
  0600 files), encrypted with AES-256-GCM under a data key the signer keeps in its key
  store (so it is bound to the sealed KEK, and an offline copy of `/var/lib/keyflap/core` or a
  backup is ciphertext). `uninstall.sh --purge` removes it.
- **What is never saved:** anything holding a password or code the broker filled (a site
  that copies it into a cookie or storage loses that cookie or that origin's storage),
  sites you deny with `sudo keyflap policy set <site> --deny`, sites whose session TTL has no
  live clock, and high-risk sites (banks, email, identity providers, `--high-risk`)
  unless you keep them (below). sessionStorage, cache and history aren't saved either.
- **Inspect and clear:** `sudo keyflap sessions list [--agent ID] [--json]` shows, per agent
  and site, cookie and storage counts, the last save and when the session TTL ends it.
  `sudo keyflap sessions clear (--agent ID | --all) [--site SITE]` ends live and saved
  sessions at once. Revoking an agent deletes its saved state.
- **Keep a high-risk site signed in:** `sudo keyflap sessions keep <site> [--agent ID]`
  (without `--agent`: every agent); `sudo keyflap sessions unkeep <site>` drops it from the
  saved state at once. Only you can set this; no agent tool can.
- **Turn it off:** install with `--ephemeral-browser`, or set `"persist": false` in the
  `browser` object of `/etc/keyflap/core.json` (Mac: `/Library/Keyflap/etc/core.json`) and
  restart the core. Existing files are kept (not restored) until you clear them.
- `sudo keyflap status` shows "Saved sessions: N agents, M sites".

## Proton Pass

The signer runs `pass-cli` as `keyflap-signer`, with its own session in
`/var/lib/keyflap/signer/proton-pass` and the file key provider (a system service has no
keyring or D-Bus session).

**Where `pass-cli` must live.** The signer's uid can read the key store's KEK, so it only
ever runs a password tool that nobody but root can change. Every external tool goes through
the same check (`@aab/sources` `tool.ts`), at install, in `keyflap doctor` and before each
launch:

- the binary is in a system bin directory (`/usr/bin`, `/usr/local/bin`, `/usr/sbin`,
  `/usr/local/sbin`, `/bin`, `/sbin`) or in `/opt/keyflap/tools/pass-cli/`;
- the path has no symbolic link on the way, and the binary and every directory above it are
  owned by root and not writable by group or others (no setuid/setgid bits);
- its SHA-256 matches the one the installer pinned in `/etc/keyflap/signer.json`.

Anything else is refused: the password source reports "unavailable", the core audits
`source.sync_failed` (`source_tool_untrusted` or `source_tool_changed`), and the signer's
journal says why. The installer never copies a binary from your `PATH` or your home (a copy
your uid could have swapped before root read it), and earlier installs' copy in
`/opt/keyflap/bin` is deleted on upgrade.

Install `pass-cli` as root, from Proton's download (checked as their docs say) or your
distribution's package. A package's `/usr/bin/pass-cli` already qualifies; otherwise:

```sh
sudo install -d -m 0755 /opt/keyflap/tools/pass-cli
sudo install -o root -g root -m 0755 ./pass-cli /opt/keyflap/tools/pass-cli/pass-cli
sudo /opt/keyflap-release/keyflap-$V-linux-$ARCH/install.sh --approver-origin … \
  --password-source proton-pass --proton-pass-vault <vault>
```

Connect it later, or switch to it, without the installer: `sudo keyflap password-source add
proton-pass [--vault V]`, or the console's Password managers section (see "Connecting a password
manager" below). Without `--proton-pass-bin` the installer looks in `/opt/keyflap/tools/pass-cli/`,
`/usr/local/bin` and `/usr/bin`, in that order. `/opt/keyflap/tools` survives upgrades and a
plain uninstall (`--purge` removes it).

**After updating `pass-cli`** (a new download, a package upgrade) the pinned hash no longer
matches and the signer refuses it until you approve the new binary. Make sure it is genuine,
then:

```sh
sudo keyflap password-source trust pass-cli   # re-checks the location, pins the new SHA-256
```

The signer picks the new pin up on its next use of the tool; no restart. `sudo keyflap
doctor` reports a tool the signer would refuse, with the command that fixes it.

**On a Mac**, `/usr/bin` is closed to everyone by System Integrity Protection, so put
`pass-cli` in `/opt/keyflap/tools/pass-cli/` (`sudo install -o root -g wheel -m 0755 …`; macOS has
no `root` group) or a root-only `/usr/local/bin`, never Homebrew's `/opt/homebrew/bin`. The
installer refuses a `pass-cli` that still carries `com.apple.quarantine` from a browser download,
and prints the `sudo xattr -d com.apple.quarantine …` fix. `sudo keyflap setup`
logs the signer's session in for you (step 5); the commands below are the same steps by hand,
with `_keyflap-signer`, `/Library/Keyflap/data/signer`, and a restart with
`sudo launchctl kickstart -k system/com.keyflap.signer` and then `system/com.keyflap.core`.

Then log that session in once, as `keyflap-signer`, with the same environment the signer
uses. The first command asks for the personal access token without echo and hands it to
`pass-cli login` in its environment (`PROTON_PASS_PERSONAL_ACCESS_TOKEN`); the token never
appears on a command line (`PP` is the path the installer printed, e.g.
`/opt/keyflap/tools/pass-cli/pass-cli`):

```sh
PP=/opt/keyflap/tools/pass-cli/pass-cli
sudo -u keyflap-signer env HOME=/var/lib/keyflap/signer \
  PROTON_PASS_SESSION_DIR=/var/lib/keyflap/signer/proton-pass PROTON_PASS_KEY_PROVIDER=fs \
  PP="$PP" sh -c 'stty -echo; printf "Personal access token: "; IFS= read -r t; stty echo; echo
         export PROTON_PASS_PERSONAL_ACCESS_TOKEN="$t"; unset t
         exec "$PP" login'
sudo -u keyflap-signer env HOME=/var/lib/keyflap/signer \
  PROTON_PASS_SESSION_DIR=/var/lib/keyflap/signer/proton-pass PROTON_PASS_KEY_PROVIDER=fs \
  "$PP" vault list      # should list your vault
sudo systemctl restart keyflap-signer keyflap-core
```

Never put the token itself on a command line (`pass-cli login --pat <token>`): it lands in
your shell history, and every user can read `/proc/*/cmdline`. While `pass-cli login`
runs, the token is in its environment, which only `keyflap-signer` and root can read. See
[proton-pass.md](proton-pass.md#logging-in-without-the-token-on-the-command-line) for why
and what is left.

Every process sharing a session must use the same key provider, or `pass-cli` logs the
session out: always use the environment above for this session. This session is separate
from any in your own home. If the same token is also logged in elsewhere (your own
`pass-cli`, other tools), those can read the same vaults; a dedicated vault and token for
the broker avoid that.

## 1Password

The signer runs `op` as `keyflap-signer`, signed in as a 1Password service account. Like
`pass-cli`, `op` must be root-only (`/opt/keyflap/tools/op/op`, `/usr/local/bin/op` or
`/usr/bin/op`) and its SHA-256 is pinned (`sudo keyflap password-source trust op` after
updates). On Linux the installer seals the token as the systemd
credential `op-service-account-token`, which only the signer service loads (a drop-in,
`keyflap-signer.service.d/1password.conf`). On a Mac it is the 0400 file
`/Library/Keyflap/credentials/signer/op-service-account-token`, owned by `_keyflap-signer`. The
token is never in the signer's configuration or on a command line:

```sh
sudo ./install.sh --approver-origin … \
  --password-source 1password --1password-vault Agent [--op-bin PATH] [--op-token-file FILE]
```

No `--op-token-file`: it prompts for the token without echo. Upgrades keep the sealed
token. Setup, vault scoping and request limits: [1password.md](1password.md).

### Connecting a password manager (no installer)

`sudo keyflap password-source add proton-pass|1password [--vault V] [--bin PATH] [--yes]`
connects a manager on a machine that is already installed, and the console's Password managers
section does the same (Connect Proton Pass, Connect 1Password, Disconnect). Both run one
in-process routine as root. It never goes through the admin sockets or the running services,
which write no config and choose no binary.

1. It finds the tool in the root-only places above and pins its SHA-256. A tool anywhere else
   is refused.
2. It proves the credential as the signer's user with a clean environment. For 1Password it
   reads the token without echo and runs `op vault list` with it; for Proton Pass it asks
   `pass-cli` for the vaults, and logs in with a personal access token when the signer is not
   logged in.
3. It stores the token. Linux seals it with `systemd-creds` (the token goes in on stdin, never
   on a command line) and swaps the signer's drop-in from `no-network.conf` to `1password.conf`.
   On a Mac it writes the 0400 file owned by `_keyflap-signer`.
4. It writes `signer.json` and `core.json` (checked with the parsers the services use, written
   to a temporary file and renamed), reloads systemd, and restarts the signer, then the core.

Adding the manager that is already connected keeps its vault, and by default its tool. At the
vault question, blank keeps the current vault and `all` lifts the limit; without a terminal
the vault stays unless `--vault` names another. If the tool's SHA-256 changed since it was
pinned, the command prints the old and new hashes and asks first (without a terminal it needs
`--yes`), the same decision as `sudo keyflap password-source trust`. In the console, connecting
a manager that is already connected and working says so and asks `Change it?` before it asks
for a token.

Keyflap uses one manager at a time. Connecting a different one asks first, and says what
happens to the current one's logins: they stay in that manager, and Keyflap signs out of Proton
Pass or deletes its copy of the 1Password token. The answer defaults to no. Without a terminal
the replacement needs `--yes`.

`sudo keyflap password-source remove` disconnects the manager. It deletes the token, switches
the signer's drop-in back to `no-network.conf` so the signer has no network again, and restarts
both services. Agents then use the passwords stored in Keyflap itself. For Proton Pass, add and
remove sign the signer out of `pass-cli`, and say so if they could not. The installer does not:
`install.sh --password-source none` or a switch leaves the signer's Proton Pass login in place.
Use the command or the console to switch away from Proton Pass.

An upgrade keeps the connected manager: re-running `install.sh` without `--password-source`
keeps the tool, its pin, the vault and the token, and `--op-token-file` alone rotates the
connected 1Password token. An explicit flag overrides, and `--password-source none` turns the
manager off. If the connected manager's settings cannot be read the installer stops and asks you
to say what you want with `--password-source`. The one-command `install-keyflap.sh` keeps the
manager when you choose an import or go on without a tool, and disconnects it only when you
choose to disconnect and confirm. If the tool changed since it was pinned the
installer keeps the old pin and says so, and the signer refuses the tool until
`sudo keyflap password-source trust <tool>`.

## Headed browser on a private display (Xvfb, the Linux default)

This section is Linux only. On a Mac a service has no display, so the core runs the full
Chromium in new headless mode, with Chromium's own sandbox on; the installer refuses `--xvfb`
and `--headless` there.

Some sites' bot walls refuse headless Chromium (its user agent says `HeadlessChrome`), and
the broker doesn't disguise automation. So by default the core starts Xvfb itself and runs
Chromium headed on that display. The installer needs Xvfb for that and stops (changing
nothing) if it's missing:

| Distribution | Package |
|---|---|
| Debian, Ubuntu | `sudo apt install xvfb` |
| Fedora | `sudo dnf install xorg-x11-server-Xvfb` |
| Arch | `sudo pacman -S xorg-server-xvfb` |

It uses the `Xvfb` on root's `PATH` (else `/usr/bin/Xvfb`), which must be root-owned;
`--xvfb PATH` picks another. `--headless` keeps Chromium headless instead (no Xvfb
needed). Installs from before this default were headless; re-running a newer installer
without `--headless` switches them to headed, and sites that tied a session to the
headless user agent (such as `cf_clearance` cookies) may ask for a fresh sign-in.

The display is the managed browser's screen and keyboard, so it is kept from other uids:
Xvfb runs inside `keyflap-core.service` with `-nolisten tcp -nolisten local` (no TCP port and
no abstract socket, which would ignore file permissions); its only socket is in the
unit's private `/tmp`; and clients need a cookie from a `keyflap-core`-only Xauthority file.
The isolation tests check that your uid can't connect to it.

## Uninstall

From the extracted release directory (after the one command, `/opt/keyflap-release/keyflap-<version>-<os>-<arch>/`),
or `packages/install/linux/` or `packages/install/macos/` in a checkout:

```sh
sudo ./uninstall.sh          # code, services, sockets; keeps data, KEK, users
sudo ./uninstall.sh --purge  # also the key store, database, credentials, users
```

On a Mac, `--purge` removes everything except the three hidden service users: macOS lets only an
app with Full Disk Access delete a user record, so from Terminal or ssh the delete fails
(`eDSPermissionError -14120`). The script says so and prints the fix. The users have no shell
and no password, and a later install reuses them. Uninstall also leaves `/usr/local/bin`, even
when the installer created it.

`--purge` deletes every passkey the broker holds. Sites where you registered one need
another sign-in method afterwards.

## Limits

- **Root is out of scope** ([ARCHITECTURE.md section 11](../ARCHITECTURE.md#11-threat-model)):
  root can read everything here.
- **The intent hook still runs as you** and reads your host-token copy, so a same-user
  agent can forge "you said…" text ([ISOLATION_PLAN.md, "Not fixed by this
  plan"](../ISOLATION_PLAN.md#not-fixed-by-this-plan)). The phone
  shows those words; deny prompts you didn't type.
- **`sudo` can be aliased** by a same-user agent (`alias sudo=…` in your shell rc) to
  capture your password. Admin commands moving to phone approvals is the planned fix.
- **Install-time trust:** the installer runs as root on the release you extracted or the
  bundle you built. Verify a release and extract it as root (above); build a bundle from a
  checkout no agent could write to. `install.sh` refuses to run from, or read inputs from,
  anywhere but root could change, and checks `Xvfb` and `pass-cli` the same way (the core
  re-checks `Xvfb` at every start). `sudo keyflap setup` edits your files (Claude Code and
  other agents' configs, the hook directory) as your uid, not as root, and refuses any
  symbolic link it would read or write through there, so a link your uid planted can't point
  it at a broker file. `pass-cli` itself is Proton's code running as `keyflap-signer`, next to
  the KEK: the location check and the pin make sure it is the binary you installed, not that
  the binary is honest. A release trusts GitHub Actions and this repository's
  release workflow (that is what the attestation proves), plus Playwright's download of
  Chromium at install time, which isn't pinned by checksum (`--browsers-dir` avoids it).
- **On Linux, Chromium runs without its own sandbox** (Playwright's default); the unit's sandbox
  (`ProtectSystem=strict`, `ProtectHome=`, `PrivateTmp=`, `NoNewPrivileges=`, no
  capabilities, …) and the `keyflap-core` uid are what contain a browser exploit. Such an
  exploit can't get a signature without your phone, read the signer's keys, or change the
  approver page. But it runs as `keyflap-core`, so it gets everything the core holds: every
  agent's saved browser sessions (cookies, storage) and their keys, every password and TOTP
  code the signer has released for a fill (the core keeps them in memory to scrub them from
  later tool output), the host token (and so the power to record "You said" words), and the agents' token hashes.
  On a card it can make up the "You said" words and the agent name (they aren't part of what
  the phone signs); the site, credential and any allow-for window are checked, and within a
  live allow-for grant it can sign in without a prompt like the agent could.
- **On a Mac there is no systemd sandbox** (see below). Chromium's own sandbox is on there, and
  the same exploit gets the same things it gets on Linux.
- **The approval address is watched, not locked.** Anyone who may change `tailscale serve`
  can still repoint it. The signer catches a change on its next poll (2 seconds, 250 ms while
  an approval waits), so a repoint undone within one poll and timed to your phone's request is
  not caught. The core tells the signer when an approval waits, so against a compromised core
  the window is the 2-second poll. The reading is only as trustworthy as the `tailscale`
  binary the signer runs (root-only, never the app in `/Applications`), and the push warning
  reaches only phones that turned notifications on. An address only Keyflap controls is the
  next roadmap item.

## On a Mac

The design and the isolation claims are the same as on Linux: the uid boundary and root-owned
code keep an agent that runs as you away from the keys, memory and browser. The macOS isolation
suite checks invariants 1, 5, 7 and 9 from a third uid on a real Mac against the real install
(IMPLEMENTATION_NOTES "Isolation suite on macOS"). What differs:

- **Apple silicon and macOS 14 or later only.** Intel Macs get "not supported yet". Tested on
  macOS 26.
- **Secrets are service-owned 0400 files**, not sealed to a TPM. FileVault covers disk theft;
  the installer reports when it is off and does not refuse.
- **No systemd sandboxing layers** (`ProtectSystem`, `ProtectHome`, `PrivateTmp`, the syscall
  filter, `RestrictAddressFamilies`). Each service gets its own `TMPDIR` (`<data>/tmp`, 0700) in
  place of `PrivateTmp`.
- **The signer has network access.** launchd has no equivalent of `RestrictAddressFamilies`, so
  the Linux test that the signer cannot open a network socket has no Mac twin.
- **The browser runs headless,** with Chromium's own sandbox on. Bot walls that refuse headless
  browsers may show more human checks; you solve them in the live view on your phone.
- **Logs** are files under `/Library/Keyflap/log/<service>/`, which only root and that service's
  user can read. They are not rotated yet.
- **Password tools** live in `/opt/keyflap/tools/<command>/` or a root-only `/usr/local/bin`.
- **How the signer reads Tailscale's setting.** With the standalone Tailscale app (from
  tailscale.com/download), the signer runs no Tailscale command. The app's command reaches
  Tailscale through the app itself, which a background service can't do. The signer asks
  Tailscale's own service directly instead, on `127.0.0.1` at the port named in
  `/Library/Tailscale/ipnport`, with the token Tailscale keeps next to it. The installer lets
  `_keyflap-signer` read that token: it adds an access-control entry to `/Library/Tailscale`
  that each new token file inherits, and one to the current token file. It changes nothing else
  of Tailscale's, and `uninstall.sh` removes the entries. When Tailscale restarts it writes a
  new token file, which takes the directory's entry (not yet verified on a real Mac). If an
  update or a reinstall re-creates `/Library/Tailscale`, the entries are gone: approvals pause
  with "Tailscale's token cannot be read" until you re-run the installer, and
  `sudo keyflap doctor` says so. The App Store Tailscale app keeps its token where a background service can't read it:
  install the standalone app or open-source `tailscaled` instead. With open-source `tailscaled`,
  the signer runs a root-only `tailscale` (`--tailscale-bin`).
- **`uninstall.sh --purge`** keeps the hidden service users (above).
- **The simple install** ([simple-mac-install.md](simple-mac-install.md)) is the no-admin-password
  alternative. It protects less. The full installer refuses while it is on the Mac, and the
  simple install refuses while the full one is.

Every Mac decision, with what was measured: [MAC_PLAN.md](../MAC_PLAN.md), "Deviations from the
Linux design", and IMPLEMENTATION_NOTES from "Service mode on macOS (S5): the platform layer" on.
