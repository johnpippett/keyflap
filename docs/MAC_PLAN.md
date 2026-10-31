# Mac plan: service mode, the simple install and agent-led setup on macOS

Status: **building** (2026-10-29; M1 to M7 landed, M8 open). Owner decision (`DECISIONS.md`, "Mac works like Linux"): Mac
is supported at launch and works like Linux. This plan is ISOLATION_PLAN.md step S5, plus the
simple Mac install and the agent-led setup from the README roadmap. Section 5 of
ARCHITECTURE.md is unchanged. Every Mac-only difference from the Linux design is listed under
"Deviations" and goes into IMPLEMENTATION_NOTES as it lands.

Grounding: a survey of every Linux/systemd coupling in service mode (file:line), kept with the
run's decision trail. The parts of it that shape this plan are restated here.

## Definition of done

On the test Mac (Apple silicon, macOS 26), starting from nothing installed:

1. The agent install prompt in Claude Code ends with the agent signing into the local test RP
   after one approval on the owner's iPhone. The owner typed one admin-password command, scanned
   the pairing code and approved. The same holds for a password + TOTP login and a passkey, and a
   denial on the phone is a denial.
2. `pnpm test:isolation` on the Mac (invariants 1, 5, 7 and 9 against a third uid) passes on that
   install. An upgrade in place keeps keys, phone and agents. Uninstall leaves nothing behind.
3. `pnpm check` and `pnpm test:isolation` pass on Linux exactly as before.
4. The simple install (no admin password) signs in the same way and says "protects less" before
   it installs and in `keyflap status`/`doctor`.

## Shape on macOS

Same three service users, same sockets, same fd contract as Linux. launchd replaces systemd.

| | Linux | macOS |
|---|---|---|
| Users | `keyflap-core`, `keyflap-signer`, `keyflap-web` (sysusers) | `_keyflap-core`, `_keyflap-signer`, `_keyflap-web` (dscl, hidden, uid/gid < 500, shell `/usr/bin/false`), each with the un-prefixed name as a second `RecordName` |
| Code + runtime | `/opt/keyflap` | `/opt/keyflap` (root:wheel 0755; `/opt` created if missing) |
| Config (no secrets) | `/etc/keyflap/*.json` | `/Library/Keyflap/etc/*.json` |
| Secrets | systemd-creds, per-unit `$CREDENTIALS_DIRECTORY` | per-service dirs `/Library/Keyflap/credentials/<service>/`, owned by that service user, 0500, files 0400; `CREDENTIALS_DIRECTORY` set in the plist. Two copies of the channel key, as Linux has two decrypted copies |
| Data | `/var/lib/keyflap/{core,signer}` | `/Library/Keyflap/data/{core,signer}` (0700, service-owned) |
| Hook dir | `/var/lib/keyflap/hook` | `/Library/Keyflap/hook` (owner 0700) |
| Sockets | systemd socket units in `/run/keyflap*` | launchd `Sockets` in `/Library/Keyflap/run/{core,signer,approver}/`, same owners and modes as Linux, handed over by `keyflap-launch` |
| Services | `keyflap-{signer,core,approver}.service` | `/Library/LaunchDaemons/com.keyflap.{signer,core,approver}.plist` |
| Logs | journal | `StandardErrorPath` under `/Library/Keyflap/log/` (root:wheel 0700 dir) |
| Browser | headed on a private Xvfb display | headless, full Chromium in new headless mode (`channel: 'chromium'`) |
| Wrapper | `/usr/local/bin/keyflap` | `/usr/local/bin/keyflap`; the installer refuses if `/usr/local` or `/usr/local/bin` is not root-only. Docs and setup print `sudo keyflap …`, as on Linux |

No path in the table goes through `/etc`, `/var` or `/tmp`, which are symlinks to `/private/…` on
macOS and fail the realpath rule in `sources/src/tool.ts`. None has a space.

### keyflap-launch: socket handover without systemd

Node can't call `launch_activate_socket(3)`, and self-binding loses two Linux properties: the
approver port 8766 stays held while the front restarts (inv5: the core uid can never take it),
and admin sockets are root-owned. So a small C program, `packages/install/macos/launcher/`,
runs as the job's `UserName`, asks launchd for each socket named in the plist's `Sockets`,
moves them to fds 3.., sets `LISTEN_PID`, `LISTEN_FDS` and `LISTEN_FDNAMES` exactly as systemd
does, and execs Node. Every service entry point then takes its existing fd path
(`signer/src/systemd.ts` `listenFds`) unchanged. launchd (root) creates each socket with
`SockPathMode`, `SockPathOwner` and `SockPathGroup` before any broker code runs, and queues
connections until the service is up, which also gives the core its start order.

It is not an npm dependency and the signer stays dependency-free. It ships prebuilt for
arm64 inside the release tarball, covered by the same checksum and attestation. It must be
reproducible from source in the release job.

### Signer tools on a Mac

`/usr/bin` is SIP-protected and Homebrew paths are user-owned, so on a Mac `pass-cli` and `op`
live in `/opt/keyflap/tools/<cmd>/`, copied there by root (installer or `password-source
trust`). `PROTON_PASS_KEY_PROVIDER=fs`, as on Linux: a hidden user has no login keychain.

### User lookup

`/etc/passwd` doesn't list real Mac users. All lookups go through `System` and use Directory
Services on darwin (`dscl`, `id`), so the existing fakes keep working in tests.

## Agent-led setup (both platforms)

The owner's two ways in from keyflap.com do the same thing:

- **The agent prompt.** The agent reads `docs/INSTALL_FOR_AGENTS.md` (a guide written for
  agents), checks the machine and the prerequisites, explains what will happen, then hands the
  owner one command. Afterwards it runs `keyflap doctor` and a test sign-in, and fixes what doctor
  reports. It never runs `sudo`, never types a secret and never writes its own approval rules.
- **The command.** The owner runs the same one command themselves.

The one command is the same on every page and in every agent's hands. It downloads the release
as root, checks it against hashes pinned inside the command's own script (a release asset,
covered by the release attestation), installs, then runs guided setup on `/dev/tty`. Setup finds
installed agents, pre-selects them, pairs the phone (QR) and connects the password manager. So
the agent never writes a command that runs as root. That leaves the owner four things to do: run
the command, scan the code, enter a vault token or pick the Apple Passwords export, and approve
the first sign-in.

## Simple Mac install (no admin password)

From the README roadmap: "One installer that does not need `sudo` … It will say clearly that it
protects less." It installs the same release into `~/Library/Application Support/Keyflap` (code,
Node, Chromium) and runs the daemon as a LaunchAgent (no Terminal window). It uses the phone
approver only, and the key store unlocks from a key file in the user's data dir. It is dev mode
packaged: `--unprotected` with its banner and audit event. Before it installs, `keyflap status`
and `doctor` say in plain words what it doesn't protect (an agent that runs commands as you can
read its files and change its code) and name the real install. It is never the default.

## Deviations from the Linux design (go to IMPLEMENTATION_NOTES as they land)

- Credentials are plain service-owned 0400 files, not sealed to a TPM. Disk theft is covered by
  FileVault; the installer reports when FileVault is off and does not refuse (Linux doesn't
  refuse without disk encryption either).
- No systemd sandboxing layers (`ProtectSystem`, `ProtectHome`, `PrivateTmp`, syscall filter,
  `RestrictAddressFamilies`). The uid boundary and root-owned code carry the isolation, as the
  plan's core claim requires. The signer's no-network rule becomes a test, not a kernel filter.
  Chromium's own Seatbelt sandbox is turned on if it runs under the service user (measured on
  the Mac); `sandbox-exec` is deprecated and not used.
- Headless only. Bot walls that refuse headless browsers may show more human checks; the
  phone's live view handles them.
- `TMPDIR` per service (`<data>/tmp`, 0700) replaces `PrivateTmp`. The approver front gets
  `/Library/Keyflap/data/approver` (0700, `_keyflap-web`) as its home and tmp; on Linux its
  home is `/`.
- Apple silicon only. The installer refuses Intel with a plain message.
- Logs: `/Library/Keyflap/log` is root:wheel **0711** (not 0700: launchd opens
  `StandardErrorPath` as the job's user and refuses a job whose log dir it can't enter), with a
  0700 `log/<service>/` per service owned by it. Not rotated yet.
- `uninstall.sh --purge` cannot delete the service users from Terminal or ssh (TCC,
  `eDSPermissionError -14120`); it removes everything else and prints the Full Disk Access
  fix. The users are hidden, shell `/usr/bin/false`, password `*`, and a later install reuses
  them. The plan's "uninstall leaves nothing behind" holds for files and jobs only.
- launchd holds the approver port on both `127.0.0.1` and `::1` (two `Sockets` entries,
  `approver` and `approver6`) when the listener is the default `127.0.0.1`: another uid can
  otherwise bind the IPv6 twin and answer whoever dials `localhost`. The front serves both.
  Linux has one listener (its units are unchanged).
- The plists set no `GroupName` (launchd ignores `wheel` for a non-root user; the service users'
  primary groups carry the group ids), and `launchctl enable` runs only when a bootstrap is
  refused, because its override entry can never be removed.

## Build order (each unit ends green; riskiest first)

- **M0 Mac spike** (needs the test Mac with sudo): a throwaway launchd job proves that full
  Chromium in new headless mode starts as a hidden user with no login session, that `pass-cli`
  honours the fs key provider and that dscl user creation is idempotent. Results recorded in
  IMPLEMENTATION_NOTES. (M2 already proved that `keyflap-launch` hands over a `SockPathOwner`
  socket and a TCP listener, and that macOS enforces socket file modes on `connect()`.)
- **M1 Platform layer** (Linux-testable): a `ServicePlatform` lookup in `@aab/signer/platform`
  (linux, darwin, unsupported) replacing `serviceModeUnsupported`; `SERVICE_PATHS` per platform;
  user lookup through `System` (dscl on darwin); a service-manager seam for setup and doctor
  (`systemctl` / `launchctl`, logs hint); headless channel option through the shim; doctor and
  setup text per platform; darwin pins in the paths test.
- **M2 keyflap-launch**: the C source, a reproducible build, tests on the Mac. **Done**
  (IMPLEMENTATION_NOTES "keyflap-launch"): cross-built on Linux, so the release job needs no
  macOS runner; the launchd findings M3 needs (default socket mode 0666, socket files left
  after `bootout`, no `GroupName`) are listed there.
- **M3 Mac installer**: `packages/install/macos/{install.sh,uninstall.sh}` (bash 3.2, BSD tools),
  plist templates, darwin Node pins in `runtime-pins.sh`, `build-bundle.sh --os darwin` producing
  `keyflap-V-darwin-arm64.tar.xz`, release workflow building it.
- **M4 Mac isolation suite**: `packages/isolation` runs on darwin with `sudo -n` against the real
  install: invariants 1, 5, 7 and 9 from a third uid (task_for_pid/lldb/vmmap, `ps eww`, `lsof`,
  socket connects, writes under the prefix), plus upgrade and uninstall. **Done**
  (IMPLEMENTATION_NOTES "Isolation suite on macOS"): no lldb (a stub without the Command Line
  Tools); task_for_pid through JXA, run from Linux with `packages/isolation/darwin/run-on-mac.sh`.
- **M5 Agent-led setup**: the one-command bootstrap (both OS), setup on `/dev/tty`,
  `docs/INSTALL_FOR_AGENTS.md`, Tailscale CLI path on macOS; the website's install section in
  `../keyflap-site` on a branch, not deployed.
- **M6 Simple Mac install.** **Done** (IMPLEMENTATION_NOTES "Simple Mac install";
  `docs/integrations/simple-mac-install.md`): `install-keyflap.sh --simple`, `install-simple.sh`,
  the LaunchAgent `com.keyflap.simple`, the key file, the label in status, doctor and setup.
- **M7 Docs**: service-mode.md for both platforms, README, GETTING_STARTED, ISOLATION_PLAN S5,
  CLAUDE.md layout; fix `cli/test/pty.ts`'s hard-coded `/usr/bin/python3`. **Done**: those docs,
  plus INSTALL_FOR_AGENTS (the simple install only on request), the CLI's fixes on a Mac
  (`sudo keyflap …`, as on Linux) and the simple daemon's stop
  line. `pty.ts` was already fixed (IMPLEMENTATION_NOTES "Run on a real Mac"). Still open from
  the M3 notes: log rotation on the Mac, and `password-source trust` removing the quarantine
  attribute.
- **M8 End to end on the Mac** with the owner's phone (definition of done 1).
