# Isolation plan: the broker leaves the user's uid

Status: **decisions settled** (owner, 2026-10-05): D1 auto-unlock, D2 two service users,
D3 sudo now / phone later, D4 pinned runtime, D5 fail closed without the phone approver,
D6 `--unprotected` gate. S1 done; **S2–S4 and the isolation suite done on Linux**
(IMPLEMENTATION_NOTES "Service mode"; setup: `docs/integrations/service-mode.md`). **S5
(macOS) done** on 2026-10-29: launchd, hidden `_keyflap-*` users, and the isolation suite on a
real Mac (`docs/MAC_PLAN.md`; IMPLEMENTATION_NOTES from "Service mode on macOS (S5): the
platform layer" on).
Since 2026-10-20 a third service user, `keyflap-web` (`_keyflap-web` on a Mac), serves the phone
approver page so the core can't change it (`APPROVER_INTEGRITY_PLAN.md`).
Closes the known limit in IMPLEMENTATION_NOTES "Signer boundary": a process running as
the user's OS user can defeat invariants 1, 7 and 9.

## The problem, concretely

An agent with unsandboxed shell access as the user has four ways in today. Reading
memory is the hardest of them:

| Door | What's exposed | Works where |
|---|---|---|
| Files | `approver-key.json` (plaintext Ed25519, forges approvals), `host-token` (forges intents), `keys.enc.json` (needs the passphrase) | everywhere: 0600 stops other users, not this one |
| Memory | passphrase (daemon + signer), channel key (core), decrypted keys (signer), released passwords (core) | `ptrace` / `/proc/<pid>/mem`; blocked by Yama `ptrace_scope=1` (Ubuntu default) but not on Debian/Fedora defaults |
| Code | the broker runs from a user-writable checkout; edit `daemon.ts` and the next typed passphrase leaks | everywhere, no special rights |
| Browser | Chromium runs as the user: profile (post-login session cookies), DevTools | everywhere |

Today's only defence is Claude Code's sandbox config on `~/.aab`. It covers files, covers
code only while the agent's project isn't the broker repo, is unverified for memory and
browser, and exists for one agent host.

Hardening inside one uid (prctl dumpable, mlock, obfuscation) does not fix this: the
code and files doors stay open. The fix is a uid boundary plus code the user can't write.

## Shape

```
 user uid                     │ aab-core uid                    │ aab-signer uid
                              │                                 │
 agent ──MCP (127.0.0.1, ───────► core: broker, MCP, intents, ──────► signer: key store,
          bearer token)       │   audit, SQLite, Chromium       │   approval verification
 hook ──intent.sock ────────────►   (headless)                  │   (socket 0660, group
          (host token)        │                                 │    aab-core only)
 sudo aab agent add … ──admin.sock (root only) ──►              │
                              │         ▲                       │        ▲
 phone (M4) ──────────────────┼─────────┘ approval relayed ─────┼────────┘ signer verifies
                              │                                 │   the phone's passkey sig
 installed code + runtime: root-owned, read-only to everyone
```

- **Code** installs to a root-owned prefix (`/opt/aab` on Linux, `/Library/Application
  Support/aab/app` on macOS) with its own pinned Node and Chromium (D4). The service
  definitions point only there. The user's checkout is irrelevant to the service.
- **Data** moves to `/var/lib/aab/{core,signer}` (macOS: `/Library/Application
  Support/aab/data/{core,signer}`), each 0700 and owned by its service user.
- **Processes** run as service users (D2). A non-root process can't ptrace or read the
  memory of another uid's process on Linux or macOS. Root is out of scope (section 11:
  "fully compromised OS").
- **The agent's interface is unchanged:** MCP over loopback with its bearer token. That
  token is the agent's own credential; holding it was always expected.
- **Invariant 9 becomes OS-enforced:** the signer socket lives in a directory only
  `aab-core` can reach. The HMAC channel stays as a second layer. Its key is provisioned at
  install into a file readable by both service users and nobody else, instead of being
  passed over stdin, because the core can no longer spawn a process under another uid.
- **Dev mode stays:** today's same-user `aab daemon` keeps working for development and
  tests, behind a flag and a banner (D6).

## Decisions

**D1. How the key store unlocks.** A passphrase typed into the user's terminal is now
the weak point: a same-user agent can't read the service's memory, but it *can* put
`alias aab=…` in `~/.bashrc` and run a fake prompt.
- *Recommended:* **auto-unlock with a machine-bound secret.** The installer generates a
  32-byte key-encryption key and stores it where only `aab-signer` can read it. On Linux
  that's `systemd-creds` (sealed to TPM2 when present, otherwise the root-only host key),
  delivered via `LoadCredentialEncrypted=`. On macOS it's a file owned by `_aab-signer`,
  0400. The signer passes it to `KeyStore.open` in place of the passphrase, so
  `keystore.ts` doesn't change. Protection against disk theft comes from the TPM or
  FileVault/LUKS, not from a passphrase.
- Alternative: keep a passphrase, entered via `sudo aab unlock`. sudo resolves to a
  root-owned binary, but nothing stops an alias in front of `sudo` itself. Weaker, and
  adds a step at every boot.
- Later: unlock gated on a phone approval (after M4).

**D2. One service user or two.**
- *Recommended:* **two (`aab-core`, `aab-signer`).** Chromium renders hostile pages and is
  the biggest attack surface on the box. With one uid, a browser exploit that reaches the
  core reads every key in the store. With two, it reaches a core that, once M4 has the
  signer verifying the phone's passkey signature, can't get a single signature without a
  phone approval and can't bulk-export anything. Passwords are still released to the core
  for filling: that's inherent to filling a form.
- Alternative: one `aab` user. Simpler sockets and install, and the signer stays a child
  process with the stdin channel key as today. Still fixes the user-uid problem completely.

**D3. Who may run admin commands** (agent add/revoke, password add/remove, unlock,
status).
- *Recommended now:* **root only, via `sudo aab …` over a root-only `admin.sock`.** sudo
  timestamps are per-tty by default, so an agent running in another pty can't ride the
  user's recent sudo. Residual risk: an agent can still alias `sudo` and capture a
  password typed into that alias. That's the same class of attack as D1, and the M4
  follow-up below closes it.
- Later (after M4): admin operations require a phone approval instead.
- Rejected: a user-group socket. The agent is in that group too, so it could mint agent
  identities ("Claude Code") or revoke yours.

**D4. Runtime.**
- *Recommended:* **ship a pinned Node 22 and Playwright's Chromium inside the root-owned
  prefix.** The service must not run the user's `node` (nvm or Homebrew paths are
  user-writable) or a browser the user can swap out.
- Alternative: require a system Node at a root-owned path. Smaller download, more
  support load.

**D5. Approvals before M4 lands.** The terminal approver can't work in a service (no
TTY), and any approval UI running as the user is reachable by the agent.
- *Recommended:* **service mode refuses to start without a phone approver.** Fail
  closed. Until M4 merges, service mode is buildable and testable with
  `ScriptedApprover` in tests only.
- Alternative: an interim `sudo aab approve` loop. It works, but it's ugly and it trains
  users to type sudo passwords on demand, which is exactly the phishing pattern D3 worries
  about.

**D6. What happens to same-user mode.**
- *Recommended:* `aab daemon` (same-user) requires `--unprotected`, prints a banner on
  every start and in `agent add` output, and audits `daemon.unprotected`. The installer
  and docs only ever set up service mode. A paid build either omits the flag or refuses
  to issue agent tokens without it. That's a packaging decision for later, not now.

## Not fixed by this plan

- **The intent hook (invariants 4/5).** The hook runs as the user and must read
  `host-token`, so a same-user agent can read it too and fake a "you said…" intent. The
  approval then shows words the user didn't type. It's still a human decision on the
  phone, not a silent signature. Mitigations: keep the Claude Code sandbox config, deny
  prompts you didn't type, and per-agent host tokens (a small follow-up). A real fix needs
  an intent channel only typed input reaches. Already tracked in IMPLEMENTATION_NOTES.
- **Session cookies after login.** They live in the service's Chromium, out of the
  agent's reach, but the agent acts *through* that session by design (section 12,
  action-level policy). Since sessions plan P2 they are also on disk, encrypted, in
  `/var/lib/aab/core/browser-state` (`aab-core`, 0700); `inv1-isolation.test.ts` checks the
  user uid gets EACCES there and that a core restart keeps the agent signed in.
- **Root, kernel exploits, a malicious installer.** Out of scope (section 11).

## Build order (Linux first; it's the platform these tests can run on)

- **S1. Paths and modes.** *(done: `--unprotected` gate, banner, `daemon.unprotected`
  audit, warning in `agent add`.)* Service paths, `--unprotected` gate and banner (D6), CLI
  resolves the service's sockets. No behaviour change in dev mode.
- **S2. Signer as its own service.** *(done.)* Signer reads config from a root-provisioned
  file plus `$CREDENTIALS_DIRECTORY` instead of stdin. Socket dir perms. The core connects
  instead of spawning. Dev mode keeps spawning.
- **S3. Auto-unlock (D1)** and the admin socket (D3). *(done: KEK sealed with
  `systemd-creds`, `LoadCredentialEncrypted=`; admin sockets are root:root 0600 socket units
  whose fds systemd hands to the services, since Node has no `SO_PEERCRED`.)*
- **S4. Linux installer**: system users, systemd units (`ProtectHome=`, `NoNewPrivileges=`,
  `PrivateTmp=`, `ProtectSystem=strict`), root-owned prefix with pinned runtime. Plus the
  **isolation test suite** below. *(done: `packages/install/linux`, `packages/isolation`.)*
- **S5. macOS installer.** *(done, 2026-10-29: `packages/install/macos`, plan and every
  deviation in `docs/MAC_PLAN.md`, facts in IMPLEMENTATION_NOTES "Service mode on macOS (S5)"
  and "Isolation suite on macOS".)* Not as sketched here: there is no `.pkg` (a release tarball
  and the one-command installer); `keyflap-launch` hands launchd's sockets over as systemd
  does, so the services don't bind their own; the KEK is a `_keyflap-signer`-owned 0400 file;
  paths are under `/Library/Keyflap`, not `/Library/Application Support/aab`.
- Wires up to M4's approver when it lands.

## Tests (invariants 1, 5, 7, 9 under service mode)

`packages/isolation/test/` (vitest project `isolation`, `pnpm test:isolation`, not part of
`pnpm test`; on Linux it needs podman or docker and creates its users in a throwaway systemd
container; on macOS see below; skipped elsewhere; CI job ready in `packages/isolation/ci-job.yml`). It runs the real installer,
starts the installed services, then runs a probe as a third ordinary uid that must fail
at each of these:
- read or list `/var/lib/aab/**`, the credential, the channel-key file;
- `connect()` to the signer socket or the admin socket;
- `ptrace(PTRACE_ATTACH)` and `open('/proc/<pid>/mem')` against core, signer and Chromium;
- connect to Chromium's DevTools (invariant 7);
- write anywhere under the install prefix or the unit files.
It also confirms the probe *can* do the legitimate thing: reach MCP with its token and
get a signature only through an approved request. Test names: `inv1-isolation`,
`inv7-isolation`, `inv9-isolation`. Built with two additions: the probe also can't
`connect()` to the private X display (Xvfb, on by default since the release installer:
abstract socket, path socket or TCP), and every admin command run as that uid is refused.
The machine is installed from a release tarball (`build-bundle.sh --release`), then
upgraded in place from a source bundle (`release-install.test.ts`).

**On macOS** (Mac M4, 2026-10-29) the same files run on a real Mac against the real install:
`KEYFLAP_MAC=user@host packages/isolation/darwin/run-on-mac.sh` builds the darwin release and
a source bundle on Linux, copies the checkout to `/Users/Shared/keyflap-isolation` on the Mac
and runs the suite there as an admin with passwordless `sudo -n` (without it, or without the
built release, the darwin run skips and says why; it never runs in `pnpm test`). It installs as
root from a root-only stage, with `--user _kfprobe`, a hidden user with no shell and no password
that the suite creates once and reuses (macOS won't delete a user over ssh). The paths, users
and service commands of each OS live in `test/platform.ts`, so the file, socket, write,
legitimate-path, browser-state, admin-command and installer tests are one body for both. The
Mac-only probes, each with a control on the probe's own process or as root:
- `task_for_pid` (through `osascript -l JavaScript`, no compiler needed), `vmmap`, `sample`,
  `lsof -p`, `kill -0` and `ps eww` against the core, signer, approver front and Chromium;
- no secret (KEK, channel keys, host token, agent token, in hex, base64 and base64url) on any
  service command line, which `ps` shows every uid;
- no TCP listener in Chromium's process tree (`lsof`), and DevTools on none of the service ports;
- the core's uid gets `EADDRINUSE` on `127.0.0.1`, `::1`, `0.0.0.0` and `::` port 8766, also
  right after the front is killed (launchd, pid 1, holds both listeners);
- the same file, socket, write and process probes from the admin account that ran the install,
  which also may not reach the hook dir or the intent socket;
- install from a user-owned copy and `--xvfb` refused with nothing changed, upgrade in place,
  `uninstall.sh` and a reinstall over the kept data (same KEK, phone and agent), and
  `uninstall.sh --purge` at the end, which must leave nothing but the hidden users.
See IMPLEMENTATION_NOTES "Isolation suite on macOS".
