# Proton Pass

Let the broker sign agents in with the logins you already keep in Proton Pass, without
copying them anywhere. The broker reads them through Proton's CLI, `pass-cli`, at the
moment you approve a sign-in, and only for the site you approved.

## How it works

- The **signer** process (never the broker core, never the agent) runs `pass-cli`.
- In the background it reads which sites each login is for (its URLs and username, never
  the password) and offers a login on the registrable domains of its URLs. Logins you
  add later are picked up within 5 minutes, or as soon as an agent reaches a page with
  no saved login.
- When the agent calls `auth_login` on a matching page, you approve as usual. Only then
  does the signer read that one item, check again that its URLs belong to the site you
  approved, and hand the broker the password (and the current code, if the item has a
  TOTP secret) to fill. The agent sees `success` or `denied`; the password never reaches
  it, and is scrubbed from everything it can read afterwards.
- Proton records every read with a reason: "Keyflap broker: matching saved logins to
  sites" or "Keyflap broker: approved sign-in on <origin>".

## Setup

With the installed broker, choose Proton Pass in the one-command install or in
`sudo keyflap setup`. Setup logs the signer in with your personal access token. The steps below
are for dev mode.

1. Install `pass-cli` (see Proton's docs) and log it in. A personal access token works
   (format `pst_<token>::<key>`). The broker uses that session; it never logs in itself
   and never sees the token. Keep the token off the command line (see
   [Logging in without the token on the command line](#logging-in-without-the-token-on-the-command-line)):

   ```sh
   read -rs PAT    # bash or zsh: paste the token, then Enter; nothing is echoed
   PROTON_PASS_PERSONAL_ACCESS_TOKEN="$PAT" pass-cli login; unset PAT
   ```

2. Check it: `pass-cli vault list` should list the vault you want to use. A vault of its
   own for the logins your agents may use is the safest choice.
3. Start the daemon with the source:

   ```sh
   keyflap daemon --unprotected --password-source proton-pass --proton-pass-vault <vault>
   ```

   Without `--proton-pass-vault` it reads every vault the session can see.
   `--proton-pass-bin PATH` if `pass-cli` isn't on your PATH.
4. `keyflap password list` shows the logins it matched (SOURCE `proton-pass`), next to any
   native ones from `keyflap password add`.

Only logins whose URLs are `https://`, `http://` or a bare domain are offered. A login
without a URL, or with only an app URL (`android://...`), is never used. If two logins
(or a vault login and a native one) cover the same site, the broker refuses rather than
guess (`ambiguous_credential`).

In service mode the signer runs `pass-cli` as `keyflap-signer` with its own session, and
only from a root-only path: a system bin directory or `/opt/keyflap/tools/pass-cli/`,
installed by root (never a copy from your home, which your uid, and so an agent, could
replace), and pinned by SHA-256 (`sudo keyflap password-source trust pass-cli` after an
update). On a Mac, put `pass-cli` in `/opt/keyflap/tools/pass-cli/`, never Homebrew's
`/opt/homebrew/bin`, and remove its `com.apple.quarantine` attribute first. See
[service-mode.md](service-mode.md#proton-pass).

To connect Proton Pass on a machine that is already installed, without the installer:

```sh
sudo keyflap password-source add proton-pass --vault Agent
```

It runs `pass-cli` as the signer, logs in with a personal access token it reads without echo
when the signer is not logged in, and restarts the services. `sudo keyflap password-source
remove` undoes it and signs the signer out. The console's Password managers section does the
same. Proton Pass replaces 1Password if that is connected, after asking.

## Logging in without the token on the command line

`pass-cli login --pat <token>` works, but don't use it: the token ends up in your shell
history, and while `pass-cli` runs it is in `/proc/<pid>/cmdline`, which every user on the
machine can read. `pass-cli` (checked with 2.3.3) also reads the token from the
`PROTON_PASS_PERSONAL_ACCESS_TOKEN` environment variable when you run plain
`pass-cli login`; `login --pat` with no value is an error, not a prompt. The pattern in
step 1 reads the token without echo into a shell variable, so neither the token nor a
command containing it reaches your history, and hands it to that one `pass-cli` process
in its environment.

What is left: a process's environment (`/proc/<pid>/environ`) is readable by the same
user and by root while it runs, and the variable lives in your shell until `unset`. So
log in from a terminal no agent is driving, don't `export` the token, and don't put it
in a shell profile or in the environment Claude Code (or the daemon) starts from. Once
logged in, `pass-cli` keeps its session in its own files and no longer needs the token.

Anyone who holds the same token, or can read the session `pass-cli` stores, can read the
vaults it grants. The broker keeps the vault's secrets away from the agent; it does not
keep them away from other local tools logged in with the same token. A dedicated vault
and token for the broker avoid that.

## Gotchas

- **Use one key provider everywhere.** `pass-cli` keeps a local key in your keyring (over
  D-Bus) or, with `PROTON_PASS_KEY_PROVIDER=fs`, in a file. If a process can't find the
  key the session was created with, `pass-cli` **logs the session out** ("Local
  encryption key not found ... Forcing logout"). The broker passes your
  `DBUS_SESSION_BUS_ADDRESS`, `PROTON_PASS_KEY_PROVIDER` and `PROTON_PASS_SESSION_DIR`
  through, so start it from the same kind of environment you logged in from. Better:
  give each environment its own session. The same personal access token can be logged in
  several times, so point the broker at its own `PROTON_PASS_SESSION_DIR` (with
  `PROTON_PASS_KEY_PROVIDER=fs` on a box without a keyring) and log in there once, instead
  of sharing the session other tools use.
- **Logged out?** Sign-ins with vault logins are denied and the audit log records
  `source.sync_failed {reason: source_not_logged_in}`. Log in again; the next lookup or
  the 5-minute refresh picks it up.
- **Editing a login** in Proton Pass takes effect at the next sign-in for the password,
  and within 5 minutes for which sites it's offered on. Removing a URL stops it being
  filled there at once: the signer checks the live item every time.
- **Sites with bot walls** block the default headless browser (it says `HeadlessChrome`;
  the broker won't disguise that). Run `keyflap daemon --headed`, on your desktop or under
  Xvfb on a headless box (service mode on Linux does this by default: a private display only
  the broker can reach). On a Mac the installed browser is always headless; you solve human
  checks in the live view on your phone.
- Matching reads every login in the vault once (about 1.5 s per login, 6 at a time),
  then only new or changed ones.
