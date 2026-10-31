# 1Password

Let the broker sign agents in with logins you keep in 1Password, without copying them
anywhere. The broker reads them through 1Password's CLI, `op`, signed in as a **service
account**, at the moment you approve a sign-in, and only for the site you approved.

## How it works

- The **signer** process (never the broker core, never the agent) runs `op`.
- In the background it reads which sites each Login item is for (its URLs and username,
  never the password) and offers a login on the registrable domains of its URLs. Logins
  you add later are picked up within 30 minutes, or within 5 minutes once an agent reaches
  a page with no saved login. (Slower than Proton Pass on purpose: see
  [Request limits](#request-limits).)
- When the agent calls `auth_login` on a matching page, you approve as usual. Only then
  does the signer read that one item (`op item get --reveal`), check again that its URLs
  belong to the site you approved, and hand the broker the password (and the current
  code, computed by the signer from the item's one-time password secret) to fill. The
  agent sees `success` or `denied`; the password never reaches it, and is scrubbed from
  everything it can read afterwards.
- `op` gets the service account token in its environment, never on its command line, and
  nothing else from the broker's environment. The desktop app integration is switched off
  (`OP_BIOMETRIC_UNLOCK_ENABLED=false`) and so is op's cache daemon (`OP_CACHE=false`).

Why a service account: in service mode the signer runs as its own system user
(`keyflap-signer`), which can't reach your desktop app's unlock prompt. A service account
token works without the app and can be limited to one vault, read only.

## Setup

1. Install `op` 2.18.0 or later (1Password's docs: "Get started with 1Password CLI").
2. Make a vault of its own for the logins your agents may use, for example **Agent**, and
   move or copy those logins into it. Nothing outside it should be reachable by the broker.
3. Create a service account (on 1Password.com, under Developer) with **read** access to
   that vault only. Save its token
   (`ops_...`) somewhere only you can read; 1Password shows it once.
4. `keyflap setup` (step 5, Credentials > 1Password) checks the token with `op vault list`,
   lets you pick the vault and records the choice. In dev mode it never saves the token; in
   service mode it stores the token for the signer, as `password-source add` does. Or by hand:
   start the daemon with the token in its environment, read without echo so it never
   reaches your shell history or a command line:

   ```sh
   read -rs op_token   # bash or zsh: paste the token, then Enter
   OP_SERVICE_ACCOUNT_TOKEN=$op_token keyflap daemon --unprotected --password-source 1password --1password-vault Agent
   unset op_token
   ```

   Hand the token to the daemon's command only, as above. Don't `export` it or put it in a
   shell profile: every program started from that shell inherits exported variables,
   including an agent (Claude Code), which could then read the whole vault with `op`
   itself. Keep the token in your password manager and run the daemon from a terminal no
   agent is driving.

   The daemon takes the token out of its own environment at start (the managed browser
   inherits that environment) and hands it to the signer on its stdin. Without
   `--1password-vault` it reads every vault the service account can see. `--op-bin PATH`
   if `op` isn't on your PATH.
5. `keyflap password list` shows the logins it matched (SOURCE `1password`), next to any
   native ones from `keyflap password add`.

Only Login items are read. Only URLs that are `https://`, `http://` or a bare domain are
used; a login without one is never offered. If two logins (or a 1Password login and a
native one) cover the same site, the broker refuses rather than guess
(`ambiguous_credential`). An item with two one-time password fields is offered for its
password only (which code the site wants would be a guess).

### Service mode

The signer runs `op` only from a path nobody but root can change, exactly like `pass-cli`
(`@aab/sources` tool.ts, security review H3): `/opt/keyflap/tools/op/op`, `/usr/local/bin/op`
or `/usr/bin/op` (searched in that order, never your PATH), root-owned all the way up, and
with its SHA-256 pinned in `/etc/keyflap/signer.json`. Install it as root from 1Password's
apt/dnf repository or its signed release, never a copy from your home (on a Mac, `-g wheel`
in place of `-g root`):

```sh
sudo install -d -m 0755 /opt/keyflap/tools/op
sudo install -o root -g root -m 0755 <the verified op> /opt/keyflap/tools/op/op
```

After `op` updates, check the new binary is genuine and re-pin it with
`sudo keyflap password-source trust op` (until then the signer refuses it:
`source_tool_changed`, and `sudo keyflap doctor` says so). On Linux the token is sealed as a
systemd credential that only the signer service can read. On a Mac it is a 0400 file only
`_keyflap-signer` can read. It is never written to a config file. To choose 1Password at
install time, pick it in the one command, or run your release's `install.sh` (in
`/opt/keyflap-release/keyflap-<version>-<os>-<arch>/`) with:

```sh
sudo ./install.sh --approver-origin https://HOST:8766 \
  --password-source 1password --1password-vault Agent [--op-bin PATH] [--op-token-file FILE]
```

Without `--op-token-file` it prompts for the token (no echo). Re-running the installer
keeps the connected 1Password (tool, pin, vault and sealed token) unless you pass a flag. To
rotate the token, run `sudo keyflap password-source add 1password` again (it keeps the vault
and the tool), or re-run the installer with `--op-token-file`.

To connect 1Password on a machine that is already installed, without the installer:

```sh
sudo keyflap password-source add 1password --vault Agent
```

It reads the token without echo, checks it as the signer's user, seals it, opens the signer's
network and restarts the services. `sudo keyflap password-source remove` undoes it. The
console's Password managers section does the same. 1Password replaces Proton Pass if that is
connected, after asking. A token file you created for this should be `chmod 600` and deleted
afterwards. If the credential is missing the signer still starts, and every 1Password
read fails closed (`source_not_logged_in`).

## Request limits

Service accounts have request limits: per hour per token (1,000 reads on individual,
family and Teams plans; 10,000 on Business) and per day per account (1,000 on individual
and family plans; 5,000 Teams; 50,000 Business). The broker keeps to them by:

- addressing everything by vault id and item id (one request per `op item get`, about
  two for `op item list` in one vault, plus one for `op vault list`);
- re-reading the list every 30 minutes, and on a lookup miss at most every 5 minutes;
- reading an item again only when its version changed.

Every other tool using the same account counts toward the daily limit too. When a limit is
hit, `op` refuses and the broker fails closed: the audit log records
`source.sync_failed {reason: source_rate_limited}` and sign-ins with 1Password logins are
denied until the window passes.

## Gotchas

- **Token revoked or expired?** Sign-ins with 1Password logins are denied and the audit log
  records `source.sync_failed {reason: source_not_logged_in}`. Restart the daemon with a new
  token (service mode: `sudo keyflap password-source add 1password` with the new token).
- **Editing a login** takes effect at the next sign-in for the password, and within 30
  minutes for which sites it's offered on. Removing a URL stops it being filled there at
  once: the signer checks the live item every time. Archived items are not offered after
  the next sync.
- **Two vaults with the same name** and `--1password-vault`: the broker refuses
  (`source_vault_ambiguous`) rather than pick one. Rename one.
- Anyone who holds the same token can read the vaults it grants. The broker keeps the
  vault's secrets away from the agent; it does not keep them away from other local tools
  given the same token. A dedicated vault and service account for the broker avoid that.
- Same-user dev mode (`--unprotected`) protects nothing from a process running as you: the
  token is in the daemon's and signer's memory and in `op`'s environment while it runs.
