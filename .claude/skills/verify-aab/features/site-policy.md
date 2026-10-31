# Site policy

The user sets per-site rules with `keyflap policy`. A deny rule stops sign-ins on a site with no prompt, and the denial is audited. Rules apply while the daemon runs.

## Sub-features

- `policy-deny` `keyflap policy set <site> --deny` makes `auth_login` return `denied` with no approval prompt.
- `policy-list` `keyflap policy list --json` shows the rule. `keyflap policy remove <site>` restores the default.
- `policy-audit` the audit trail has `policy.set`, `denied` with `reason: policy_deny`, and `policy.removed`.

## How to get to it (user POV)

- Run `keyflap policy set rp.localhost --deny`, then ask the agent to sign in.
- Run `keyflap policy list` and `keyflap policy remove rp.localhost`.

## Driving it with verify-aab

Preconditions:

- `scripts/doctor.sh` printed `RESULT doctor PASS`.
- No rule exists for `rp.localhost` (`keyflap policy list --json` is empty).

- **Run all of it.** `scripts/drive.sh policy`. Exit code `0`.
- **Deny.** `keyflap policy set rp.localhost --deny --data-dir <sandbox>/data` exits `0`. Open `<rp>password/login`, record an intent, call `auth_login`. The tool returns `{"status":"denied"}`. After one second the daemon's stdout has no new prompt block. The snapshot does not say `Signed in as`.
- **List and remove.** `keyflap policy list --json` mentions `rp.localhost` and `deny`. `keyflap policy remove rp.localhost` exits `0`. The next `policy list --json` no longer mentions it.
- **Audit.** `keyflap audit tail --json` has `policy.set`, `denied` with `reason: policy_deny`, `policy.removed`. `keyflap audit verify` exits `0`.
- **Proof.** `<evidence dir>/policy/`: `snapshot-after-deny.txt`, `policy-list.json`, `steps.jsonl`, `audit-tail.json`, `audit-verify.txt`.

## Gotchas

- Not driven: `--ask`, `--ask-strong`, `--allow-for`, `--session-ttl`, and per-agent rules. `--ask-strong` and high-risk sites need a phone approver, which this stack does not have (the terminal approver denies them with `user_verification_unavailable`). `--allow-for` needs a signed approval; its behavior is covered by `packages/signer/test/inv6-policy-grants.test.ts`.
- The rule is read on every request, so no restart is needed. Run `policy remove` before the next feature, or later features on the same stack will be denied. The script does this.
- Use `--data-dir` of the sandbox, or you would edit the live rules in `~/.keyflap` (or `~/.aab`). `drive.mjs` and the `keyflap` helper in `lib.sh` do.
