## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## Checklist

- [ ] `pnpm check` passes (and `pnpm test:isolation` if service mode is touched).
- [ ] No security invariant (ARCHITECTURE.md section 5) is weakened; changed or new
      invariant behavior has an automated test.
- [ ] Tests use only the local test RP and the fake `pass-cli`, never third-party sites
      or real vaults.
- [ ] No secrets (passwords, keys, tokens, one-time codes) in code, tests, logs or this PR.
- [ ] Any new deviation from the design is recorded in `docs/IMPLEMENTATION_NOTES.md`.

<!-- Security vulnerabilities: don't open a PR. See SECURITY.md. -->
