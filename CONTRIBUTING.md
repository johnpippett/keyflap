# Contributing to Keyflap

Thanks for helping. Keyflap holds people's passkeys and passwords, so the bar for changes
is high, especially for security-relevant code.

## Security issues

**Don't report a vulnerability in an issue or a pull request.** Follow
[SECURITY.md](SECURITY.md) to report it privately.

## Before you start

- Read [AGENTS.md](AGENTS.md) (layout, conventions, non-negotiables) and
  [ARCHITECTURE.md section 5](docs/ARCHITECTURE.md#5-security-invariants) (the security
  invariants).
- The invariants are fixed. A change must never weaken one to make a feature work. If an
  invariant is in your way, open an issue to discuss it first.
- Decisions and deviations from the design are recorded in
  [docs/IMPLEMENTATION_NOTES.md](docs/IMPLEMENTATION_NOTES.md). Record any new one there.
- For anything larger than a small fix, open an issue first so we can agree on the approach.

## Tests

Every invariant has an automated test, and a change that touches one must keep or extend
those tests. Name invariant tests so they're findable (`inv9-channel.test.ts`,
`describe('invariant 2: …')`).

Run before you open a pull request:

```sh
pnpm check            # typecheck, lint, all unit and e2e tests
pnpm test:isolation   # service mode in a throwaway systemd container (Linux + podman or docker)
```

`pnpm hooks:install` turns on a pre-push hook that runs typecheck, lint and the source
checks (`pnpm check:static`, a few seconds) before every push.

The isolation suite also runs on a real Mac against the real install, and removes Keyflap from
that Mac afterwards: `KEYFLAP_MAC=user@host packages/isolation/darwin/run-on-mac.sh` (see
[AGENTS.md](AGENTS.md)).

Tests use only the bundled test relying party (`packages/test-rp`) and the fake `pass-cli`
(`@aab/sources/testing`). **Never test against third-party sites or a real password vault.**
Never put real passwords, keys, tokens or one-time codes in code, tests, logs or issues.

## License

Contributions are accepted under the project's [license](LICENSE) (Apache-2.0): by
submitting a pull request, you agree that your contribution is licensed under it (section 5
of the license). There's no agreement to sign. You keep the copyright in your contribution.
