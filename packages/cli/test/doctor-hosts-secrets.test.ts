import { describe, expect, it } from 'vitest';
import type { Check } from '../src/doctor.ts';
import { hostChecks } from '../src/doctor-hosts.ts';
import { AGENT_ID, FakeSystem } from './setup-fakes.ts';

const SECRETS = {
  hermesYaml: 'sk-test-hermes-yaml-0000000000000000',
  hermesPlugin: 'tok-test-hermes-plugin-1111111111111',
  codexHooks: 'tok-test-codex-hooks-2222222222222222',
  codexToml: 'sk-test-codex-toml-3333333333333333',
};

function hermes(backend: string): FakeSystem {
  return new FakeSystem()
    .dir('/home/u/.hermes', 0o700)
    .file('/home/u/.hermes/plugins/keyflap-intent/__init__.py', '')
    .file(
      '/home/u/.hermes/plugins/keyflap-intent/config.json',
      JSON.stringify({ agent: AGENT_ID, owners: ['telegram:1'], token: SECRETS.hermesPlugin }),
    )
    .file(
      '/home/u/.hermes/config.yaml',
      [
        `api_key: ${SECRETS.hermesYaml}`,
        'plugins:',
        '  enabled:',
        '    - keyflap-intent',
        'terminal:',
        `  backend: ${backend}`,
        `  env: { KEYFLAP_AGENT_TOKEN: ${SECRETS.hermesYaml} }`,
        '',
      ].join('\n'),
    );
}

function codex(denyDir: boolean): FakeSystem {
  return new FakeSystem()
    .file(
      '/home/u/.codex/hooks.json',
      JSON.stringify({
        hooks: {
          UserPromptSubmit: [
            {
              hooks: [
                {
                  type: 'command',
                  command: `node /m.ts hook codex --agent ${AGENT_ID}`,
                  env: { KEYFLAP_AGENT_TOKEN: SECRETS.codexHooks },
                },
              ],
            },
          ],
        },
      }),
    )
    .file(
      '/home/u/.codex/config.toml',
      [
        `api_key = "${SECRETS.codexToml}"`,
        ...(denyDir
          ? [
              'default_permissions = "keyflap-protected"',
              '[permissions.keyflap-protected.filesystem]',
              '"~/.keyflap" = "deny"',
            ]
          : []),
        '',
      ].join('\n'),
    );
}

function report(sys: FakeSystem): Check[] {
  return hostChecks({
    sys,
    read: (p) => sys.readUserFile(p, { uid: 1000, gid: 1000 }),
    home: '/home/u',
    denyDir: '/home/u/.keyflap',
    agents: [{ id: AGENT_ID, name: 'h', revoked: false }],
  });
}

describe('doctor host checks read config text and never print a token from it', () => {
  it('Hermes and Codex reports, passing and failing, hold no secret from the config files', () => {
    const checks = [
      ...report(hermes('docker')),
      ...report(hermes('local')),
      ...report(codex(true)),
      ...report(codex(false)),
    ];
    expect(checks.map((c) => c.status)).toEqual([
      'ok',
      'ok',
      'ok',
      'ok',
      'fail',
      'ok',
      'ok',
      'ok',
      'ok',
      'fail',
    ]);
    const text = JSON.stringify(checks);
    for (const secret of Object.values(SECRETS)) expect(text).not.toContain(secret);
  });
});
