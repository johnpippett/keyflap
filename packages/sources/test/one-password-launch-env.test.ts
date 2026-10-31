import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { OnePasswordSource } from '../src/index.ts';
import { type FakeOpAccount, fakeOp } from './fake.ts';

const ENV_PROBE = fileURLToPath(new URL('./fake-op-env-probe.ts', import.meta.url));
const TOKEN = 'ops_fakeServiceAccountToken_DO_NOT_LEAK';
const VAULT = 'agentvault0000000000000000';
const ITEM = 'itema000000000000000000000';

function account(): FakeOpAccount {
  return {
    token: TOKEN,
    vaults: [
      {
        id: VAULT,
        name: 'Agent',
        items: [
          { id: ITEM, title: 'Example', username: 'alice', password: 'pw', urls: ['example.org'] },
        ],
      },
    ],
  };
}

describe('1Password source: op runs with no cache daemon and no desktop-app integration', () => {
  it('sets OP_CACHE and OP_BIOMETRIC_UNLOCK_ENABLED to false on every launch, whatever the configured env says', async () => {
    const f = fakeOp(account());
    const src = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: ENV_PROBE,
      env: { ...f.env, OP_CACHE: 'true', OP_BIOMETRIC_UNLOCK_ENABLED: 'true' },
      vault: 'Agent',
    });
    await src.list();
    await src.fetch(`1password:${VAULT}:${ITEM}`, 'r');

    const launches = readFileSync(join(f.dir, 'env-values.jsonl'), 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as Record<string, string | null>);
    expect(launches.length).toBeGreaterThanOrEqual(3);
    for (const env of launches) {
      expect(env).toEqual({ OP_CACHE: 'false', OP_BIOMETRIC_UNLOCK_ENABLED: 'false' });
    }
  });
});
