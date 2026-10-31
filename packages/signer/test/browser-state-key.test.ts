import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { KeyStore } from '../src/keystore.ts';
import type { BrowserStateKeyResult } from '../src/protocol.ts';
import { SignerHandler } from '../src/server.ts';
import { tmpDir } from './helpers.ts';

function keyOf(handler: SignerHandler): string {
  const res = handler.handle({ op: 'browser_state_key' });
  if (!res.ok) throw new Error(res.error);
  return (res.result as BrowserStateKeyResult).key;
}

describe('browser_state_key', () => {
  it('is 32 random bytes, stable across a restart of the same store', () => {
    const path = join(tmpDir(), 'keys');
    const first = keyOf(
      new SignerHandler({ store: KeyStore.open(path, 'pw'), trustedApproverKeys: {} }),
    );
    expect(Buffer.from(first, 'base64url')).toHaveLength(32);
    const handler = new SignerHandler({
      store: KeyStore.open(path, 'pw'),
      trustedApproverKeys: {},
    });
    expect(keyOf(handler)).toBe(first);
    expect(keyOf(handler)).toBe(first);
    const onDisk = readFileSync(path, 'utf8');
    expect(onDisk).not.toContain(first);
    expect(onDisk).not.toContain(Buffer.from(first, 'base64url').toString('base64'));
  });

  it('a different store gives a different key', () => {
    const a = keyOf(
      new SignerHandler({
        store: KeyStore.open(join(tmpDir(), 'keys'), 'pw'),
        trustedApproverKeys: {},
      }),
    );
    const b = keyOf(
      new SignerHandler({
        store: KeyStore.open(join(tmpDir(), 'keys'), 'pw'),
        trustedApproverKeys: {},
      }),
    );
    expect(a).not.toBe(b);
  });

  it('logs no key material', () => {
    const lines: string[] = [];
    const handler = new SignerHandler({
      store: KeyStore.open(join(tmpDir(), 'keys'), 'pw'),
      trustedApproverKeys: {},
      log: (e, f) => lines.push(JSON.stringify({ e, f })),
    });
    const key = keyOf(handler);
    expect(lines.join('\n')).not.toContain(key);
  });
});
