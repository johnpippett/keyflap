import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { tmpDir } from './helpers.ts';

type ListFile = 'readable' | 'unreadable' | 'empty' | 'truncated';

const realText = readFileSync(
  new URL('../src/psl/public_suffix_list.dat', import.meta.url),
  'utf8',
);

async function loadWith(list: ListFile) {
  vi.resetModules();
  vi.doMock('node:fs', async (importOriginal) => {
    const real = await importOriginal<typeof import('node:fs')>();
    const read = real.readFileSync as (...a: unknown[]) => unknown;
    return {
      ...real,
      readFileSync: (path: unknown, ...rest: unknown[]) => {
        if (!String(path).endsWith('public_suffix_list.dat')) return read(path, ...rest);
        if (list === 'unreadable') throw new Error('EACCES: permission denied');
        if (list === 'empty') return '';
        if (list === 'truncated') return realText.slice(0, realText.length / 2);
        return realText;
      },
    };
  });
  const [psl, risk, server, keystore] = await Promise.all([
    import('../src/psl.ts'),
    import('../src/risk.ts'),
    import('../src/server.ts'),
    import('../src/keystore.ts'),
  ]);
  const startHandler = () =>
    new server.SignerHandler({
      store: keystore.KeyStore.open(join(tmpDir(), 'keys'), 'pw'),
      trustedApproverKeys: {},
    });
  return { psl, risk, startHandler };
}

describe('the signer public suffix list fails closed', () => {
  afterEach(() => {
    vi.doUnmock('node:fs');
    vi.resetModules();
  });

  it.each(['unreadable', 'empty', 'truncated'] as const)(
    '%s list: no registrable domain, no rpId allowed, every host high-risk, no signer starts',
    async (list) => {
      const { psl, risk, startHandler } = await loadWith(list);
      expect(psl.registrableDomain('www.example.com')).toBeNull();
      expect(psl.registrableDomain('example.com')).toBeNull();
      expect(psl.rpIdAllowedForHost('example.com', 'example.com')).toBe(false);
      expect(psl.rpIdAllowedForHost('example.com', 'www.example.com')).toBe(false);
      expect(risk.isHighRisk('www.example.com')).toBe(true);
      expect(risk.isHighRisk('example.com')).toBe(true);
      expect(risk.isHighRiskOrigin('https://example.com')).toBe(true);
      expect(() => psl.loadPublicSuffixList()).toThrow();
      expect(startHandler).toThrow();
    },
  );

  it('control: the same harness with a readable list answers normally and a signer starts', async () => {
    const { psl, risk, startHandler } = await loadWith('readable');
    expect(psl.registrableDomain('www.example.com')).toBe('example.com');
    expect(psl.rpIdAllowedForHost('example.com', 'www.example.com')).toBe(true);
    expect(risk.isHighRisk('www.example.com')).toBe(false);
    expect(startHandler).not.toThrow();
  });
});
