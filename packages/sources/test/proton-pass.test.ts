import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  loginHosts,
  ProtonPassSource,
  parseProtonRef,
  parseTotpUri,
  protonRef,
  SourceError,
} from '../src/index.ts';
import { type FakeVaultFile, fakePassCli } from './fake.ts';

const SAME_USER = { mode: 'same-user' } as const;
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const PW_A = 'alpha-Secr3t-password';
const PW_B = 'bravo-Secr3t-password';
const PW_OTHER = 'other-vault-password';

function vault(): FakeVaultFile {
  return {
    loggedIn: true,
    vaults: [
      {
        name: 'Agent',
        share_id: 'SHARE_agent==',
        vault_id: 'V1',
        items: [
          {
            id: '-itemA_x==',
            title: 'Example',
            modify_time: '2026-10-01T00:00:00',
            login: {
              username: 'alice',
              password: PW_A,
              urls: ['https://login.example.com/signin', 'example.org', 'android://com.x.app'],
              totp_uri: `otpauth://totp/Example:alice?secret=${SEED}&issuer=Example`,
            },
          },
          {
            id: 'itemB',
            title: 'Bravo',
            login: { email: 'bob@mail.test', password: PW_B, urls: ['https://bravo.test'] },
          },
          { id: 'trashed', title: 'Old', state: 'Trashed', login: { password: 'old-pass' } },
          { id: 'note1', title: 'A note', item_type: 'note' },
        ],
      },
      {
        name: 'Personal',
        share_id: 'SHARE_personal',
        vault_id: 'V2',
        items: [{ id: 'itemP', title: 'P', login: { password: PW_OTHER, urls: ['p.test'] } }],
      },
    ],
  };
}

const views = (f: ReturnType<typeof fakePassCli>) =>
  f.calls().filter((c) => c.argv[0] === 'item' && c.argv[1] === 'view');

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    expect(err).toBeInstanceOf(SourceError);
    return (err as SourceError).reason;
  }
  throw new Error('expected a SourceError');
}

describe('Proton Pass source (fake pass-cli)', () => {
  it('lists active logins with hosts, username and TOTP presence, and nothing secret', async () => {
    const f = fakePassCli(vault());
    const src = new ProtonPassSource({ bin: f.bin, trust: SAME_USER, env: f.env, vault: 'Agent' });
    const items = await src.list();
    expect(items).toEqual([
      {
        ref: 'proton-pass:SHARE_agent==:-itemA_x==',
        hosts: ['login.example.com', 'example.org'],
        username: 'alice',
        hasTotp: true,
      },
      {
        ref: 'proton-pass:SHARE_agent==:itemB',
        hosts: ['bravo.test'],
        username: 'bob@mail.test',
        hasTotp: false,
      },
    ]);
    const text = JSON.stringify(items);
    for (const s of [PW_A, PW_B, SEED, PW_OTHER]) expect(text).not.toContain(s);
  });

  it('passes ids as --flag=value (they can start with "-") and states its reason', async () => {
    const f = fakePassCli(vault());
    await new ProtonPassSource({ bin: f.bin, trust: SAME_USER, env: f.env, vault: 'Agent' }).list();
    const v = views(f);
    expect(v).toHaveLength(2);
    expect(v.flatMap((c) => c.argv)).toContain('--item-id=-itemA_x==');
    expect(v.every((c) => c.reason?.startsWith('Keyflap broker:'))).toBe(true);
  });

  it('gives pass-cli only PATH, the configured env and its own settings', async () => {
    const f = fakePassCli(vault());
    process.env.KEYFLAP_TEST_LEAK = 'leak';
    try {
      await new ProtonPassSource({
        bin: f.bin,
        trust: SAME_USER,
        env: f.env,
        vault: 'Agent',
      }).list();
    } finally {
      delete process.env.KEYFLAP_TEST_LEAK;
    }
    const env = new Set(f.calls().flatMap((c) => c.env));
    expect(env.has('KEYFLAP_TEST_LEAK')).toBe(false);
    expect(env.has('HOME')).toBe(false);
    expect([...env].filter((k) => k.startsWith('PROTON_PASS_')).sort()).toEqual([
      'PROTON_PASS_AGENT_REASON',
      'PROTON_PASS_NO_UPDATE_CHECK',
      'PROTON_PASS_SESSION_DIR',
    ]);
  });

  it('without a vault name reads every vault the session sees; an unknown name fails', async () => {
    const f = fakePassCli(vault());
    const all = await new ProtonPassSource({ bin: f.bin, trust: SAME_USER, env: f.env }).list();
    expect(all.map((i) => i.ref)).toContain('proton-pass:SHARE_personal:itemP');
    const bad = new ProtonPassSource({ bin: f.bin, trust: SAME_USER, env: f.env, vault: 'Nope' });
    expect(await reason(bad.list())).toBe('source_vault_not_found');
  });

  it('views an item again only when its modify_time changed, and drops deleted ones', async () => {
    const f = fakePassCli(vault());
    const src = new ProtonPassSource({ bin: f.bin, trust: SAME_USER, env: f.env, vault: 'Agent' });
    await src.list();
    expect(views(f)).toHaveLength(2);
    await src.list();
    expect(views(f)).toHaveLength(2);
    f.update((d) => {
      const it = d.vaults[0]?.items.find((i) => i.id === 'itemB');
      if (it?.login) {
        it.login.urls = ['https://bravo2.test'];
        it.modify_time = '2026-10-02T00:00:00';
      }
      d.vaults[0]?.items.splice(0, 1);
    });
    const items = await src.list();
    expect(views(f)).toHaveLength(3);
    expect(items).toEqual([expect.objectContaining({ hosts: ['bravo2.test'] })]);
  });

  it('fetches the password and TOTP parameters of one item', async () => {
    const f = fakePassCli(vault());
    const src = new ProtonPassSource({ bin: f.bin, trust: SAME_USER, env: f.env });
    const s = await src.fetch('proton-pass:SHARE_agent==:-itemA_x==', 'Keyflap broker: test');
    expect(s).toEqual({
      hosts: ['login.example.com', 'example.org'],
      password: PW_A,
      totp: { secret: SEED },
    });
    expect(views(f).at(-1)?.reason).toBe('Keyflap broker: test');
  });

  it('refuses trashed items, non-logins, bad refs and missing items', async () => {
    const f = fakePassCli(vault());
    const src = new ProtonPassSource({ bin: f.bin, trust: SAME_USER, env: f.env });
    expect(await reason(src.fetch('proton-pass:SHARE_agent==:trashed', 'r'))).toBe(
      'source_item_inactive',
    );
    expect(await reason(src.fetch('proton-pass:SHARE_agent==:note1', 'r'))).toBe(
      'source_not_a_login',
    );
    expect(await reason(src.fetch('proton-pass:SHARE_agent==:gone', 'r'))).toBe(
      'source_item_not_found',
    );
    for (const bad of ['other:SHARE_agent==:itemB', 'proton-pass:a/b:c', 'proton-pass:a:b:c']) {
      expect(await reason(src.fetch(bad, 'r'))).toBe('bad_ref');
    }
  });

  it('maps failures to fixed reasons without the CLI output', async () => {
    const f = fakePassCli({ ...vault(), loggedIn: false });
    const src = new ProtonPassSource({ bin: f.bin, trust: SAME_USER, env: f.env });
    let caught: unknown;
    try {
      await src.list();
    } catch (err) {
      caught = err;
    }
    expect((caught as SourceError).reason).toBe('source_not_logged_in');
    expect(String((caught as Error).message)).toBe('source_not_logged_in');

    const missing = new ProtonPassSource({
      bin: join(f.dir, 'no-such-pass-cli'),
      trust: SAME_USER,
      env: f.env,
    });
    expect(await reason(missing.list())).toBe('source_unavailable');

    const g = fakePassCli(vault());
    writeFileSync(join(g.dir, 'hang'), '');
    const slow = new ProtonPassSource({
      bin: g.bin,
      trust: SAME_USER,
      env: g.env,
      timeoutMs: 1_500,
    });
    expect(await reason(slow.list())).toBe('source_timeout');
  });

  it('refs round-trip and reject anything else', () => {
    const ref = protonRef('S-1_=', '-I');
    expect(parseProtonRef(ref)).toEqual({ shareId: 'S-1_=', itemId: '-I' });
    expect(parseProtonRef('proton-pass:S')).toBeNull();
    expect(parseProtonRef('proton-pass:S:I x')).toBeNull();
    expect(() => protonRef('a:b', 'c')).toThrow(SourceError);
  });

  it('loginHosts keeps http(s) and scheme-less hosts only', () => {
    expect(
      loginHosts([
        'https://Login.Example.com/x',
        'http://a.test:8080',
        'example.org',
        'android://com.app',
        'ftp://f.test',
        'https://10.0.0.1/',
        'localhost',
        '',
        42,
      ]),
    ).toEqual(['login.example.com', 'a.test', 'example.org']);
  });

  it('parseTotpUri reads otpauth://totp URIs and bare secrets', () => {
    expect(
      parseTotpUri(`otpauth://totp/X?secret=${SEED}&algorithm=sha256&digits=8&period=60`),
    ).toEqual({
      secret: SEED,
      algorithm: 'SHA256',
      digits: 8,
      period: 60,
    });
    expect(parseTotpUri(SEED)).toEqual({ secret: SEED });
    expect(parseTotpUri('')).toBeNull();
    expect(parseTotpUri('otpauth://hotp/X?secret=AAAA')).toBeNull();
    expect(parseTotpUri('otpauth://totp/X')).toBeNull();
  });
});
