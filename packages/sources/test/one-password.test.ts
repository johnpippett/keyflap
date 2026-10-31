import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  OnePasswordSource,
  onePasswordRef,
  parseOnePasswordRef,
  SourceError,
} from '../src/index.ts';
import { type FakeOpAccount, fakeOp } from './fake.ts';

const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const PW_A = 'alpha-Secr3t-password';
const PW_B = 'bravo-Secr3t-password';
const PW_OTHER = 'other-vault-password';
const TOKEN = 'ops_fakeServiceAccountToken_DO_NOT_LEAK';

const V_AGENT = 'agentvault0000000000000000';
const V_PERSONAL = 'personalvault0000000000000';
const I_A = 'itema000000000000000000000';
const I_B = 'itemb000000000000000000000';
const I_ARCH = 'itemarchived00000000000000';
const I_NOTE = 'itemnote000000000000000000';
const I_TWO_OTP = 'itemtwootp0000000000000000';
const I_P = 'itemp000000000000000000000';

function account(): FakeOpAccount {
  return {
    token: TOKEN,
    vaults: [
      {
        id: V_AGENT,
        name: 'Agent',
        items: [
          {
            id: I_A,
            title: 'Example',
            username: 'alice',
            password: PW_A,
            urls: ['https://login.example.com/signin', 'example.org', 'android://com.x.app'],
            otp: [`otpauth://totp/Example:alice?secret=${SEED}&issuer=Example`],
          },
          {
            id: I_B,
            title: 'Bravo',
            username: 'bob@mail.test',
            password: PW_B,
            urls: ['https://bravo.test'],
          },
          { id: I_ARCH, title: 'Old', archived: true, password: 'old-pass', urls: ['old.test'] },
          { id: I_NOTE, title: 'A note', category: 'SECURE_NOTE' },
          {
            id: I_TWO_OTP,
            title: 'Two codes',
            username: 'carol',
            password: 'carol-password',
            urls: ['https://two.test'],
            otp: [`otpauth://totp/A?secret=${SEED}`, 'otpauth://totp/B?secret=AAAAAAAAAAAAAAAA'],
          },
        ],
      },
      {
        id: V_PERSONAL,
        name: 'Personal',
        items: [{ id: I_P, title: 'P', password: PW_OTHER, urls: ['p.test'] }],
      },
    ],
  };
}

const gets = (f: ReturnType<typeof fakeOp>) =>
  f.calls().filter((c) => c.argv[0] === 'item' && c.argv[1] === 'get');

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    expect(err).toBeInstanceOf(SourceError);
    expect((err as Error).message).toBe((err as SourceError).reason);
    return (err as SourceError).reason;
  }
  throw new Error('expected a SourceError');
}

describe('1Password source (fake op)', () => {
  it('lists active logins with hosts, username and TOTP presence, and nothing secret', async () => {
    const f = fakeOp(account());
    const src = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: f.bin,
      env: f.env,
      vault: 'Agent',
    });
    const items = await src.list();
    expect(items).toEqual([
      {
        ref: `1password:${V_AGENT}:${I_A}`,
        hosts: ['login.example.com', 'example.org'],
        username: 'alice',
        hasTotp: true,
      },
      {
        ref: `1password:${V_AGENT}:${I_B}`,
        hosts: ['bravo.test'],
        username: 'bob@mail.test',
        hasTotp: false,
      },
      {
        ref: `1password:${V_AGENT}:${I_TWO_OTP}`,
        hosts: ['two.test'],
        username: 'carol',
        hasTotp: false,
      },
    ]);
    const text = JSON.stringify(items);
    for (const s of [PW_A, PW_B, SEED, PW_OTHER, TOKEN]) expect(text).not.toContain(s);
  });

  it('matching never asks op to reveal, and addresses items by vault id + item id', async () => {
    const f = fakeOp(account());
    await new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: f.bin,
      env: f.env,
      vault: 'Agent',
    }).list();
    const g = gets(f);
    expect(g).toHaveLength(3);
    for (const c of g) {
      expect(c.argv).not.toContain('--reveal');
      expect(c.argv).toContain(`--vault=${V_AGENT}`);
    }
    expect(f.calls().find((c) => c.argv[1] === 'list' && c.argv[0] === 'item')?.argv).toEqual([
      'item',
      'list',
      `--vault=${V_AGENT}`,
      '--categories=Login',
      '--format=json',
    ]);
  });

  it('gives op only PATH, the configured env and its own settings; the token never in argv', async () => {
    const f = fakeOp(account());
    process.env.KEYFLAP_TEST_LEAK = 'leak';
    process.env.OP_CONNECT_TOKEN = 'connect-token';
    try {
      const src = new OnePasswordSource({
        trust: { mode: 'same-user' },
        bin: f.bin,
        env: f.env,
        vault: 'Agent',
      });
      await src.list();
      await src.fetch(`1password:${V_AGENT}:${I_A}`, 'r');
    } finally {
      delete process.env.KEYFLAP_TEST_LEAK;
      delete process.env.OP_CONNECT_TOKEN;
    }
    const env = new Set(f.calls().flatMap((c) => c.env));
    expect(env.has('KEYFLAP_TEST_LEAK')).toBe(false);
    expect(env.has('HOME')).toBe(false);
    expect([...env].filter((k) => k.startsWith('OP_')).sort()).toEqual([
      'OP_BIOMETRIC_UNLOCK_ENABLED',
      'OP_CACHE',
      'OP_SERVICE_ACCOUNT_TOKEN',
    ]);
    for (const c of f.calls()) expect(c.argv.join(' ')).not.toContain(TOKEN);
  });

  it('without a vault name reads every vault; an unknown or duplicated name fails', async () => {
    const f = fakeOp(account());
    const all = await new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: f.bin,
      env: f.env,
    }).list();
    expect(all.map((i) => i.ref)).toContain(`1password:${V_PERSONAL}:${I_P}`);
    const bad = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: f.bin,
      env: f.env,
      vault: 'Nope',
    });
    expect(await reason(bad.list())).toBe('source_vault_not_found');
    f.update((d) => {
      d.vaults.push({ id: 'agentvault1111111111111111', name: 'Agent', items: [] });
    });
    const dup = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: f.bin,
      env: f.env,
      vault: 'Agent',
    });
    expect(await reason(dup.list())).toBe('source_vault_ambiguous');
  });

  it('reads an item again only when its version changed, and drops deleted ones', async () => {
    const f = fakeOp(account());
    const src = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: f.bin,
      env: f.env,
      vault: 'Agent',
    });
    await src.list();
    expect(gets(f)).toHaveLength(3);
    await src.list();
    expect(gets(f)).toHaveLength(3);
    f.update((d) => {
      const it = d.vaults[0]?.items.find((i) => i.id === I_B);
      if (it) {
        it.urls = ['https://bravo2.test'];
        it.version = 2;
      }
      d.vaults[0]?.items.splice(0, 1);
    });
    const items = await src.list();
    expect(gets(f)).toHaveLength(4);
    expect(items.map((i) => i.hosts)).toEqual([['bravo2.test'], ['two.test']]);
  });

  it('fetches the password and the TOTP seed (never the current code) with --reveal', async () => {
    const f = fakeOp(account());
    const src = new OnePasswordSource({ trust: { mode: 'same-user' }, bin: f.bin, env: f.env });
    const s = await src.fetch(`1password:${V_AGENT}:${I_A}`, 'Keyflap broker: test');
    expect(s).toEqual({
      hosts: ['login.example.com', 'example.org'],
      password: PW_A,
      totp: { secret: SEED },
    });
    expect(gets(f).at(-1)?.argv).toEqual([
      'item',
      'get',
      I_A,
      `--vault=${V_AGENT}`,
      '--format=json',
      '--reveal',
    ]);
    const two = await src.fetch(`1password:${V_AGENT}:${I_TWO_OTP}`, 'r');
    expect(two.totp).toBeNull();
    const none = await src.fetch(`1password:${V_AGENT}:${I_B}`, 'r');
    expect(none).toEqual({ hosts: ['bravo.test'], password: PW_B, totp: null });
  });

  it('refuses archived items, non-logins, bad refs, missing items and answers for another item', async () => {
    const f = fakeOp(account());
    const src = new OnePasswordSource({ trust: { mode: 'same-user' }, bin: f.bin, env: f.env });
    expect(await reason(src.fetch(`1password:${V_AGENT}:${I_ARCH}`, 'r'))).toBe(
      'source_item_inactive',
    );
    expect(await reason(src.fetch(`1password:${V_AGENT}:${I_NOTE}`, 'r'))).toBe(
      'source_not_a_login',
    );
    expect(await reason(src.fetch(`1password:${V_AGENT}:${'z'.repeat(26)}`, 'r'))).toBe(
      'source_item_not_found',
    );
    expect(await reason(src.fetch(`1password:${V_AGENT}:${I_P}`, 'r'))).toBe(
      'source_item_not_found',
    );
    expect(await reason(src.fetch(`1password:${'y'.repeat(26)}:${I_A}`, 'r'))).toBe(
      'source_vault_not_found',
    );
    for (const bad of [
      `proton-pass:${V_AGENT}:${I_A}`,
      `1password:${V_AGENT}`,
      `1password:${V_AGENT}:${I_A}:x`,
      `1password:${V_AGENT}:-${I_A.slice(1)}`,
      `1password:${V_AGENT}:${I_A}x`,
      `1password:${V_AGENT}:Example`,
      `1password:Agent:${I_A}`,
    ]) {
      expect(await reason(src.fetch(bad, 'r'))).toBe('bad_ref');
    }
    expect(gets(f).some((c) => c.argv[2] === 'Example')).toBe(false);
  });

  it('maps failures to fixed reasons without the CLI output', async () => {
    const f = fakeOp(account());
    const wrong = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: f.bin,
      env: { ...f.env, OP_SERVICE_ACCOUNT_TOKEN: 'ops_wrong' },
    });
    expect(await reason(wrong.list())).toBe('source_not_logged_in');
    const noToken = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: f.bin,
      env: { KEYFLAP_FAKE_OP_DIR: f.dir },
    });
    expect(await reason(noToken.fetch(`1password:${V_AGENT}:${I_A}`, 'r'))).toBe(
      'source_not_logged_in',
    );

    const missing = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: join(f.dir, 'no-such-op'),
      env: f.env,
    });
    expect(await reason(missing.list())).toBe('source_unavailable');

    const g = fakeOp(account());
    writeFileSync(join(g.dir, 'garbage'), '');
    const garbled = new OnePasswordSource({ trust: { mode: 'same-user' }, bin: g.bin, env: g.env });
    expect(await reason(garbled.list())).toBe('source_bad_output');
    expect(await reason(garbled.fetch(`1password:${V_AGENT}:${I_A}`, 'r'))).toBe(
      'source_bad_output',
    );

    const r = fakeOp(account());
    writeFileSync(join(r.dir, 'ratelimit'), '');
    const limited = new OnePasswordSource({ trust: { mode: 'same-user' }, bin: r.bin, env: r.env });
    expect(await reason(limited.list())).toBe('source_rate_limited');

    const u = fakeOp(account());
    writeFileSync(join(u.dir, 'undecodable'), '');
    const malformed = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: u.bin,
      env: u.env,
    });
    expect(await reason(malformed.list())).toBe('source_not_logged_in');
    expect(await reason(malformed.fetch(`1password:${V_AGENT}:${I_A}`, 'r'))).toBe(
      'source_not_logged_in',
    );

    const h = fakeOp(account());
    writeFileSync(join(h.dir, 'hang'), '');
    const slow = new OnePasswordSource({
      trust: { mode: 'same-user' },
      bin: h.bin,
      env: h.env,
      timeoutMs: 1_500,
    });
    expect(await reason(slow.fetch(`1password:${V_AGENT}:${I_A}`, 'r'))).toBe('source_timeout');
  });

  it('refs round-trip and reject anything else', () => {
    const ref = onePasswordRef(V_AGENT, I_A);
    expect(ref).toBe(`1password:${V_AGENT}:${I_A}`);
    expect(parseOnePasswordRef(ref)).toEqual({ vaultId: V_AGENT, itemId: I_A });
    expect(parseOnePasswordRef('1password:x')).toBeNull();
    expect(parseOnePasswordRef(42)).toBeNull();
    expect(() => onePasswordRef('a:b', I_A)).toThrow(SourceError);
    expect(() => onePasswordRef(V_AGENT, 'short')).toThrow(SourceError);
  });
});
