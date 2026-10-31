import { existsSync, readFileSync } from 'node:fs';
import { type FakeOp, type FakeOpAccount, fakeOp } from '@aab/sources/testing';
import { totp } from '@aab/test-rp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CredentialRepo } from '../src/db.ts';
import { dbPath, type McpHarness, startMcpHarness } from './mcp-harness.ts';

const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const ALICE_PW = 'alice-1Password/pass word+%&?';
const OTHER_PW = 'other-site-password-8Rz';
const TOKEN = 'ops_eyJfakeServiceAccountTokenForTests';
const VAULT = 'agentvault0000000000000000';
const ITEM = 'aliceitem00000000000000000';
const OTHER = 'otheritem00000000000000000';
const REF = `1password:${VAULT}:${ITEM}`;

function codesAround(seed: string): string[] {
  const now = Date.now();
  const out: string[] = [];
  for (let i = -5; i <= 5; i++) out.push(totp(seed, now + i * 30_000));
  return out;
}

function forms(secret: string): string[] {
  return [
    secret,
    JSON.stringify(secret).slice(1, -1),
    encodeURIComponent(secret),
    new URLSearchParams({ v: secret }).toString().slice(2),
    Buffer.from(secret).toString('base64'),
  ];
}

function contains(haystack: string, needle: string): boolean {
  if (!/^\d+$/.test(needle)) return haystack.includes(needle);
  return new RegExp(`(?<![0-9])${needle}(?![0-9])`).test(haystack);
}

function expectNoSecrets(haystack: string, secrets: string[], where: string) {
  for (const s of secrets) {
    for (const f of forms(s)) expect(contains(haystack, f), `${f} in ${where}`).toBe(false);
  }
}

describe('1Password logins through MCP (fake op)', () => {
  let h: McpHarness;
  let fake: FakeOp;
  const signerLog: string[] = [];

  const accountFor = (rpUrl: string): FakeOpAccount => ({
    token: TOKEN,
    vaults: [
      {
        id: VAULT,
        name: 'Agent',
        items: [
          {
            id: ITEM,
            title: 'Test RP',
            username: 'alice',
            password: ALICE_PW,
            urls: [`${rpUrl}password/login`],
            otp: [`otpauth://totp/RP:alice?secret=${SEED}`],
          },
          {
            id: OTHER,
            title: 'Other site',
            username: 'zed',
            password: OTHER_PW,
            urls: ['https://other.test/'],
          },
        ],
      },
      {
        id: 'personalvault0000000000000',
        name: 'Personal',
        items: [
          {
            id: 'pitem000000000000000000000',
            title: 'P',
            password: 'personal-pw-1',
            urls: ['p.test'],
          },
        ],
      },
    ],
  });

  beforeAll(async () => {
    fake = fakeOp({ token: TOKEN, vaults: [{ id: VAULT, name: 'Agent', items: [] }] });
    h = await startMcpHarness({
      agentName: 'op-agent',
      rp: { users: [{ username: 'alice', password: ALICE_PW, totpSecret: SEED }] },
      daemon: {
        passwordSource: {
          kind: '1password',
          bin: fake.bin,
          env: fake.env,
          vault: 'Agent',
          retryMs: 0,
        },
        onSignerLog: (l) => signerLog.push(l),
      },
    });
    await h.daemon.sourceSync?.refresh().catch(() => {});
    fake.write(accountFor(h.rp.url));
    await h.daemon.sourceSync?.refresh();
  });
  afterAll(async () => h?.close());

  it('mirrors the vault: one row per registrable domain, only the named vault', () => {
    const rows = new CredentialRepo(h.daemon.db)
      .sourcePasswords('1password')
      .sort((a, b) => a.registrable_domain.localeCompare(b.registrable_domain));
    expect(rows.map((r) => [r.registrable_domain, r.username, r.has_totp, r.signer_ref])).toEqual([
      ['other.test', 'zed', 0, `1password:${VAULT}:${OTHER}`],
      ['rp.localhost', 'alice', 1, REF],
    ]);
  });

  it('password + TOTP sign-in: one approval, both read from 1Password after it', async () => {
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    expect(await h.mcp.ok('auth_status')).toMatchObject({
      credentials: [{ type: 'password' }, { type: 'totp' }],
    });
    await h.intent('sign in to the test RP with my 1Password login');
    const before = h.approver.seen.length;
    const callsBefore = fake.calls().length;
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password+totp' });
    expect(h.approver.seen.length - before).toBe(1);
    expect(h.approver.seen.at(-1)?.binding).toMatchObject({
      kind: 'fill',
      rpId: 'rp.localhost',
      credentialId: REF,
    });
    const reads = fake.calls().slice(callsBefore);
    expect(reads).toHaveLength(2);
    for (const c of reads) {
      expect(c.argv).toEqual([
        'item',
        'get',
        ITEM,
        `--vault=${VAULT}`,
        '--format=json',
        '--reveal',
      ]);
    }
  });

  it('the signer refuses an item whose URLs moved elsewhere since the sync', async () => {
    fake.update((d) => {
      const it = d.vaults[0]?.items.find((i) => i.id === ITEM);
      if (it) it.urls = ['https://somewhere-else.test/'];
    });
    try {
      await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
      await h.intent('sign in to the test RP again');
      const logins = h.rp.logins.length;
      expect(await h.mcp.ok('auth_login')).toEqual({ status: 'denied' });
      expect(h.rp.logins.length).toBe(logins);
      expect(signerLog.join('\n')).toContain('item_not_for_domain');
    } finally {
      fake.write(accountFor(h.rp.url));
    }
  });

  it('a revoked token: sign-in is denied and the failure is audited', async () => {
    fake.update((d) => {
      d.token = 'ops_rotated';
    });
    try {
      await expect(h.daemon.sourceSync?.refresh()).rejects.toThrow('source_not_logged_in');
      expect(
        h
          .auditEvents()
          .filter((e) => e.type === 'source.sync_failed')
          .at(-1)?.payload,
      ).toEqual({ source: '1password', reason: 'source_not_logged_in' });
      await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
      await h.intent('sign in to the test RP once more');
      expect(await h.mcp.ok('auth_login')).toEqual({ status: 'denied' });
    } finally {
      fake.write(accountFor(h.rp.url));
    }
  });

  it('nothing the MCP server sent, the audit log, the database or the signer log holds a secret', async () => {
    const secrets = [ALICE_PW, OTHER_PW, SEED, TOKEN, ...codesAround(SEED)];
    expectNoSecrets(await h.mcp.everything(), secrets, 'MCP output');
    expectNoSecrets(JSON.stringify(h.daemon.broker.audit.all()), secrets, 'audit log');
    expectNoSecrets(signerLog.join('\n'), secrets, 'signer log');
    for (const f of [dbPath(h.dataDir), `${dbPath(h.dataDir)}-wal`].filter(existsSync)) {
      expectNoSecrets(readFileSync(f).toString('latin1'), [ALICE_PW, OTHER_PW, SEED, TOKEN], f);
    }
    for (const c of fake.calls()) expect(c.argv.join(' ')).not.toContain(TOKEN);
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});
