import { existsSync, readFileSync } from 'node:fs';
import { type FakePassCli, type FakeVaultFile, fakePassCli } from '@aab/sources/testing';
import { totp } from '@aab/test-rp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CredentialRepo } from '../src/db.ts';
import { dbPath, type McpHarness, startMcpHarness } from './mcp-harness.ts';

const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const ALICE_PW = 'alice-Proton/pass word+%&?';
const OTHER_PW = 'other-site-password-7Qx';
const SHARE = 'SHARE_agent==';
const ITEM = '-aliceItem_1';
const REF = `proton-pass:${SHARE}:${ITEM}`;

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

describe('M3 phase 2: Proton Pass logins through MCP (fake pass-cli)', () => {
  let h: McpHarness;
  let fake: FakePassCli;
  const signerLog: string[] = [];

  beforeAll(async () => {
    fake = fakePassCli({ loggedIn: true, vaults: [] });
    h = await startMcpHarness({
      agentName: 'proton-agent',
      rp: { users: [{ username: 'alice', password: ALICE_PW, totpSecret: SEED }] },
      daemon: {
        passwordSource: {
          kind: 'proton-pass',
          bin: fake.bin,
          env: fake.env,
          vault: 'Agent',
          retryMs: 0,
        },
        onSignerLog: (l) => signerLog.push(l),
      },
    });
    await h.daemon.sourceSync?.refresh().catch(() => {});
    fake.write(vaultFor(h.rp.url));
    await h.daemon.sourceSync?.refresh();
  });
  afterAll(async () => h?.close());

  const vaultFor = (rpUrl: string): FakeVaultFile => ({
    loggedIn: true,
    vaults: [
      {
        name: 'Agent',
        share_id: SHARE,
        vault_id: 'V1',
        items: [
          {
            id: ITEM,
            title: 'Test RP',
            login: {
              username: 'alice',
              password: ALICE_PW,
              urls: [`${rpUrl}password/login`],
              totp_uri: `otpauth://totp/RP:alice?secret=${SEED}`,
            },
          },
          {
            id: 'other',
            title: 'Other site',
            login: { username: 'zed', password: OTHER_PW, urls: ['https://other.test/'] },
          },
        ],
      },
      {
        name: 'Personal',
        share_id: 'SHARE_personal',
        vault_id: 'V2',
        items: [{ id: 'p', title: 'P', login: { password: 'personal-pw-1', urls: ['p.test'] } }],
      },
    ],
  });

  it('mirrors the vault: one row per registrable domain, only the named vault', () => {
    const rows = new CredentialRepo(h.daemon.db)
      .sourcePasswords('proton-pass')
      .sort((a, b) => a.registrable_domain.localeCompare(b.registrable_domain));
    expect(rows.map((r) => [r.registrable_domain, r.username, r.has_totp, r.signer_ref])).toEqual([
      ['other.test', 'zed', 0, `proton-pass:${SHARE}:other`],
      ['rp.localhost', 'alice', 1, REF],
    ]);
  });

  it('auth_status reports password and totp from the vault', async () => {
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    expect(await h.mcp.ok('auth_status')).toEqual({
      origin: h.rp.origin,
      credentials: [{ type: 'password' }, { type: 'totp' }],
      humanCheck: false,
    });
  });

  it('password + TOTP sign-in: one approval, both read from the vault after it', async () => {
    await h.intent('sign in to the test RP with my Proton Pass login');
    const before = h.approver.seen.length;
    const viewsBefore = fake.calls().length;
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password+totp' });
    expect(h.approver.seen.length - before).toBe(1);
    const req = h.approver.seen.at(-1);
    expect(req?.display.credentialType).toBe('password+totp');
    expect(req?.binding).toMatchObject({ kind: 'fill', rpId: 'rp.localhost', credentialId: REF });
    const reads = fake.calls().slice(viewsBefore);
    expect(reads.map((c) => c.reason)).toEqual([
      `Keyflap broker: approved sign-in on ${h.rp.origin}`,
      `Keyflap broker: approved sign-in on ${h.rp.origin}`,
    ]);
    expect(reads.every((c) => c.argv.includes(`--item-id=${ITEM}`))).toBe(true);
  });

  it('a login saved after the last sync is found when a page has none', async () => {
    const late = `http://late.localhost:${new URL(h.rp.url).port}`;
    const ctx = await h.context();
    await ctx.route(/late\.localhost.*\/login$/, (r) =>
      r.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><title>Late</title><form method="post"><input name="u" autocomplete="username"><input type="password" name="p"></form>',
      }),
    );
    await h.mcp.ok('browser_open', { url: `${late}/login` });
    expect(await h.mcp.ok('auth_status')).toMatchObject({ credentials: [] });
    fake.update((d) =>
      d.vaults[0]?.items.push({
        id: 'late',
        title: 'Late',
        modify_time: '2026-10-12T00:00:00',
        login: { username: 'lee', password: 'late-password-1', urls: [`${late}/`] },
      }),
    );
    expect(await h.mcp.ok('auth_status')).toMatchObject({ credentials: [{ type: 'password' }] });
  });

  it('the signer refuses an item whose URLs moved elsewhere since the sync', async () => {
    fake.update((d) => {
      const it = d.vaults[0]?.items.find((i) => i.id === ITEM);
      if (it?.login) it.login.urls = ['https://somewhere-else.test/'];
    });
    try {
      await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
      await h.intent('sign in to the test RP again');
      const logins = h.rp.logins.length;
      expect(await h.mcp.ok('auth_login')).toEqual({ status: 'denied' });
      expect(h.rp.logins.length).toBe(logins);
      expect(signerLog.join('\n')).toContain('item_not_for_domain');
    } finally {
      fake.write(vaultFor(h.rp.url));
    }
  });

  it('a vault login is never offered on another site', async () => {
    const evil = `http://evil.localhost:${new URL(h.rp.url).port}`;
    const ctx = await h.context();
    await ctx.route(/evil\.localhost.*\/login$/, (r) =>
      r.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><title>Sign in</title><form method="post"><input name="u" autocomplete="username"><input type="password" name="p"></form>',
      }),
    );
    await h.mcp.ok('browser_open', { url: `${evil}/login` });
    expect(await h.mcp.ok('auth_status')).toMatchObject({ credentials: [] });
    await h.intent('sign in here');
    expect(await h.mcp.ok('auth_login')).toMatchObject({ status: 'unsupported' });
  });

  it('pass-cli logged out: sign-in is denied and the failure is audited, no secret anywhere', async () => {
    fake.update((d) => {
      d.loggedIn = false;
    });
    try {
      await expect(h.daemon.sourceSync?.refresh()).rejects.toThrow('source_not_logged_in');
      expect(
        h
          .auditEvents()
          .filter((e) => e.type === 'source.sync_failed')
          .at(-1)?.payload,
      ).toEqual({
        source: 'proton-pass',
        reason: 'source_not_logged_in',
      });
      await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
      await h.intent('sign in to the test RP once more');
      expect(await h.mcp.ok('auth_login')).toEqual({ status: 'denied' });
    } finally {
      fake.write(vaultFor(h.rp.url));
    }
  });

  it('nothing the MCP server sent, the audit log, the database or the signer log holds a secret', async () => {
    const secrets = [ALICE_PW, OTHER_PW, SEED, ...codesAround(SEED)];
    expectNoSecrets(await h.mcp.everything(), secrets, 'MCP output');
    expectNoSecrets(JSON.stringify(h.daemon.broker.audit.all()), secrets, 'audit log');
    expectNoSecrets(signerLog.join('\n'), secrets, 'signer log');
    for (const f of [dbPath(h.dataDir), `${dbPath(h.dataDir)}-wal`].filter(existsSync)) {
      expectNoSecrets(readFileSync(f).toString('latin1'), [ALICE_PW, OTHER_PW, SEED], f);
    }
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});
