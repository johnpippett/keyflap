import { createPrivateKey } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { KeyStore } from '../../signer/src/keystore.ts';
import {
  dbPath,
  keyStorePath,
  type McpHarness,
  mcpSignUp,
  PASSPHRASE,
  startMcpHarness,
} from './mcp-harness.ts';

function secretForms(pkcs8b64: string): { label: string; value: string }[] {
  const der = Buffer.from(pkcs8b64, 'base64');
  const key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const jwk = key.export({ format: 'jwk' });
  if (!jwk.d) throw new Error('no d');
  const d = Buffer.from(jwk.d, 'base64url');
  const pem = (key.export({ format: 'pem', type: 'pkcs8' }) as string)
    .split('\n')
    .filter((l) => l && !l.startsWith('-----'));
  const sec1 = key.export({ format: 'der', type: 'sec1' }) as Buffer;
  return [
    { label: 'pkcs8 b64', value: pkcs8b64 },
    { label: 'pkcs8 b64url', value: der.toString('base64url') },
    { label: 'pkcs8 hex', value: der.toString('hex') },
    { label: 'sec1 b64', value: sec1.toString('base64') },
    { label: 'sec1 hex', value: sec1.toString('hex') },
    { label: 'jwk d (b64url)', value: jwk.d },
    { label: 'd b64', value: d.toString('base64').replace(/=+$/, '') },
    { label: 'd hex', value: d.toString('hex') },
    { label: 'd HEX', value: d.toString('hex').toUpperCase() },
    { label: 'jwk json', value: JSON.stringify(jwk) },
    { label: 'pem line', value: pem[0] as string },
  ];
}

function expectAbsent(haystack: string, forms: { label: string; value: string }[], where: string) {
  for (const f of forms) {
    expect(haystack.includes(f.value), `${f.label} found in ${where}`).toBe(false);
  }
}

describe('invariant 1: the agent never receives secret material', () => {
  let h: McpHarness;
  let keys: { id: string; privateKey: string }[] = [];

  beforeAll(async () => {
    h = await startMcpHarness({ agentName: 'inv1-agent' });
  });
  afterAll(async () => h?.close());

  it('full passkey enrollment + sign-in through MCP tools only', async () => {
    const m = h.mcp;
    const tools = await m.listTools();
    expect(tools).toHaveLength(8);

    await h.intent('add a passkey to my test RP account, then sign in with it');
    await mcpSignUp(h, m, 'inv1-user');
    await m.ok('browser_click', { target: { role: 'button', name: 'Add a passkey' } });
    expect(await m.ok('auth_enroll_passkey')).toEqual({ status: 'success' });
    await expect.poll(() => h.rp.users.get('inv1-user')?.passkeys.length).toBe(1);
    const afterAdd = await m.ok<{ snapshot: string }>('browser_snapshot');
    expect(afterAdd.snapshot).toContain('passkey added');
    expect(await m.ok('auth_status')).toEqual({
      origin: h.rp.origin,
      credentials: [{ type: 'passkey' }],
      humanCheck: false,
    });

    await m.ok('browser_click', { target: { role: 'button', name: 'Log out' } });
    await m.ok('browser_open', { url: `${h.rp.url}login` });
    await m.ok('browser_click', { target: { role: 'button', name: 'Sign in with a passkey' } });
    expect(await m.ok('auth_login')).toEqual({ status: 'success' });
    await expect
      .poll(() => h.rp.logins.at(-1))
      .toEqual({
        username: 'inv1-user',
        method: 'passkey',
      });
    await expect
      .poll(async () => (await m.ok<{ snapshot: string }>('browser_snapshot')).snapshot)
      .toContain('Signed in as inv1-user');
    expect(h.approver.seen.map((r) => r.display.action)).toEqual(['register', 'sign-in']);
    expect(h.approver.signed).toHaveLength(2);

    const store = KeyStore.open(keyStorePath(h.dataDir), PASSPHRASE);
    const ids = h.daemon.broker.credentials.allPasskeyRpIds().map((c) => c.id);
    expect(ids).toHaveLength(1);
    keys = ids.map((id) => {
      const c = store.get(id);
      if (!c) throw new Error('credential missing from the key store');
      return { id, privateKey: c.privateKey };
    });
  });

  it('no form of any private key appears in anything the MCP server sent', async () => {
    expect(keys).toHaveLength(1);
    const everything = await h.mcp.everything();
    expect(h.mcp.raw.length).toBeGreaterThan(10);
    expect(everything).toContain('Signed in as inv1-user');
    expect(everything).toContain('auth_enroll_passkey');
    for (const k of keys) expectAbsent(everything, secretForms(k.privateKey), 'MCP output');
  });

  it('nor in the audit log payloads, nor in the broker database file', () => {
    const audit = JSON.stringify(h.daemon.broker.audit.all());
    const files = [dbPath(h.dataDir), `${dbPath(h.dataDir)}-wal`].filter(existsSync);
    const bytes = files.map((f) => readFileSync(f));
    for (const k of keys) {
      const forms = secretForms(k.privateKey);
      expectAbsent(audit, forms, 'audit log');
      for (const [i, b] of bytes.entries()) {
        expectAbsent(b.toString('latin1'), forms, files[i] as string);
        const der = Buffer.from(k.privateKey, 'base64');
        const jwk = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }).export({
          format: 'jwk',
        });
        expect(b.indexOf(der), `DER in ${files[i]}`).toBe(-1);
        expect(b.indexOf(Buffer.from(jwk.d as string, 'base64url')), `d in ${files[i]}`).toBe(-1);
      }
    }
    const row = h.daemon.db.prepare('SELECT public_key FROM credentials').get() as {
      public_key: string;
    };
    expect(bytes.some((b) => b.toString('latin1').includes(row.public_key))).toBe(true);
  });

  it('approval signatures, the signer channel key, passphrase and host token never reach the agent', async () => {
    const everything = await h.mcp.everything();
    const channelKey = (h.daemon.signer.client as unknown as { key: Buffer }).key;
    expect(Buffer.isBuffer(channelKey) && channelKey.length === 32).toBe(true);
    const forbidden = [
      ...h.approver.signed.map((a) => ({
        label: 'approval signature',
        value: a.signature as string,
      })),
      { label: 'channel key b64url', value: channelKey.toString('base64url') },
      { label: 'channel key b64', value: channelKey.toString('base64') },
      { label: 'channel key hex', value: channelKey.toString('hex') },
      { label: 'passphrase', value: PASSPHRASE },
      { label: 'host token', value: h.daemon.hostToken },
    ];
    expect(h.approver.signed.length).toBe(2);
    expectAbsent(everything, forbidden, 'MCP output');
  });
});

const SECRETS_PAGE = `<!doctype html><title>loading</title><body>
<label>Display name <input id="name" value="plain-visible-value"></label>
<label>Password <input id="pw" type="password" value="inv1-prefilled-password"></label>
<label>Code <input id="otp" autocomplete="one-time-code" inputmode="numeric" value="864213"></label>
<label>Later <input id="later" type="password"></label>
<label>Current <input id="cur" autocomplete="current-password" value="inv1-current-pw"></label>
<script>
window.addEventListener('load', () => setTimeout(() => {
  document.getElementById('later').value = 'inv1-set-by-script-after-load';
  document.getElementById('otp').value = '975310';
  document.title = 'ready';
}, 150));
</script>
</body>`;

describe('invariant 1: password and one-time-code values never reach the agent', () => {
  let h: McpHarness;
  const SECRETS = [
    'inv1-prefilled-password',
    '864213',
    '975310',
    'inv1-set-by-script-after-load',
    'inv1-current-pw',
  ];

  beforeAll(async () => {
    h = await startMcpHarness({ agentName: 'inv1-fields' });
    const ctx = await h.context();
    await ctx.route(/\/inv1-secrets$/, (route) =>
      route.fulfill({ contentType: 'text/html', body: SECRETS_PAGE }),
    );
  });
  afterAll(async () => h?.close());

  it('browser_snapshot returns neither prefilled nor script-set values', async () => {
    const m = h.mcp;
    await m.ok('browser_open', { url: `${h.rp.url}inv1-secrets` });
    let snap = await m.ok<{ title: string; snapshot: string }>('browser_snapshot');
    for (let i = 0; i < 50 && snap.title !== 'ready'; i++) {
      await new Promise((r) => setTimeout(r, 50));
      snap = await m.ok('browser_snapshot');
    }
    expect(snap.title).toBe('ready');
    expect(await h.page().inputValue('#later')).toBe('inv1-set-by-script-after-load');
    expect(snap.snapshot).toContain('plain-visible-value');
    expect(snap.snapshot).toContain('[redacted]');
    for (const s of SECRETS) expect(snap.snapshot, s).not.toContain(s);
  });

  it('browser_type into a password, one-time-code or current-password field is refused', async () => {
    const m = h.mcp;
    for (const target of [
      { label: 'Password' },
      { css: '#pw' },
      { label: 'Code' },
      { css: '#otp' },
      { label: 'Later' },
      { label: 'Current' },
    ]) {
      const msg = await m.err('browser_type', { target, text: 'agent-typed-secret' });
      expect(msg, JSON.stringify(target)).toMatch(/auth_login/);
    }
    expect(await h.page().inputValue('#pw')).toBe('inv1-prefilled-password');
    expect(await h.page().inputValue('#otp')).toBe('975310');
    await m.ok('browser_type', { target: { label: 'Display name' }, text: 'ok' });
    expect(await h.page().inputValue('#name')).toBe('ok');
  });

  it('none of the values appears anywhere in the MCP output', async () => {
    const everything = await h.mcp.everything();
    for (const s of SECRETS) expect(everything.includes(s), s).toBe(false);
  });
});
