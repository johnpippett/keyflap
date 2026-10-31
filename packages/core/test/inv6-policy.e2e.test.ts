import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addPasswordItem } from '../src/passwords.ts';
import { type McpHarness, startMcpHarness } from './mcp-harness.ts';

const PW = 'alice-policy-pass-0n3';
const CLI = join(import.meta.dirname, '..', '..', 'cli', 'src', 'main.ts');

function keyflap(dataDir: string, ...args: string[]): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, ...args, '--data-dir', dataDir],
      { timeout: 20_000 },
      (err, stdout, stderr) => {
        const code = err ? ((err as { code?: number }).code ?? 1) : 0;
        resolve({ code: typeof code === 'number' ? code : 1, out: `${stdout}${stderr}` });
      },
    );
  });
}

async function until(cond: () => boolean | Promise<boolean>, ms = 10_000): Promise<void> {
  const end = Date.now() + ms;
  while (!(await cond())) {
    if (Date.now() > end) throw new Error('timed out waiting');
    await new Promise((r) => setTimeout(r, 100));
  }
}

describe('invariant 6: policy (deny, allow-for, session TTL) through MCP', () => {
  let h: McpHarness;
  const types = () => h.auditEvents().map((e) => e.type);
  const login = () => h.mcp.ok<{ status: string }>('auth_login');
  const openLogin = () => h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
  const logout = async () => {
    await h.mcp.ok('browser_open', { url: `${h.rp.url}account` });
    await h.mcp.ok('browser_click', { target: { role: 'button', name: 'Log out' } });
  };

  beforeAll(async () => {
    h = await startMcpHarness({
      agentName: 'policy-agent',
      rp: { users: [{ username: 'alice', password: PW }] },
      daemon: { sessionSweepMs: 200 },
    });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: PW },
    );
  });
  afterAll(async () => h?.close());

  it('the agent still sees exactly the eight tools; none takes a policy', async () => {
    const tools = await h.mcp.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'auth_enroll_passkey',
      'auth_login',
      'auth_status',
      'browser_click',
      'browser_handoff',
      'browser_open',
      'browser_snapshot',
      'browser_type',
    ]);
    const keys = JSON.stringify(tools.map((t) => t.inputSchema)).match(/"[A-Za-z]+":/g) ?? [];
    expect(keys.join(' ')).not.toMatch(/policy|allow|deny|grant|ttl|mode|agent/i);
  });

  it('deny set by the CLI while the daemon runs: denied, nobody asked, audited', async () => {
    const set = await keyflap(h.dataDir, 'policy', 'set', 'rp.localhost', '--deny');
    expect(set.code, set.out).toBe(0);
    await openLogin();
    await h.intent('sign in to the test RP');
    const asked = h.approver.seen.length;
    expect(await login()).toEqual({ status: 'denied' });
    expect(h.approver.seen.length).toBe(asked);
    const ev = h.auditEvents();
    const denied = ev.filter((e) => e.type === 'denied').at(-1);
    expect(denied?.payload).toMatchObject({ reason: 'policy_deny', agentId: h.agent.id });
    const policy = ev.filter((e) => e.type === 'policy').at(-1);
    expect(policy?.payload).toMatchObject({
      requestId: denied?.payload.requestId,
      mode: 'deny',
      rules: [{ pattern: 'rp.localhost', agentId: '*' }],
    });
    expect(ev.some((e) => e.type === 'policy.set' && e.payload.mode === 'deny')).toBe(true);
    expect((await keyflap(h.dataDir, 'policy', 'remove', 'rp.localhost')).code).toBe(0);
    expect(await login()).toEqual({ status: 'success' });
    expect(h.approver.seen.length).toBe(asked + 1);
    expect(h.approver.seen.at(-1)?.display.allowForMs).toBeUndefined();
  });

  it('allow-for: one approval shows the window, later sign-ins need none but each is audited', async () => {
    const set = await keyflap(
      h.dataDir,
      'policy',
      'set',
      h.rp.origin,
      '--agent',
      h.agent.id,
      '--allow-for',
      '10m',
    );
    expect(set.code, set.out).toBe(0);
    await logout();
    await openLogin();
    const asked = h.approver.seen.length;
    expect(await login()).toEqual({ status: 'success' });
    expect(h.approver.seen.length).toBe(asked + 1);
    const req = h.approver.seen.at(-1);
    expect(req?.display.allowForMs).toBe(10 * 60_000);
    expect(req?.binding.grant).toEqual({ agentId: h.agent.id, durationMs: 10 * 60_000 });
    const signed = h.approver.signed.at(-1);
    expect(signed?.statement.grant?.agentId).toBe(h.agent.id);
    expect(types()).toContain('grant.created');

    const logins = h.rp.logins.length;
    for (let i = 0; i < 2; i++) {
      await logout();
      await openLogin();
      expect(await login()).toEqual({ status: 'success' });
    }
    expect(h.approver.seen.length).toBe(asked + 1);
    expect(h.rp.logins.length).toBe(logins + 2);
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password' });
    const used = h.auditEvents().filter((e) => e.type === 'grant.used');
    expect(used).toHaveLength(2);
    for (const u of used) {
      expect(u.payload).toMatchObject({ agentId: h.agent.id, verifiedOrigin: h.rp.origin });
      const trail = h
        .auditEvents()
        .filter((e) => e.payload.requestId === u.payload.requestId)
        .map((e) => e.type);
      expect(trail).toEqual(expect.arrayContaining(['request', 'policy', 'grant.used']));
      expect(trail.at(-1)).toBe('fill.completed');
    }
  });

  it('inside the window a sign-in without a live intent is denied, unprompted (invariant 4)', async () => {
    await logout();
    await openLogin();
    h.daemon.db.exec('DELETE FROM intents');
    const asked = h.approver.seen.length;
    const usedBefore = types().filter((t) => t === 'grant.used').length;
    expect(await login()).toEqual({ status: 'denied' });
    expect(h.approver.seen.length).toBe(asked);
    expect(types().filter((t) => t === 'grant.used').length).toBe(usedBefore);
    expect(
      h
        .auditEvents()
        .filter((e) => e.type === 'denied')
        .at(-1)?.payload.reason,
    ).toBe('no_live_intent');
    await h.intent('sign in to the test RP again');
    expect(await login()).toEqual({ status: 'success' });
    expect(h.approver.seen.length).toBe(asked);
  });

  it('session TTL: the site session ends in the agent browser after the TTL, audited', async () => {
    await logout();
    await openLogin();
    expect(await login()).toEqual({ status: 'success' });
    const ctx = await h.context();
    await h.page().evaluate(() => localStorage.setItem('session-marker', 'x'));
    await ctx.addCookies([
      { name: 'other', value: '1', domain: 'other.localhost', path: '/' },
      { name: 'wide', value: '1', domain: '.rp.localhost', path: '/' },
    ]);
    expect((await ctx.cookies()).map((c) => c.name).sort()).toEqual(['other', 'sid', 'wide']);
    expect(h.daemon.sessionTtl.tracked().map((t) => t.origin)).toContain(h.rp.origin);
    expect(
      (await keyflap(h.dataDir, 'policy', 'set', 'rp.localhost', '--session-ttl', '2s')).code,
    ).toBe(0);

    await until(() => types().includes('session.cleared'));
    const cleared = h.auditEvents().find((e) => e.type === 'session.cleared');
    expect(cleared?.payload).toEqual({
      agentId: h.agent.id,
      origin: h.rp.origin,
      ttlMs: 2000,
      cookies: 2,
      pages: 1,
      via: 'ttl',
    });
    expect((await ctx.cookies()).map((c) => c.name)).toEqual(['other']);
    expect(h.daemon.sessions.peek(h.agent.id)?.currentPage()).toBeNull();
    const r = await h.mcp.ok<{ url: string }>('browser_open', { url: `${h.rp.url}account` });
    expect(r.url).toBe(`${h.rp.url}login`);
    expect(await h.page().evaluate(() => localStorage.getItem('session-marker'))).toBeNull();
    expect(ctx.pages()).toHaveLength(1);
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});
