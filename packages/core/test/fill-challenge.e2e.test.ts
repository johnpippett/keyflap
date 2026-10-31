import { startTestRp, type TestRp, type TestRpOptions } from '@aab/test-rp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addPasswordItem } from '../src/passwords.ts';
import { type McpHarness, startMcpHarness } from './mcp-harness.ts';

const ALICE_PW = 'alice-challenge-pw-7Qx!';
const USERS = [{ username: 'alice', password: ALICE_PW }];

describe('honest outcome: challenge after a password fill', () => {
  let h: McpHarness;
  const rps: TestRp[] = [];

  beforeAll(async () => {
    h = await startMcpHarness({
      agentName: 'challenge-agent',
      rp: { users: USERS },
      daemon: { challengeHosts: ['captcha.localhost'] },
    });
    await addPasswordItem(
      { signer: h.daemon.signer.client, db: h.daemon.db },
      { site: 'rp.localhost', username: 'alice', password: ALICE_PW },
    );
  });
  afterAll(async () => {
    for (const r of rps) await r.close();
    await h?.close();
  });

  const rpAt = async (sub: string, o: TestRpOptions): Promise<TestRp> => {
    const r = await startTestRp({ host: `${sub}.rp.localhost`, users: USERS, ...o });
    rps.push(r);
    return r;
  };

  const fillCompleted = () =>
    h
      .auditEvents()
      .filter((e) => e.type === 'fill.completed')
      .at(-1)?.payload;

  async function login(r: TestRp) {
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${r.url}password/login` });
    return h.mcp.ok<{ status: string }>('auth_login');
  }

  const cases: [NonNullable<TestRpOptions['challenge']>, string, string][] = [
    ['aws-waf', 'aws-waf', 'one'],
    ['cloudflare', 'cloudflare', 'two'],
    ['frame', 'test', 'three'],
  ];
  for (const [mode, provider, sub] of cases) {
    it(`${mode}: auth_login answers challenge, audited with the provider, no TTL clock`, async () => {
      const r = await rpAt(sub, { challenge: mode });
      const trackedBefore = h.daemon.sessionTtl.tracked().length;
      expect(await login(r)).toEqual({ status: 'challenge' });
      expect(r.logins.at(-1)).toEqual({ username: 'alice', method: 'password' });
      expect(fillCompleted()).toMatchObject({
        verifiedOrigin: r.origin,
        outcome: 'challenge',
        humanCheck: provider,
        fields: ['password'],
      });
      expect(h.daemon.sessionTtl.tracked()).toHaveLength(trackedBefore);
      expect(h.daemon.sessionTtl.tracked().some((t) => t.origin === r.origin)).toBe(false);

      const st = await h.mcp.ok<{ humanCheck: boolean }>('auth_status');
      expect(st.humanCheck).toBe(true);
      const snap = await h.mcp.ok<{ humanCheck: boolean; snapshot: string }>('browser_snapshot');
      expect(snap.humanCheck).toBe(true);
      expect(snap.snapshot).toContain("Let's confirm you are human");
      expect(snap.snapshot).not.toContain(ALICE_PW);
    });
  }

  it('page text alone is no signal: a text-only "confirm you are human" page reads as success', async () => {
    const r = await rpAt('text', { challenge: 'text-only' });
    expect(await login(r)).toEqual({ status: 'success' });
    expect(fillCompleted()).toMatchObject({ verifiedOrigin: r.origin, outcome: 'success' });
    expect(fillCompleted()?.humanCheck).toBeUndefined();
    const snap = await h.mcp.ok<{ humanCheck: boolean; snapshot: string }>('browser_snapshot');
    expect(snap.snapshot).toContain("Let's confirm you are human");
    expect(snap.humanCheck).toBe(false);
    expect((await h.mcp.ok<{ humanCheck: boolean }>('auth_status')).humanCheck).toBe(false);
    expect(h.daemon.sessionTtl.tracked().some((t) => t.origin === r.origin)).toBe(true);
  });

  it('a background widget on the login page (script + 1×1 frame) does not make it a challenge', async () => {
    const r = await rpAt('bg', { invisibleWidget: true });
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${r.url}password/login` });
    expect((await h.mcp.ok<{ humanCheck: boolean }>('auth_status')).humanCheck).toBe(false);
    expect(r.requests.some((q) => q.path === '/challenge/widget')).toBe(true);
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    expect(fillCompleted()).toMatchObject({ verifiedOrigin: r.origin, outcome: 'success' });
    const snap = await h.mcp.ok<{ humanCheck: boolean; snapshot: string }>('browser_snapshot');
    expect(snap.snapshot).toContain('Signed in as alice');
    expect(snap.humanCheck).toBe(false);
  });

  it('a wrong password is still failed, even on a site with a challenge after sign-in', async () => {
    const r = await rpAt('wrong', {
      challenge: 'aws-waf',
      users: [{ username: 'alice', password: 'a-different-password' }],
    });
    expect(await login(r)).toEqual({ status: 'failed' });
    expect(fillCompleted()).toMatchObject({ verifiedOrigin: r.origin, outcome: 'failed' });
  });

  it('a check that pops up over a form that stays ends the fill as challenge, and the field is cleared', async () => {
    const r = await rpAt('popup', {});
    const ctx = await h.context();
    const port = new URL(r.origin).port;
    await ctx.route(/captcha\.localhost:\d+\/challenge\/widget$/, (route) =>
      route.fulfill({ contentType: 'text/html', body: '<p>check</p>' }),
    );
    await ctx.route(/popup\.rp\.localhost:\d+\/hc-popup$/, (route) =>
      route.fulfill({
        contentType: 'text/html',
        body: `<!doctype html><title>Sign in</title>
<form id="f" method="post" action="/hc-popup-post">
<label>Username <input id="username" name="username" autocomplete="username"></label>
<label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
<button>Sign in</button></form>
<script>
document.getElementById('f').addEventListener('submit', (e) => {
  e.preventDefault();
  const f = document.createElement('iframe');
  f.src = 'http://captcha.localhost:${port}/challenge/widget';
  f.width = '320'; f.height = '160';
  document.body.appendChild(f);
});
</script>`,
      }),
    );
    try {
      await h.intent('sign me in to the test site');
      await h.mcp.ok('browser_open', { url: `${r.url}hc-popup` });
      expect(await h.mcp.ok('auth_login')).toEqual({ status: 'challenge' });
      expect(fillCompleted()).toMatchObject({ outcome: 'challenge', humanCheck: 'test' });
      expect(await h.page().locator('#password').inputValue()).toBe('');
      const snap = await h.mcp.ok<{ humanCheck: boolean; snapshot: string }>('browser_snapshot');
      expect(snap.humanCheck).toBe(true);
    } finally {
      await ctx.unrouteAll({ behavior: 'ignoreErrors' });
    }
  });

  it('nothing the agent got or the audit log holds contains the password or a provider name', async () => {
    const everything = await h.mcp.everything();
    expect(everything).not.toContain(ALICE_PW);
    expect(everything).not.toContain(encodeURIComponent(ALICE_PW));
    for (const p of ['aws-waf', 'cloudflare', '"provider"']) expect(everything).not.toContain(p);
    expect(JSON.stringify(h.daemon.broker.audit.all())).not.toContain(ALICE_PW);
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});
