import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { HANDOFF_IN_PROGRESS } from '../src/agent-port.ts';
import { ALICE_PW, type HandoffHarness, startHandoffHarness } from './handoff-harness.ts';

describe('human handoff on the web phone approver: the full flow', () => {
  let h: HandoffHarness;

  beforeAll(async () => {
    h = await startHandoffHarness({ rp: { challenge: 'aws-waf' } });
    h.daemon.broker.policy.set('rp.localhost', '*', { sessionTtlMs: 60 * 60_000 });
  });
  afterAll(async () => h?.close());

  it('challenge → browser_handoff → push → Face ID → tap → Done → signed in, and it survives a restart', async () => {
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const login = h.mcp.ok<{ status: string }>('auth_login');
    const card = await h.approveOnPhone();
    expect(card).toContain('sign me in to the test site');
    expect(await login).toEqual({ status: 'challenge' });
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password' });
    expect(h.daemon.sessionTtl.tracked()).toEqual([]);
    const pushesBefore = h.pushes.length;

    const handoff = h.mcp.ok<{ status: string }>('browser_handoff', { timeoutMs: 60_000 });
    await expect.poll(() => h.pushes.length, { timeout: 10_000 }).toBe(pushesBefore + 1);
    expect(h.pushPayload(pushesBefore)).toBe('{"t":"handoff","host":"rp.localhost"}');
    expect(h.daemon.handoffs.isOpen(h.agent.id)).toBe(true);

    const second = await connectSecondCall(h);
    expect(second).toBe(HANDOFF_IN_PROGRESS);

    await h.phonePage.goto(`${h.approver.origin}/`);
    const link = h.phonePage.locator('#handoffs a.handoff');
    await link.waitFor();
    expect(await link.textContent()).toContain('Human check waiting on rp.localhost');
    expect(await h.phonePage.locator('#handoffs img, #handoffs button').count()).toBe(0);

    await h.openLiveView();
    expect(await h.phonePage.textContent('#host')).toBe('rp.localhost');
    expect(await h.phonePage.textContent('#agent')).toBe('handoff-agent');
    expect(await h.phonePage.textContent('#said')).toContain('sign me in to the test site');
    const started = h.auditEvents().filter((e) => e.type === 'handoff.started');
    expect(started).toHaveLength(1);

    expect(new URL(h.page().url()).pathname).toBe('/password/login');
    await h.tapOnPhone('#challenge-solve');
    await h.page().waitForURL('**/account', { timeout: 10_000 });

    await h.phonePage.click('#done');
    expect(await handoff).toEqual({ status: 'done' });
    await h.phonePage.waitForURL(`${h.approver.origin}/`, { timeout: 10_000 });
    expect(h.daemon.handoffs.isOpen(h.agent.id)).toBe(false);
    const snap = await h.mcp.ok<{ url: string; snapshot: string; humanCheck: boolean }>(
      'browser_snapshot',
    );
    expect(snap.snapshot).toContain('Signed in as alice');
    expect(snap.humanCheck).toBe(false);

    expect(h.daemon.sessionTtl.tracked().map((t) => t.origin)).toEqual([h.rp.origin]);
    const ended = h.auditEvents().find((e) => e.type === 'handoff.ended');
    expect(ended?.payload).toMatchObject({
      agentId: h.agent.id,
      verifiedOrigin: h.rp.origin,
      outcome: 'done',
      inputs: { clicks: 1, scrolls: 0, drags: 0, keys: 0, texts: 0 },
    });
    await expect
      .poll(() => {
        const r = h.daemon.persistence?.store.load(h.agent.id);
        return r?.kind === 'ok' ? r.plain.state.cookies.map((c) => c.name).sort() : [];
      })
      .toEqual(expect.arrayContaining(['rp_clearance']));

    const everything = await h.mcp.everything();
    expect(everything).not.toMatch(/"type":"image"|image\/jpeg|data:image|\/9j\//);
    expect(everything).not.toContain(ALICE_PW);

    const logins = h.rp.logins.length;
    const asked = h.recording.requests.length;
    await h.restart();
    await h.mcp.ok('browser_open', { url: `${h.rp.url}account` });
    const after = await h.mcp.ok<{ snapshot: string; humanCheck: boolean }>('browser_snapshot');
    expect(after.snapshot).toContain('Signed in as alice');
    expect(after.humanCheck).toBe(false);
    expect(h.rp.logins.length).toBe(logins);
    expect(h.recording.requests.length).toBe(asked);
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });

  it('the live view never strands the phone: with no human check open it goes to approvals', async () => {
    await h.phonePage.goto(`${h.approver.origin}/handoff`);
    await h.phonePage.waitForURL(`${h.approver.origin}/`, { timeout: 10_000 });
    await h.intent('sign me in to the test site again');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const login = h.mcp.ok<{ status: string }>('auth_login');
    const card = h.phonePage.locator('#requests .card').first();
    await card.waitFor({ timeout: 15_000 });
    expect(await card.textContent()).toContain('sign me in to the test site again');
    await card.locator('.approve').click();
    expect(['success', 'challenge']).toContain((await login).status);
  });
});

async function connectSecondCall(h: HandoffHarness): Promise<string> {
  const { connectAgent } = await import('./mcp-harness.ts');
  const c = await connectAgent(h.daemon.mcpUrl as string, h.agent);
  try {
    return await c.err('browser_snapshot');
  } finally {
    await c.close();
  }
}
