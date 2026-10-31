import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type HandoffHarness, routeChallengePage, startHandoffHarness } from './handoff-harness.ts';

describe('invariant 4: a handoff needs a live intent', () => {
  let h: HandoffHarness;
  let url: string;

  beforeAll(async () => {
    h = await startHandoffHarness({ password: false, daemon: { intentTtlMs: 60_000 } });
    url = await routeChallengePage(h, '/inv4-check', '<h1>Please confirm</h1>');
  });
  afterAll(async () => h?.close());

  it('no live intent: denied, no push, audited', async () => {
    await h.mcp.ok('browser_open', { url });
    expect((await h.mcp.ok<{ humanCheck: boolean }>('auth_status')).humanCheck).toBe(true);
    const pushes = h.pushes.length;
    expect(await h.mcp.ok('browser_handoff', { timeoutMs: 1000 })).toEqual({ status: 'denied' });
    expect(h.daemon.handoffs.isOpen(h.agent.id)).toBe(false);
    await new Promise((r) => setTimeout(r, 300));
    expect(h.pushes.length).toBe(pushes);
    const denied = h.auditEvents().filter((e) => e.type === 'handoff.denied');
    expect(denied.at(-1)?.payload).toEqual({
      agentId: h.agent.id,
      verifiedOrigin: h.rp.origin,
      reason: 'no_live_intent',
    });
    expect(h.auditEvents().some((e) => e.type === 'handoff.requested')).toBe(false);
    h.daemon.broker.intents.record(h.agent.id, 'old words');
    h.daemon.db.prepare('UPDATE intents SET expires_at = 1').run();
    expect(await h.mcp.ok('browser_handoff', { timeoutMs: 1000 })).toEqual({ status: 'denied' });
    expect(h.pushes.length).toBe(pushes);
  });

  it('with an intent: exactly one push; a second call joins the open handoff', async () => {
    await h.intent('get me past the check on the test site');
    const pushes = h.pushes.length;
    expect(await h.mcp.ok('browser_handoff', { timeoutMs: 1000 })).toEqual({ status: 'pending' });
    expect(h.daemon.handoffs.isOpen(h.agent.id)).toBe(true);
    await expect.poll(() => h.pushes.length).toBe(pushes + 1);
    expect(await h.mcp.ok('browser_handoff', { timeoutMs: 1000 })).toEqual({ status: 'pending' });
    await new Promise((r) => setTimeout(r, 300));
    expect(h.pushes.length).toBe(pushes + 1);
    const requested = h.auditEvents().filter((e) => e.type === 'handoff.requested');
    expect(requested).toHaveLength(1);
    expect(requested[0]?.payload).toMatchObject({
      agentId: h.agent.id,
      verifiedOrigin: h.rp.origin,
      provider: 'test',
    });
    h.daemon.handoffs.endAgent(h.agent.id, 'closed');
    expect(await h.mcp.ok('browser_handoff', { timeoutMs: 1000 })).toEqual({
      status: 'cancelled',
    });
  });
});

describe('invariant 4 (P3b): no live intent, no combined human check + sign-in card', () => {
  let h: HandoffHarness;

  beforeAll(async () => {
    h = await startHandoffHarness({ rp: { challenge: 'aws-waf', challengeAt: 'login-page' } });
  });
  afterAll(async () => h?.close());

  it('without an intent: denied, no push, no approval card; with one: exactly one card', async () => {
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const pushes = h.pushes.length;
    expect(await h.mcp.ok('browser_handoff', { timeoutMs: 1000 })).toEqual({ status: 'denied' });
    await new Promise((r) => setTimeout(r, 300));
    expect(h.pushes.length).toBe(pushes);
    expect(h.recording.requests).toHaveLength(0);
    expect(h.auditEvents().some((e) => e.type === 'grant.created')).toBe(false);

    await h.intent('sign me in to the test site');
    expect(await h.mcp.ok('browser_handoff', { timeoutMs: 1000 })).toEqual({ status: 'pending' });
    await expect.poll(() => h.recording.requests.length).toBe(1);
    await expect.poll(() => h.pushes.length).toBe(pushes + 1);
    expect(h.pushPayload(pushes)).toBe('{"t":"approval"}');
    expect(h.recording.requests[0]?.display.intentText).toBe('sign me in to the test site');
    expect(h.recording.requests[0]?.display.handoffSignIn).toBeDefined();
    expect(await h.mcp.ok('browser_handoff', { timeoutMs: 1000 })).toEqual({ status: 'pending' });
    await new Promise((r) => setTimeout(r, 300));
    expect(h.recording.requests).toHaveLength(1);
    expect(h.pushes.length).toBe(pushes + 1);
    h.daemon.handoffs.endAgent(h.agent.id, 'closed');
    await expect.poll(() => h.recording.decisions.length).toBe(1);
    expect(h.recording.decisions[0]?.approved).toBe(false);
    expect(h.auditEvents().some((e) => e.type === 'grant.created')).toBe(false);
  });
});
