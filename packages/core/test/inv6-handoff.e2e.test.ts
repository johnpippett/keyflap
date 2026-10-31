import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { HANDOFF_IN_PROGRESS } from '../src/agent-port.ts';
import type { FillTarget } from '../src/broker.ts';
import { type HandoffHarness, startHandoffHarness } from './handoff-harness.ts';

describe('invariant 6: no credential operation while a handoff is open', () => {
  let h: HandoffHarness;
  let handoff: Promise<unknown>;
  let seqAtOpen = 0;
  let askedAtOpen = 0;

  beforeAll(async () => {
    h = await startHandoffHarness({ rp: { challenge: 'cloudflare' } });
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const login = h.mcp.ok('auth_login');
    await h.approveOnPhone();
    if (((await login) as { status: string }).status !== 'challenge')
      throw new Error('no challenge');
    askedAtOpen = h.recording.requests.length;
    seqAtOpen = h.auditEvents().at(-1)?.seq ?? 0;
    handoff = h.mcp.ok('browser_handoff', { timeoutMs: 60_000 });
    handoff.catch(() => {});
    const end = Date.now() + 10_000;
    while (!h.daemon.handoffs.isOpen(h.agent.id)) {
      if (Date.now() > end) throw new Error('handoff did not open');
      await new Promise((r) => setTimeout(r, 50));
    }
  });
  afterAll(async () => h?.close());

  it('auth_login (and every other tool) is held while the owner has the page', async () => {
    const { connectAgent } = await import('./mcp-harness.ts');
    const c = await connectAgent(h.daemon.mcpUrl as string, h.agent);
    try {
      for (const tool of ['auth_login', 'auth_status', 'auth_enroll_passkey', 'browser_snapshot']) {
        expect(await c.err(tool)).toBe(HANDOFF_IN_PROGRESS);
      }
      expect(await c.err('browser_open', { url: `${h.rp.url}password/login` })).toBe(
        HANDOFF_IN_PROGRESS,
      );
    } finally {
      await c.close();
    }
  });

  it('a fill that reaches the broker anyway is denied handoff_open, before any approval', async () => {
    let performed = false;
    const target: FillTarget = {
      origin: { origin: h.rp.origin, host: 'rp.localhost' },
      first: 'password',
      perform: async () => {
        performed = true;
        return { outcome: 'success' };
      },
    };
    expect(await h.daemon.broker.fill({ id: h.agent.id, name: 'handoff-agent' }, target)).toBe(
      'denied',
    );
    expect(performed).toBe(false);
    const denied = h
      .auditEvents()
      .filter((e) => e.type === 'denied')
      .at(-1);
    expect(denied?.payload).toMatchObject({ kind: 'password.fill', reason: 'handoff_open' });
  });

  it('a page-initiated passkey sign-in or registration is denied handoff_open', async () => {
    const outcome = await h.page().evaluate(async () => {
      const r: string[] = [];
      for (const f of [
        () =>
          navigator.credentials.get({
            publicKey: { challenge: new Uint8Array(32), timeout: 3000 },
          }),
        () =>
          navigator.credentials.create({
            publicKey: {
              challenge: new Uint8Array(32),
              rp: { name: 'x' },
              user: { id: new Uint8Array(8), name: 'u', displayName: 'u' },
              pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
              timeout: 3000,
            },
          }),
      ]) {
        try {
          await f();
          r.push('OK');
        } catch (e) {
          r.push((e as Error).name);
        }
      }
      return r;
    });
    expect(outcome).toEqual(['NotAllowedError', 'NotAllowedError']);
    const reasons = h
      .auditEvents()
      .filter((e) => e.type === 'denied')
      .slice(-2)
      .map((e) => [e.payload.kind, e.payload.reason]);
    expect(reasons).toEqual([
      ['passkey.get', 'handoff_open'],
      ['passkey.create', 'handoff_open'],
    ]);
  });

  it('the handoff never produced an approval or a signer operation; after Done sign-in works', async () => {
    expect(h.recording.requests.length).toBe(askedAtOpen);
    const during = h.auditEvents().filter((e) => e.seq > seqAtOpen);
    for (const t of [
      'approval',
      'passkey.signed',
      'passkey.created',
      'fill.released',
      'grant.used',
    ]) {
      expect(
        during.some((e) => e.type === t),
        t,
      ).toBe(false);
    }
    await h.openLiveView();
    await h.tapOnPhone('#challenge-solve');
    await h.page().waitForURL('**/account', { timeout: 10_000 });
    await h.phonePage.click('#done');
    expect(await handoff).toEqual({ status: 'done' });
    await h
      .page()
      .evaluate(() =>
        navigator.credentials
          .get({ publicKey: { challenge: new Uint8Array(32), timeout: 2000 } })
          .catch(() => null),
      );
    const last = h
      .auditEvents()
      .filter((e) => e.type === 'denied')
      .at(-1);
    expect(last?.payload.reason).not.toBe('handoff_open');
    expect(h.daemon.broker.audit.verify()).toBeNull();
  });
});
