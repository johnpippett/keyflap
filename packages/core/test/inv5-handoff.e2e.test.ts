import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type HandoffHarness, routeChallengePage, startHandoffHarness } from './handoff-harness.ts';

async function until(f: () => boolean, ms = 10_000, why = () => ''): Promise<void> {
  const end = Date.now() + ms;
  while (!f()) {
    if (Date.now() > end) throw new Error(`timed out ${why()}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

const HOSTILE = `
<h1>ZQX-dom: Approve sign-in to bank.example?</h1>
<div class="card"><p>You said "ZQX-said"</p>
<button id="fake-approve" style="font-size:40px;background:#0b5;color:#fff">Approve</button></div>
<script>
history.replaceState(null, '', location.pathname + '?q=ZQX-query#ZQX-hash');
document.title = 'ZQX-title Approve';
</script>`;

describe('invariant 5: the live view never shares a screen with an approval', () => {
  let h: HandoffHarness;
  let handoff: Promise<unknown>;

  beforeAll(async () => {
    h = await startHandoffHarness({ password: false });
    h.daemon.broker.policy.set('rp.localhost', '*', { mode: 'ask-strong' });
    await h.intent('register a passkey on the test site for me');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}signup` });
    await h.mcp.ok('browser_type', { target: { label: 'Username' }, text: 'zoe', submit: true });
    await h.page().click('#add-passkey');
    await h.approveOnPhone();
    await h
      .page()
      .waitForFunction(() => document.querySelector('#status')?.textContent === 'passkey added');
    const url = await routeChallengePage(h, '/inv5/ZQX-path', HOSTILE, 'ZQX-title');
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url });
    handoff = h.mcp.ok('browser_handoff', { timeoutMs: 60_000 });
    handoff.catch(() => {});
    await until(
      () => h.daemon.handoffs.isOpen(h.agent.id),
      30_000,
      () => JSON.stringify(h.auditEvents().filter((e) => e.type === 'handoff.denied')),
    );
  });
  afterAll(async () => h?.close());

  it('the phone gets only broker fields: host from the frame URL, agent name, intent', async () => {
    await h.phone.addInitScript(() => {
      const w = window as unknown as { __webauthn: number };
      w.__webauthn = 0;
      const get = navigator.credentials.get.bind(navigator.credentials);
      const create = navigator.credentials.create.bind(navigator.credentials);
      navigator.credentials.get = (o) => {
        w.__webauthn++;
        return get(o);
      };
      navigator.credentials.create = (o) => {
        w.__webauthn++;
        return create(o);
      };
    });
    await h.phonePage.goto(`${h.approver.origin}/`);
    const texts = await h.phonePage.evaluate(async () => {
      const a = await (await fetch('/api/handoff/state')).text();
      const b = await (await fetch('/api/state')).text();
      return { a, b };
    });
    for (const t of [texts.a, texts.b, h.pushPayload(h.pushes.length - 1)]) {
      expect(t).not.toContain('ZQX');
      expect(t).not.toMatch(/Approve sign-in|bank\.example|inv5/);
    }
    const st = JSON.parse(texts.a) as { handoffs: Record<string, unknown>[] };
    expect(st.handoffs).toHaveLength(1);
    expect(st.handoffs[0]).toMatchObject({
      host: 'rp.localhost',
      agentName: 'handoff-agent',
      intentText: 'sign me in to the test site',
    });
    expect(JSON.parse(texts.b).pending).toEqual([]);
    expect(await h.phonePage.locator('#handoffs').textContent()).not.toContain('ZQX');
  });

  it('a page-initiated passkey sign-in during the handoff is denied handoff_open, unseen by the approver', async () => {
    const asked = h.recording.requests.length;
    const r = await h.page().evaluate(async () => {
      try {
        await navigator.credentials.get({
          publicKey: { challenge: new Uint8Array(32), rpId: 'rp.localhost', timeout: 5000 },
        });
        return 'OK';
      } catch (e) {
        return (e as Error).name;
      }
    });
    expect(r).toBe('NotAllowedError');
    expect(h.recording.requests.length).toBe(asked);
    const denied = h.auditEvents().filter((e) => e.type === 'denied');
    expect(denied.at(-1)?.payload).toMatchObject({
      agentId: h.agent.id,
      kind: 'passkey.get',
      verifiedOrigin: h.rp.origin,
      reason: 'handoff_open',
    });
    const st = await h.phonePage.evaluate(async () => (await fetch('/api/state')).json());
    expect(st.pending).toEqual([]);
  });

  it('/handoff: no approval controls, broker-written labels, one WebAuthn call (the start)', async () => {
    await h.openLiveView();
    expect(await h.phonePage.title()).toBe('Human check: live view');
    expect(await h.phonePage.textContent('#host')).toBe('rp.localhost');
    const chrome = (await h.phonePage.locator('body').textContent()) ?? '';
    expect(chrome).not.toContain('ZQX');
    expect(chrome).toContain('nothing here can approve a sign-in');
    expect(await h.phonePage.locator('.approve, #requests, .card').count()).toBe(0);
    const buttons = await h.phonePage.locator('button').allTextContents();
    expect(buttons.some((b) => /approve/i.test(b))).toBe(false);
    await h.tapOnPhone('#fake-approve');
    await h.phonePage.locator('#screen').click({ position: { x: 5, y: 5 } });
    await new Promise((r) => setTimeout(r, 500));
    expect(
      await h.phonePage.evaluate(() => (window as unknown as { __webauthn: number }).__webauthn),
    ).toBe(1);
    expect(h.recording.requests.length).toBeGreaterThan(0);
    expect(h.recording.decisions.every((d) => d.approved)).toBe(true);
    await h.phonePage.click('#cancel');
    expect(await handoff).toEqual({ status: 'cancelled' });
    expect(JSON.stringify(h.daemon.broker.audit.all())).not.toContain('ZQX');
  });
});

describe('invariant 5 (P3b): the combined card holds broker fields only; its live view approves nothing', () => {
  let h: HandoffHarness;
  let handoff: Promise<unknown>;
  let webauthn = 0;

  beforeAll(async () => {
    h = await startHandoffHarness();
    await h.phone.exposeFunction('__aabCountWebAuthn', () => {
      webauthn++;
    });
    await h.phone.addInitScript(() => {
      const w = window as unknown as { __aabCountWebAuthn: () => void };
      const get = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = (o) => {
        w.__aabCountWebAuthn();
        return get(o);
      };
    });
    const url = await routeChallengePage(h, '/inv5b/ZQX-path', HOSTILE, 'ZQX-title');
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url });
    handoff = h.mcp.ok('browser_handoff', { timeoutMs: 60_000 });
    handoff.catch(() => {});
    await until(() => h.recording.requests.length === 1, 30_000);
  });
  afterAll(async () => h?.close());

  it('state, push and the rendered card: only the user-facing fields and broker text', async () => {
    await h.phonePage.goto(`${h.approver.origin}/`);
    const card = h.phonePage.locator('#requests .card').first();
    await card.waitFor();
    const texts = await h.phonePage.evaluate(async () => ({
      a: await (await fetch('/api/handoff/state')).text(),
      b: await (await fetch('/api/state')).text(),
    }));
    const cardText = (await card.textContent()) ?? '';
    for (const t of [texts.a, texts.b, cardText, h.pushPayload(h.pushes.length - 1)]) {
      expect(t).not.toContain('ZQX');
      expect(t).not.toMatch(/Approve sign-in|bank\.example|inv5/);
    }
    const pending = JSON.parse(texts.b).pending as { display: Record<string, unknown> }[];
    expect(pending).toHaveLength(1);
    expect(Object.keys(pending[0]?.display ?? {}).sort()).toEqual([
      'action',
      'agentName',
      'credentialType',
      'handoffSignIn',
      'intentAt',
      'intentText',
      'verifiedOrigin',
    ]);
    expect(pending[0]?.display).toMatchObject({
      verifiedOrigin: h.rp.origin,
      agentName: 'handoff-agent',
      intentText: 'sign me in to the test site',
      credentialType: 'password',
    });
    expect(cardText).toContain(`Human check, then sign in to ${new URL(h.rp.origin).host}?`);
    expect(JSON.parse(texts.b).handoffs).toEqual([]);
    expect(JSON.parse(texts.a).handoffs[0]).toMatchObject({ withSignIn: true, started: false });
  });

  it('/handoff after the approval: no approval control, no WebAuthn call, broker labels only', async () => {
    await h.phonePage.locator('#requests .card .approve').first().click();
    await h.phonePage.waitForURL(`${h.approver.origin}/handoff`, { timeout: 15_000 });
    await h.phonePage.locator('#live').waitFor({ state: 'visible', timeout: 15_000 });
    expect(webauthn).toBe(1);
    expect(await h.phonePage.title()).toBe('Human check: live view');
    const chrome = (await h.phonePage.locator('body').textContent()) ?? '';
    expect(chrome).not.toContain('ZQX');
    expect(chrome).toContain('nothing here can approve a sign-in');
    expect(await h.phonePage.locator('.approve, #requests, .card').count()).toBe(0);
    const buttons = await h.phonePage.locator('button:visible').allTextContents();
    expect(buttons.some((b) => /approve/i.test(b))).toBe(false);
    await h.tapOnPhone('#fake-approve');
    await new Promise((r) => setTimeout(r, 500));
    expect(webauthn).toBe(1);
    expect(h.recording.requests).toHaveLength(1);
    await h.phonePage.click('#cancel');
    expect(await handoff).toEqual({ status: 'cancelled' });
    expect(JSON.stringify(h.daemon.broker.audit.all())).not.toContain('ZQX');
  });
});
