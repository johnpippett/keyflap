import { randomUUID } from 'node:crypto';
import { fillScope, sha256B64url } from '@aab/signer/approval';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ALICE_PW, type HandoffHarness, startHandoffHarness } from './handoff-harness.ts';

async function countWebAuthn(h: HandoffHarness): Promise<() => number> {
  let n = 0;
  await h.phone.exposeFunction('__aabCountWebAuthn', () => {
    n++;
  });
  await h.phone.addInitScript(() => {
    const w = window as unknown as { __aabCountWebAuthn: () => void };
    const get = navigator.credentials.get.bind(navigator.credentials);
    const create = navigator.credentials.create.bind(navigator.credentials);
    navigator.credentials.get = (o) => {
      w.__aabCountWebAuthn();
      return get(o);
    };
    navigator.credentials.create = (o) => {
      w.__aabCountWebAuthn();
      return create(o);
    };
  });
  return () => n;
}

async function cardOnPhone(h: HandoffHarness): Promise<string> {
  if (h.phonePage.url().startsWith(`${h.approver.origin}/handoff`)) {
    await h.phonePage.waitForURL(`${h.approver.origin}/`, { timeout: 15_000 });
  } else {
    await h.phonePage.goto(`${h.approver.origin}/`);
  }
  const card = h.phonePage.locator('#requests .card').first();
  await card.waitFor({ timeout: 15_000 });
  return (await card.textContent()) ?? '';
}

async function liveImage(h: HandoffHarness): Promise<void> {
  await h.phonePage.locator('#live').waitFor({ state: 'visible', timeout: 15_000 });
  await h.phonePage.waitForFunction(() => {
    const img = document.querySelector('#screen') as HTMLImageElement | null;
    return img?.complete === true && img.naturalWidth > 0;
  });
}

describe('P3b: one approval for the human check and the sign-in after it (full flow)', () => {
  let h: HandoffHarness;
  let webauthn: () => number;

  beforeAll(async () => {
    h = await startHandoffHarness({ rp: { challenge: 'aws-waf', challengeAt: 'login-page' } });
    webauthn = await countWebAuthn(h);
  });
  afterAll(async () => h?.close());

  it('check before the password → browser_handoff → ONE approval → live view → Done → auth_login signs in without a prompt', async () => {
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const before = await h.mcp.ok<{ snapshot: string; humanCheck: boolean }>('browser_snapshot');
    expect(before.humanCheck).toBe(true);
    expect(before.snapshot).not.toContain('Password');
    const pushes = h.pushes.length;

    const handoff = h.mcp.ok<{ status: string }>('browser_handoff', { timeoutMs: 90_000 });
    await expect.poll(() => h.pushes.length, { timeout: 10_000 }).toBe(pushes + 1);
    expect(h.pushPayload(pushes)).toBe('{"t":"approval"}');

    const card = await cardOnPhone(h);
    expect(card).toContain(`Human check, then sign in to ${new URL(h.rp.origin).host}?`);
    expect(card).toContain('sign me in to the test site');
    expect(card).toContain(h.rp.origin);
    expect(card).toContain('handoff-agent');
    expect(card).toContain('password (sign-in)');
    expect(card).toContain('One sign-in within 7 minutes, without asking again.');
    expect(await h.phonePage.locator('#handoffs a').count()).toBe(0);
    expect(h.daemon.handoffs.isOpen(h.agent.id)).toBe(true);

    await h.phonePage.locator('#requests .card .approve').first().click();
    await h.phonePage.waitForURL(`${h.approver.origin}/handoff`, { timeout: 15_000 });
    await liveImage(h);
    expect(await h.phonePage.textContent('#host')).toBe('rp.localhost');
    expect(await h.phonePage.isVisible('#signin-note')).toBe(true);
    expect(await h.phonePage.isVisible('#start')).toBe(false);
    expect(await h.phonePage.locator('.approve, #requests').count()).toBe(0);
    const started = h.auditEvents().filter((e) => e.type === 'handoff.started');
    expect(started).toHaveLength(1);
    expect(started[0]?.payload).toMatchObject({ via: 'approval' });

    await h.tapOnPhone('#challenge-solve');
    await h.page().locator('input[name="password"]').waitFor({ timeout: 10_000 });
    await h.phonePage.click('#done');
    expect(await handoff).toEqual({ status: 'done' });

    expect(h.recording.requests).toHaveLength(1);
    expect(await h.mcp.ok('auth_login')).toEqual({ status: 'success' });
    expect(h.recording.requests).toHaveLength(1);
    expect(h.rp.logins.at(-1)).toEqual({ username: 'alice', method: 'password' });
    const snap = await h.mcp.ok<{ snapshot: string; humanCheck: boolean }>('browser_snapshot');
    expect(snap.snapshot).toContain('Signed in as alice');
    expect(snap.humanCheck).toBe(false);
    expect(webauthn()).toBe(1);

    const ev = h.auditEvents();
    const types = ev.map((e) => e.type);
    for (const t of [
      'handoff.requested',
      'grant.created',
      'handoff.started',
      'handoff.ended',
      'grant.armed',
      'grant.used',
      'fill.completed',
    ]) {
      expect(types, t).toContain(t);
    }
    const grant = ev.find((e) => e.type === 'grant.created')?.payload;
    expect(grant).toMatchObject({ agentId: h.agent.id, singleUse: true });
    expect(ev.find((e) => e.type === 'grant.used')?.payload).toMatchObject({
      grantId: grant?.grantId,
      singleUse: true,
    });
    expect(ev.find((e) => e.type === 'handoff.requested')?.payload).toMatchObject({
      withSignIn: true,
    });
    const at = (t: string) => types.indexOf(t);
    expect(at('grant.created')).toBeLessThan(at('handoff.started'));
    expect(at('handoff.ended')).toBeLessThan(at('grant.armed'));
    expect(at('grant.armed')).toBeLessThan(at('grant.used'));
    expect(ev.find((e) => e.type === 'fill.completed')?.payload).toMatchObject({
      outcome: 'success',
    });
    expect(h.daemon.broker.audit.verify()).toBeNull();

    const everything = await h.mcp.everything();
    expect(everything).not.toMatch(/"type":"image"|image\/jpeg|data:image|\/9j\//);
    expect(everything).not.toContain(ALICE_PW);
    await expect(
      h.daemon.signer.client.releaseSecret({
        itemId: h.daemon.broker.credentials.passwordsForDomain('rp.localhost')[0]
          ?.signer_ref as string,
        field: 'password',
        approval: {
          statement: {
            v: 1,
            requestId: randomUUID(),
            kind: 'fill',
            verifiedOrigin: h.rp.origin,
            rpId: 'rp.localhost',
            credentialId: h.daemon.broker.credentials.passwordsForDomain('rp.localhost')[0]
              ?.signer_ref as string,
            intentHash: 'aW50ZW50',
            clientDataHash: sha256B64url(fillScope(['password'])),
            userVerified: false,
            issuedAt: Date.now(),
            expiresAt: Date.now() + 60_000,
          },
          grantId: grant?.grantId as string,
          agentId: h.agent.id,
        },
      }),
    ).rejects.toThrow('grant_used');
  });

  it('the grant was single use: the next sign-in asks the owner as usual', async () => {
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const login = h.mcp.ok<{ status: string }>('auth_login');
    const card = await cardOnPhone(h);
    expect(card).toContain('Sign in?');
    expect(card).not.toContain('Human check');
    await h.phonePage.locator('#requests .card .approve').first().click();
    expect(await login).toEqual({ status: 'success' });
    expect(h.recording.requests).toHaveLength(2);
  });
});

describe('invariant 6 (P3b): Cancel drops the grant; no fill without it', () => {
  let h: HandoffHarness;

  beforeAll(async () => {
    h = await startHandoffHarness({ rp: { challenge: 'aws-waf', challengeAt: 'login-page' } });
  });
  afterAll(async () => h?.close());

  it('approve, solve, Cancel: the grant is gone (core and signer); auth_login asks again', async () => {
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const handoff = h.mcp.ok<{ status: string }>('browser_handoff', { timeoutMs: 90_000 });
    await cardOnPhone(h);
    await h.phonePage.locator('#requests .card .approve').first().click();
    await h.phonePage.waitForURL(`${h.approver.origin}/handoff`, { timeout: 15_000 });
    await liveImage(h);
    await h.tapOnPhone('#challenge-solve');
    await h.page().locator('input[name="password"]').waitFor({ timeout: 10_000 });
    await h.phonePage.click('#cancel');
    expect(await handoff).toEqual({ status: 'cancelled' });

    const ev = h.auditEvents();
    const grantId = ev.find((e) => e.type === 'grant.created')?.payload.grantId as string;
    expect(ev.find((e) => e.type === 'grant.dropped')?.payload).toMatchObject({
      grantId,
      reason: 'handoff_cancelled',
    });
    expect(ev.some((e) => e.type === 'grant.armed')).toBe(false);
    const item = h.daemon.broker.credentials.passwordsForDomain('rp.localhost')[0]
      ?.signer_ref as string;
    await expect
      .poll(() =>
        h.daemon.signer.client
          .releaseSecret({
            itemId: item,
            field: 'password',
            approval: {
              statement: {
                v: 1,
                requestId: randomUUID(),
                kind: 'fill',
                verifiedOrigin: h.rp.origin,
                rpId: 'rp.localhost',
                credentialId: item,
                intentHash: 'aW50ZW50',
                clientDataHash: sha256B64url(fillScope(['password'])),
                userVerified: false,
                issuedAt: Date.now(),
                expiresAt: Date.now() + 60_000,
              },
              grantId,
              agentId: h.agent.id,
            },
          })
          .then(
            () => 'released',
            (e: Error) => e.message,
          ),
      )
      .toBe('unknown_grant');

    const login = h.mcp.ok<{ status: string }>('auth_login');
    const card = await cardOnPhone(h);
    expect(card).toContain('Sign in?');
    await h.phonePage.locator('#requests .card .deny').first().click();
    expect(await login).toEqual({ status: 'denied' });
    expect(h.recording.requests).toHaveLength(2);
    expect(h.auditEvents().some((e) => e.type === 'fill.released')).toBe(false);
    expect(h.auditEvents().some((e) => e.type === 'grant.used')).toBe(false);
  });
});

describe('P3b fallback: a high-risk site keeps the plain handoff and a separate approval', () => {
  let h: HandoffHarness;
  let webauthn: () => number;

  beforeAll(async () => {
    h = await startHandoffHarness({
      rp: { challenge: 'aws-waf', challengeAt: 'login-page' },
      daemon: { highRiskDomains: ['rp.localhost'] },
    });
    webauthn = await countWebAuthn(h);
  });
  afterAll(async () => h?.close());

  it('handoff push → Face ID start on /handoff → Done → its own (strong) sign-in approval', async () => {
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const pushes = h.pushes.length;
    const handoff = h.mcp.ok<{ status: string }>('browser_handoff', { timeoutMs: 90_000 });
    await expect.poll(() => h.pushes.length, { timeout: 10_000 }).toBe(pushes + 1);
    expect(h.pushPayload(pushes)).toBe('{"t":"handoff","host":"rp.localhost"}');
    expect(h.recording.requests).toHaveLength(0);
    expect(h.auditEvents().find((e) => e.type === 'handoff.requested')?.payload).toMatchObject({
      signInSkipped: 'high_risk',
    });
    expect(
      h.auditEvents().some((e) => e.type === 'handoff.requested' && e.payload.withSignIn),
    ).toBe(false);

    await h.openLiveView();
    expect(await h.phonePage.isVisible('#signin-note')).toBe(false);
    await h.tapOnPhone('#challenge-solve');
    await h.page().locator('input[name="password"]').waitFor({ timeout: 10_000 });
    await h.phonePage.click('#done');
    expect(await handoff).toEqual({ status: 'done' });

    const login = h.mcp.ok<{ status: string }>('auth_login');
    const card = await h.approveOnPhone();
    expect(card).toContain('Sign in?');
    expect(card).not.toContain('Human check');
    expect(await login).toEqual({ status: 'success' });
    expect(h.recording.requests).toHaveLength(1);
    expect(h.recording.requests[0]?.policy.tier).toBe('ask-strong');
    expect(webauthn()).toBe(2);
    expect(h.auditEvents().some((e) => e.type.startsWith('grant.'))).toBe(false);
  });
});
