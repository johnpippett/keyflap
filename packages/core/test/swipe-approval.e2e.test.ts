import { request } from 'node:http';
import type { LookupFunction } from 'node:net';
import type { ApprovalRequest } from '@aab/approver';
import { type ApprovalStatement, approvalChallenge } from '@aab/signer/approval';
import type { Locator, Page, Route } from 'playwright';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type HandoffHarness, startHandoffHarness } from './handoff-harness.ts';

const loopbackLookup = ((_host: string, opts: unknown, cb: (...a: unknown[]) => void) => {
  if ((opts as { all?: boolean }).all) cb(null, [{ address: '127.0.0.1', family: 4 }]);
  else cb(null, '127.0.0.1', 4);
}) as unknown as LookupFunction;

async function fetchRoute(route: Route) {
  const req = route.request();
  const headers = await req.allHeaders();
  const postData = req.postDataBuffer();
  return new Promise<{ status: number; headers: Record<string, string>; body: unknown }>(
    (resolve, reject) => {
      const r = request(
        req.url(),
        { method: req.method(), headers, lookup: loopbackLookup },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const out: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (v !== undefined && k !== 'content-length' && k !== 'transfer-encoding') {
                out[k] = Array.isArray(v) ? v.join('\n') : v;
              }
            }
            resolve({
              status: res.statusCode ?? 0,
              headers: out,
              body: JSON.parse(Buffer.concat(chunks).toString()),
            });
          });
        },
      );
      r.on('error', reject);
      r.end(postData ?? undefined);
    },
  );
}

const forBank = (s: ApprovalStatement): ApprovalStatement => ({
  ...s,
  verifiedOrigin: 'https://bank.localhost',
  rpId: 'bank.localhost',
});

const extraRequest = (
  n: number,
  display: Partial<ApprovalRequest['display']> = {},
  tier: 'ask' | 'ask-strong' = 'ask',
): ApprovalRequest => ({
  display: {
    intentText: `extra request ${n}`,
    intentAt: Date.now(),
    verifiedOrigin: `https://site${n}.example.org`,
    agentName: 'extra-agent',
    credentialType: 'passkey',
    action: 'sign-in',
    ...display,
  },
  policy: { tier },
  binding: {
    requestId: `extra-${n}`,
    kind: 'webauthn.get',
    rpId: `site${n}.example.org`,
    credentialId: `c${n}`,
    intentHash: 'aA',
    clientDataHash: 'bB',
  },
});

const strongExtra = (n: number): ApprovalRequest => {
  const base = extraRequest(
    n,
    {
      verifiedOrigin: 'https://login.bank.example',
      credentialType: 'password',
      keepSignedInSite: 'bank.example',
    },
    'ask-strong',
  );
  return { ...base, binding: { ...base.binding, kind: 'fill', rpId: 'bank.example' } };
};

const parseTransform = (t: string) => {
  if (t === 'none') return { tilt: 0, shift: 0, resting: true };
  const m = /matrix\(([^)]+)\)/.exec(t);
  const [a = 1, b = 0, , , tx = 0] = (m?.[1] ?? '').split(',').map(Number);
  return { tilt: (Math.atan2(b, a) * 180) / Math.PI, shift: tx, resting: false };
};

interface Grab {
  x: number;
  y: number;
  width: number;
}

describe('swipe approval cards on the phone page', () => {
  let h: HandoffHarness;
  let page: Page;
  const calls = { challenge: 0, decide: [] as string[] };
  const logins: Promise<unknown>[] = [];
  const extras: AbortController[] = [];
  const violations: string[] = [];
  let openGate = () => {};

  const released = () => h.auditEvents().filter((e) => e.type === 'fill.released').length;
  const gets = () =>
    page.evaluate(() => (window as unknown as { __gets: { userVerification: unknown }[] }).__gets);
  const transformOf = async (card: Locator) =>
    parseTransform(await card.locator('.face').evaluate((el) => getComputedStyle(el).transform));
  const opacityOf = (card: Locator, stamp: string) =>
    card
      .locator(`.stamp.${stamp}`)
      .evaluate((el) => Number.parseFloat(getComputedStyle(el).opacity));

  const startLogin = async () => {
    const ctx = (await h.daemon.sessions.get(h.agent)).context;
    await ctx.clearCookies();
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const login = h.mcp.ok<{ status: string }>('auth_login');
    logins.push(login);
    return { result: login };
  };
  const showCard = async () => {
    await page.goto(`${h.approver.origin}/`);
    const card = page.locator('#requests .card').first();
    await card.waitFor({ timeout: 15_000 });
    return card;
  };
  const addExtra = (req: ApprovalRequest) => {
    const ac = new AbortController();
    extras.push(ac);
    void h.approver.request(req, { signal: ac.signal });
  };

  const grab = async (card: Locator): Promise<Grab> => {
    const box = await card.boundingBox();
    if (!box) throw new Error('card has no box');
    const g = { x: box.x + box.width / 2, y: box.y + 70, width: box.width };
    await page.mouse.move(g.x, g.y);
    await page.mouse.down();
    return g;
  };
  const pullTo = (g: Grab, fraction: number) =>
    page.mouse.move(g.x + g.width * fraction, g.y, { steps: 12 });
  const swipe = async (card: Locator, fraction: number) => {
    const g = await grab(card);
    await pullTo(g, fraction);
    await page.mouse.up();
  };

  beforeAll(async () => {
    h = await startHandoffHarness();
    page = h.phonePage;
    await h.phone.addInitScript(() => {
      const w = window as unknown as { __gets: { userVerification: unknown }[] };
      w.__gets = [];
      const get = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = (o) => {
        w.__gets.push({ userVerification: o?.publicKey?.userVerification });
        return get(o);
      };
    });
    page.on('console', (m) => {
      if (/content security policy/i.test(m.text())) violations.push(m.text());
    });
    page.on('request', (req) => {
      const path = new URL(req.url()).pathname;
      if (path === '/api/challenge') calls.challenge++;
      if (path === '/api/decide') calls.decide.push(req.postDataJSON().decision);
    });
  });
  afterAll(async () => h?.close());

  beforeEach(() => {
    calls.challenge = 0;
    calls.decide.length = 0;
  });
  afterEach(async () => {
    openGate();
    for (const ac of extras.splice(0)) ac.abort();
    await page.mouse.up().catch(() => {});
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page
      .evaluate(() => {
        for (const b of document.querySelectorAll('#requests .deny')) (b as HTMLElement).click();
      })
      .catch(() => {});
    await Promise.allSettled(logins.splice(0));
    expect(violations.splice(0)).toEqual([]);
  });

  it('dragging right past the threshold approves at the broker through the real signer, after Face ID', async () => {
    const before = released();
    const login = await startLogin();
    const card = await showCard();
    await swipe(card, 0.6);
    await card.waitFor({ state: 'detached', timeout: 10_000 });

    expect(await login.result).toEqual({ status: 'success' });
    expect(await gets()).toEqual([{ userVerification: 'required' }]);
    expect(calls.challenge).toBe(1);
    expect(calls.decide).toEqual(['approve']);
    const d = h.recording.decisions.at(-1);
    expect(d?.approved).toBe(true);
    if (!d?.approved) throw new Error('not approved');
    expect(d.approval.webauthn).toBeDefined();
    expect(released()).toBe(before + 1);
  });

  it('a drag shorter than the threshold follows the finger, asks for nothing and springs back', async () => {
    const login = await startLogin();
    const card = await showCard();
    const g = await grab(card);
    await pullTo(g, 0.2);
    const held = await transformOf(card);
    expect(held.shift).toBeGreaterThan(g.width * 0.15);
    expect(held.shift).toBeLessThan(g.width * 0.3);
    await page.mouse.up();

    await page.waitForTimeout(500);
    expect(calls.challenge).toBe(0);
    expect(calls.decide).toEqual([]);
    expect(await gets()).toEqual([]);
    expect(await card.isVisible()).toBe(true);
    await expect.poll(async () => (await transformOf(card)).resting, { timeout: 5_000 }).toBe(true);

    await card.locator('.deny').click();
    expect(await login.result).toEqual({ status: 'denied' });
  });

  it('dragging left denies, posting the decision once and never asking for Face ID', async () => {
    const before = released();
    const login = await startLogin();
    const card = await showCard();
    await swipe(card, -0.6);
    await card.waitFor({ state: 'detached', timeout: 10_000 });

    expect(await login.result).toEqual({ status: 'denied' });
    expect(calls.decide).toEqual(['deny']);
    expect(calls.challenge).toBe(0);
    expect(await gets()).toEqual([]);
    expect(h.recording.decisions.at(-1)).toMatchObject({ approved: false, reason: 'user_denied' });
    expect(released()).toBe(before);
  });

  it('a drag whose pointer capture is lost lets go of the card: it settles, and nothing is decided', async () => {
    await startLogin();
    const card = await showCard();
    const g = await grab(card);
    await pullTo(g, 0.6);
    const dragging = () =>
      card.locator('.face').evaluate((el) => el.classList.contains('dragging'));
    expect(await dragging()).toBe(true);

    await card.locator('.face').evaluate((el) => {
      for (const id of [1, 2, 3]) if (el.hasPointerCapture(id)) el.releasePointerCapture(id);
    });

    await expect.poll(dragging, { timeout: 5_000 }).toBe(false);
    await page.mouse.move(g.x - g.width * 0.6, g.y, { steps: 6 });
    await page.mouse.up();
    await expect.poll(async () => (await transformOf(card)).shift).toBe(0);
    expect(calls.decide).toEqual([]);
    expect(calls.challenge).toBe(0);
  });

  it('with a lying core a swipe right denies and says why, exactly as the button does', async () => {
    await page.route('**/api/challenge', async (route) => {
      const res = await fetchRoute(route);
      const body = res.body as { statement: ApprovalStatement };
      const lie = forBank(body.statement);
      await route.fulfill({
        status: res.status,
        headers: res.headers,
        json: { ...body, statement: lie, challenge: approvalChallenge(lie) },
      });
    });
    const before = released();
    const login = await startLogin();
    const card = await showCard();
    await swipe(card, 0.6);

    await expect
      .poll(() => card.locator('.error').textContent(), { timeout: 10_000 })
      .toContain("doesn't match what this card shows (site)");
    expect(await card.locator('.error').textContent()).toContain('Denied');
    expect(await login.result).toEqual({ status: 'denied' });
    expect(await gets()).toEqual([]);
    expect(calls.decide).toEqual(['deny']);
    expect(h.recording.decisions.at(-1)).toMatchObject({ approved: false, reason: 'user_denied' });
    expect(released()).toBe(before);
  });

  it('with a lying core whose denial the broker does not take, the card says so instead of "Denied"', async () => {
    await page.route('**/api/challenge', async (route) => {
      const res = await fetchRoute(route);
      const body = res.body as { statement: ApprovalStatement };
      const lie = forBank(body.statement);
      await route.fulfill({
        status: res.status,
        headers: res.headers,
        json: { ...body, statement: lie, challenge: approvalChallenge(lie) },
      });
    });
    await page.route('**/api/decide', (route) =>
      route.fulfill({ status: 500, json: { error: 'broker unavailable' } }),
    );
    await startLogin();
    const card = await showCard();
    await swipe(card, 0.6);

    await expect
      .poll(() => card.locator('.error').textContent(), { timeout: 10_000 })
      .toContain("doesn't match what this card shows (site)");
    const shown = (await card.locator('.error').textContent()) ?? '';
    expect(shown).toContain('Not approved');
    expect(shown).not.toContain('Denied');
    expect(await gets()).toEqual([]);
  });

  it('when Face ID is cancelled the card stays, says "Not approved", and nothing is posted', async () => {
    const login = await startLogin();
    const card = await showCard();
    await page.evaluate(() => {
      navigator.credentials.get = () =>
        Promise.reject(new DOMException('Face ID was cancelled', 'NotAllowedError'));
    });
    await swipe(card, 0.6);

    await expect
      .poll(() => card.locator('.error').textContent(), { timeout: 10_000 })
      .toContain('Not approved');
    await expect.poll(async () => (await transformOf(card)).resting, { timeout: 5_000 }).toBe(true);
    expect(await card.isVisible()).toBe(true);
    expect(calls.challenge).toBe(1);
    expect(calls.decide).toEqual([]);

    await card.locator('.deny').click();
    expect(await login.result).toEqual({ status: 'denied' });
  });

  it('the card leaves only after the broker accepts the approval', async () => {
    await page.route('**/api/decide', async (route) => {
      if (route.request().postDataJSON().decision === 'approve') {
        await route.fulfill({ status: 400, json: { error: 'bad_credential' } });
      } else await route.continue();
    });
    const login = await startLogin();
    const card = await showCard();
    await swipe(card, 0.6);

    await expect
      .poll(() => card.locator('.error').textContent(), { timeout: 10_000 })
      .toContain('Not approved: bad_credential');
    await page.waitForTimeout(700);
    expect(await card.isVisible()).toBe(true);
    expect((await transformOf(card)).resting).toBe(true);

    await card.locator('.deny').click();
    expect(await login.result).toEqual({ status: 'denied' });
  });

  it('a drag that starts on the "Keep me signed in" checkbox or its label does not move the card', async () => {
    addExtra(strongExtra(1));
    const card = await showCard();
    await card.locator('.keep').waitFor();

    for (const part of ['.keep-box', '.keep-text']) {
      const box = await card.locator(part).boundingBox();
      if (!box) throw new Error(`no box for ${part}`);
      const x = box.x + box.width / 2;
      const y = box.y + box.height / 2;
      await page.mouse.move(x, y);
      await page.mouse.down();
      await page.mouse.move(x + 250, y, { steps: 10 });
      expect((await transformOf(card)).resting, part).toBe(true);
      await page.mouse.up();
    }
    expect(calls.challenge).toBe(0);

    const g = await grab(card);
    await pullTo(g, 0.2);
    expect((await transformOf(card)).resting).toBe(false);
    await pullTo(g, 0);
    await page.mouse.up();
  });

  it('a poll during a drag leaves the dragged card as it is, even when a new request arrives', async () => {
    const login = await startLogin();
    const card = await showCard();
    await card.evaluate((el) => {
      (el as unknown as { dragMarker: string }).dragMarker = 'same node';
    });
    const g = await grab(card);
    await pullTo(g, 0.2);
    const before = await transformOf(card);

    addExtra(extraRequest(2));
    await expect.poll(() => page.locator('#requests .card').count(), { timeout: 10_000 }).toBe(2);

    const first = page.locator('#requests .card').first();
    expect(
      await first.evaluate((el) => (el as unknown as { dragMarker?: string }).dragMarker),
    ).toBe('same node');
    expect(await first.locator('.face').evaluate((el) => el.classList.contains('dragging'))).toBe(
      true,
    );
    expect((await transformOf(first)).shift).toBeCloseTo(before.shift, 1);
    expect(await first.textContent()).toContain('sign me in to the test site');
    await pullTo(g, 0);
    await page.mouse.up();

    await expect
      .poll(async () => (await transformOf(first)).resting, { timeout: 5_000 })
      .toBe(true);
    expect(calls.challenge).toBe(0);
    await first.locator('.deny').click();
    expect(await login.result).toEqual({ status: 'denied' });
  });

  it('tilts at most 10 degrees, and not at all when the phone asks for reduced motion', async () => {
    const login = await startLogin();
    const card = await showCard();

    let g = await grab(card);
    await pullTo(g, 0.9);
    const far = await transformOf(card);
    expect(far.tilt).toBeGreaterThan(9.5);
    expect(far.tilt).toBeLessThanOrEqual(10.001);
    expect(far.shift).toBeGreaterThan(g.width * 0.8);
    await pullTo(g, -0.9);
    expect((await transformOf(card)).tilt).toBeLessThan(-9.5);
    await pullTo(g, 0);
    await page.mouse.up();

    await page.emulateMedia({ reducedMotion: 'reduce' });
    g = await grab(card);
    await pullTo(g, 0.25);
    const still = await transformOf(card);
    expect(still.tilt).toBe(0);
    expect(still.shift).toBeGreaterThan(g.width * 0.2);
    await pullTo(g, 0);
    await page.mouse.up();

    expect(calls.challenge).toBe(0);
    await card.locator('.deny').click();
    expect(await login.result).toEqual({ status: 'denied' });
  });

  it('the check fades in on the top-left while dragging right, the cross on the top-right while dragging left, and the icon pops past the threshold', async () => {
    const login = await startLogin();
    const card = await showCard();
    const armed = (stamp: string) =>
      card.locator(`.stamp.${stamp}`).evaluate((el) => el.classList.contains('armed'));
    expect(await opacityOf(card, 'yes')).toBe(0);
    expect(await opacityOf(card, 'no')).toBe(0);

    const g = await grab(card);
    await pullTo(g, 0.15);
    const partial = await opacityOf(card, 'yes');
    expect(partial).toBeGreaterThan(0.2);
    expect(partial).toBeLessThan(0.9);
    expect(await opacityOf(card, 'no')).toBe(0);
    expect(await armed('yes')).toBe(false);

    await pullTo(g, 0.5);
    expect(await opacityOf(card, 'yes')).toBe(1);
    expect(await armed('yes')).toBe(true);

    await pullTo(g, -0.15);
    expect(await opacityOf(card, 'yes')).toBe(0);
    expect(await opacityOf(card, 'no')).toBeGreaterThan(0.2);
    expect(await armed('yes')).toBe(false);

    await pullTo(g, -0.5);
    expect(await opacityOf(card, 'no')).toBe(1);
    expect(await armed('no')).toBe(true);

    const face = (await card.locator('.face').boundingBox()) as { x: number; width: number };
    const yes = (await card.locator('.stamp.yes').boundingBox()) as { x: number };
    const no = (await card.locator('.stamp.no').boundingBox()) as { x: number; width: number };
    expect(yes.x).toBeLessThan(face.x + face.width / 2);
    expect(no.x + no.width).toBeGreaterThan(face.x + face.width / 2);

    await pullTo(g, 0);
    await page.mouse.up();
    expect(calls.challenge).toBe(0);
    await card.locator('.deny').click();
    expect(await login.result).toEqual({ status: 'denied' });
  });

  it('one decision at a time: a tap or a second drag while an approval is in flight does nothing', async () => {
    const gate = new Promise<void>((r) => {
      openGate = r;
    });
    await page.route('**/api/challenge', async (route) => {
      await gate;
      await route.continue();
    });
    const login = await startLogin();
    const card = await showCard();
    await swipe(card, 0.6);
    await expect.poll(() => calls.challenge, { timeout: 5_000 }).toBe(1);
    await expect.poll(async () => (await transformOf(card)).resting, { timeout: 5_000 }).toBe(true);

    await card.locator('.approve').click();
    const again = await grab(card);
    await pullTo(again, 0.6);
    expect((await transformOf(card)).resting).toBe(true);
    await page.mouse.up();
    await swipe(card, -0.6);
    await card.locator('.deny').click();
    await page.waitForTimeout(500);
    expect(calls.challenge).toBe(1);
    expect(calls.decide).toEqual([]);

    openGate();
    await card.waitFor({ state: 'detached', timeout: 10_000 });
    expect(await login.result).toEqual({ status: 'success' });
    expect(calls.challenge).toBe(1);
    expect(calls.decide).toEqual(['approve']);
    expect(await gets()).toHaveLength(1);
  });

  it('a finger drag works too, not only a mouse', async () => {
    const login = await startLogin();
    const card = await showCard();
    const cdp = await h.phone.newCDPSession(page);
    const touch = async (type: 'touchStart' | 'touchMove' | 'touchEnd', x: number, y: number) =>
      cdp.send('Input.dispatchTouchEvent', {
        type,
        touchPoints: type === 'touchEnd' ? [] : [{ x, y }],
      });
    const box = (await card.boundingBox()) as { x: number; y: number; width: number };
    const x = box.x + box.width / 2;
    const y = box.y + 70;

    await touch('touchStart', x, y);
    for (let i = 1; i <= 10; i++) await touch('touchMove', x + (box.width * 0.2 * i) / 10, y);
    const held = await transformOf(card);
    expect(held.shift).toBeGreaterThan(box.width * 0.15);
    await touch('touchEnd', x, y);
    await page.waitForTimeout(500);
    expect(calls.challenge).toBe(0);
    await expect.poll(async () => (await transformOf(card)).resting, { timeout: 5_000 }).toBe(true);

    await touch('touchStart', x, y);
    for (let i = 1; i <= 10; i++) await touch('touchMove', x + (box.width * 0.6 * i) / 10, y);
    await touch('touchEnd', x + box.width * 0.6, y);
    await card.waitFor({ state: 'detached', timeout: 10_000 });
    expect(await login.result).toEqual({ status: 'success' });
    expect(calls.decide).toEqual(['approve']);
  });

  it('the Approve and Deny buttons still work, named by their labels and carrying no words', async () => {
    const approving = await startLogin();
    let card = await showCard();
    const approve = card.getByRole('button', { name: 'Approve', exact: true });
    const deny = card.getByRole('button', { name: 'Deny', exact: true });
    expect((await approve.innerText()).trim()).toBe('');
    expect((await deny.innerText()).trim()).toBe('');
    expect(await card.locator('button.approve').count()).toBe(1);
    expect(await card.locator('button.deny').count()).toBe(1);
    await approve.click();
    await card.waitFor({ state: 'detached', timeout: 10_000 });
    expect(await approving.result).toEqual({ status: 'success' });
    expect(await gets()).toEqual([{ userVerification: 'required' }]);
    expect(calls.decide).toEqual(['approve']);

    calls.decide.length = 0;
    const denying = await startLogin();
    card = await showCard();
    await card.getByRole('button', { name: 'Deny', exact: true }).click();
    await card.waitFor({ state: 'detached', timeout: 10_000 });
    expect(await denying.result).toEqual({ status: 'denied' });
    expect(calls.decide).toEqual(['deny']);
    expect(calls.challenge).toBe(1);
  });

  it('stacks up to two more requests behind the front card; only the front one can be acted on, and the next steps up when it is decided', async () => {
    const login = await startLogin();
    await showCard();
    for (const n of [1, 2, 3]) {
      addExtra(extraRequest(n));
      await expect
        .poll(() => page.locator('#requests .card').count(), { timeout: 10_000 })
        .toBe(n + 1);
    }
    const cards = page.locator('#requests .card');
    const inert = () => cards.evaluateAll((els) => els.map((el) => (el as HTMLElement).inert));
    const shown = () =>
      cards.evaluateAll((els) => els.map((el) => getComputedStyle(el).display !== 'none'));

    expect(await inert()).toEqual([false, true, true, true]);
    expect(await shown()).toEqual([true, true, true, false]);
    expect(await cards.nth(0).textContent()).toContain('sign me in to the test site');
    expect(await cards.nth(1).textContent()).toContain('extra request 1');

    await swipe(cards.nth(0), -0.6);
    expect(await login.result).toEqual({ status: 'denied' });
    await expect.poll(() => cards.count(), { timeout: 10_000 }).toBe(3);
    expect(await inert()).toEqual([false, true, true]);
    expect(await shown()).toEqual([true, true, true]);
    expect(await cards.nth(0).textContent()).toContain('extra request 1');
  });
});
