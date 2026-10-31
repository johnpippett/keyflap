import { request } from 'node:http';
import type { LookupFunction } from 'node:net';
import { type ApprovalStatement, approvalChallenge } from '@aab/signer/approval';
import type { Route } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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

describe('invariant 5: the phone signs only what its card shows, whatever the core says', () => {
  let h: HandoffHarness;
  const gets = () => h.phonePage.evaluate(() => (window as unknown as { __gets: number }).__gets);

  beforeAll(async () => {
    h = await startHandoffHarness({ rp: { challenge: 'aws-waf' } });
    await h.phone.addInitScript(() => {
      const w = window as unknown as { __gets: number };
      w.__gets = 0;
      const get = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = (o) => {
        w.__gets++;
        return get(o);
      };
    });
  });
  afterAll(async () => h?.close());

  it('a statement for another site is refused before any assertion, and denied', async () => {
    await h.phone.route('**/api/challenge', async (route) => {
      const res = await fetchRoute(route);
      const body = res.body as { statement: ApprovalStatement; challenge: string };
      const lie = forBank(body.statement);
      await route.fulfill({
        status: res.status,
        headers: res.headers,
        json: { ...body, statement: lie, challenge: approvalChallenge(lie) },
      });
    });
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const login = h.mcp.ok<{ status: string }>('auth_login');

    await h.phonePage.goto(`${h.approver.origin}/`);
    const card = h.phonePage.locator('#requests .card').first();
    await card.waitFor({ timeout: 15_000 });
    expect(await card.textContent()).toContain(h.rp.origin);
    await card.locator('.approve').click();
    await expect
      .poll(() => card.locator('.error').textContent(), { timeout: 10_000 })
      .toContain("doesn't match what this card shows (site)");

    expect(await login).toEqual({ status: 'denied' });
    expect(await gets()).toBe(0);
    expect(h.recording.decisions.at(-1)).toMatchObject({
      approved: false,
      reason: 'user_denied',
    });
    expect(h.auditEvents().some((e) => e.type === 'fill.released')).toBe(false);
    await h.phone.unroute('**/api/challenge');
  });

  it("the server's challenge is ignored: the page signs the statement it checked", async () => {
    await h.phone.route('**/api/challenge', async (route) => {
      const res = await fetchRoute(route);
      const body = res.body as { statement: ApprovalStatement };
      await route.fulfill({
        status: res.status,
        headers: res.headers,
        json: { ...body, challenge: approvalChallenge(forBank(body.statement)) },
      });
    });
    await h.intent('sign me in to the test site');
    await h.mcp.ok('browser_open', { url: `${h.rp.url}password/login` });
    const login = h.mcp.ok<{ status: string }>('auth_login');
    await h.approveOnPhone();
    expect(await login).toEqual({ status: 'challenge' });
    expect(await gets()).toBe(1);

    const d = h.recording.decisions.at(-1) as {
      approved: true;
      approval: { statement: ApprovalStatement; webauthn: { clientDataJSON: string } };
    };
    expect(d.approved).toBe(true);
    expect(d.approval.statement.verifiedOrigin).toBe(h.rp.origin);
    const cd = JSON.parse(Buffer.from(d.approval.webauthn.clientDataJSON, 'base64url').toString());
    expect(cd.challenge).toBe(approvalChallenge(d.approval.statement));
    expect(h.auditEvents().some((e) => e.type === 'fill.released')).toBe(true);
    await h.phone.unroute('**/api/challenge');
  });

  it("the live view's Face ID signs the handoff challenge, never the one the server sends", async () => {
    const last = h.recording.decisions.at(-1) as { approval: { statement: ApprovalStatement } };
    const someApproval = approvalChallenge(forBank(last.approval.statement));
    await h.phone.route('**/api/handoff/challenge', async (route) => {
      const res = await fetchRoute(route);
      const body = res.body as Record<string, unknown>;
      await route.fulfill({
        status: res.status,
        headers: res.headers,
        json: { ...body, challenge: someApproval },
      });
    });
    const handoff = h.mcp.ok<{ status: string }>('browser_handoff', { timeoutMs: 60_000 });
    await expect.poll(() => h.daemon.handoffs.isOpen(h.agent.id), { timeout: 10_000 }).toBe(true);
    await h.openLiveView();
    expect(h.auditEvents().filter((e) => e.type === 'handoff.started')).toHaveLength(1);
    expect(await gets()).toBe(1);
    await h.phonePage.click('#cancel');
    expect(await handoff).toEqual({ status: 'cancelled' });
    await h.phone.unroute('**/api/handoff/challenge');
  });
});
