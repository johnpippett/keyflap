import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Harness, signUpAndRegister, startHarness } from './harness.ts';

const GET_SCRIPT = async () => {
  const out: Record<string, unknown> = { selfOrigin: self.origin };
  try {
    await navigator.credentials.get({
      publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: 'rp.localhost' },
    });
    out.ok = true;
  } catch (e) {
    out.ok = false;
    out.name = (e as Error).name;
  }
  return out;
};

describe('invariant 2: opaque-origin documents on the RP URL get no passkey', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await startHarness();
    expect(await signUpAndRegister(h, 'ivy')).toBe('passkey added');
  });
  afterAll(async () => h?.close());

  const lastDenial = () => {
    const d = h.daemon.broker.audit.all().filter((r) => r.event_type === 'denied');
    return JSON.parse(d.at(-1)?.payload_json ?? '{}') as { reason?: string };
  };

  it('control: the same page without the sandbox reaches an approval', async () => {
    const url = `${h.rp.origin}/uploads/control.html`;
    await h.page.route(url, (r) => r.fulfill({ contentType: 'text/html', body: '<h1>page</h1>' }));
    await h.page.goto(url);
    const before = h.approver.seen.length;
    const res = await h.page.evaluate(GET_SCRIPT);
    expect(res.selfOrigin).toBe(h.rp.origin);
    expect(res.ok).toBe(true);
    expect(h.approver.seen.length).toBe(before + 1);
  });

  it('CSP sandbox (user upload): denied, no approval card', async () => {
    const url = `${h.rp.origin}/uploads/evil.html`;
    await h.page.route(url, (r) =>
      r.fulfill({
        contentType: 'text/html',
        headers: { 'content-security-policy': 'sandbox allow-scripts' },
        body: '<h1>user upload</h1>',
      }),
    );
    await h.page.goto(url);
    const before = h.approver.seen.length;
    const res = await h.page.evaluate(GET_SCRIPT);
    expect(res.selfOrigin).toBe('null');
    expect(res).toMatchObject({ ok: false, name: 'NotAllowedError' });
    expect(h.approver.seen.length).toBe(before);
    expect(lastDenial().reason).toBe('document_origin_mismatch');
  });

  it("a popup that inherits the sandbox, on the RP's real login page: denied", async () => {
    const url = `${h.rp.origin}/uploads/opener.html`;
    await h.page.route(url, (r) =>
      r.fulfill({
        contentType: 'text/html',
        headers: { 'content-security-policy': 'sandbox allow-scripts allow-popups' },
        body: `<button id="open" onclick="window.open('${h.rp.url}login')">open</button>`,
      }),
    );
    await h.page.goto(url);
    const [popup] = await Promise.all([h.context.waitForEvent('page'), h.page.click('#open')]);
    await popup.waitForLoadState('load');
    expect(popup.url()).toBe(`${h.rp.url}login`);
    expect(await popup.evaluate(() => self.origin)).toBe('null');
    const before = h.approver.seen.length;
    const res = await popup.evaluate(GET_SCRIPT);
    expect(res).toMatchObject({ ok: false, name: 'NotAllowedError' });
    expect(h.approver.seen.length).toBe(before);
    expect(lastDenial().reason).toBe('document_origin_mismatch');
    await popup.close();
  });

  it('registration from a sandboxed document: denied, nothing created', async () => {
    const url = `${h.rp.origin}/uploads/enroll.html`;
    await h.page.route(url, (r) =>
      r.fulfill({
        contentType: 'text/html',
        headers: { 'content-security-policy': 'sandbox allow-scripts' },
        body: '<h1>user upload</h1>',
      }),
    );
    await h.page.goto(url);
    const before = h.approver.seen.length;
    const passkeys = h.daemon.broker.credentials.passkeysForRp('rp.localhost').length;
    const res = await h.page.evaluate(async () => {
      try {
        await navigator.credentials.create({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: { id: 'rp.localhost', name: 'RP' },
            user: { id: new Uint8Array(16), name: 'x', displayName: 'x' },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          },
        });
        return 'created';
      } catch (e) {
        return (e as Error).name;
      }
    });
    expect(res).toBe('NotAllowedError');
    expect(h.approver.seen.length).toBe(before);
    expect(h.daemon.broker.credentials.passkeysForRp('rp.localhost')).toHaveLength(passkeys);
  });
});
