import type { Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Harness, signUpAndRegister, startHarness } from './harness.ts';

type GetResult =
  | { ok: true; clientData: { origin: string; type: string } }
  | { ok: false; name: string };

const callGet = (page: Page | import('playwright').Frame, rpId?: string) =>
  page.evaluate(async (rpId): Promise<GetResult> => {
    try {
      const publicKey: Record<string, unknown> = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        origin: 'http://rp.localhost',
        clientData: { origin: 'http://rp.localhost' },
      };
      if (rpId) publicKey.rpId = rpId;
      const c = (await navigator.credentials.get({
        publicKey,
      } as unknown as CredentialRequestOptions)) as PublicKeyCredential;
      const r = c.response as AuthenticatorAssertionResponse;
      return { ok: true, clientData: JSON.parse(new TextDecoder().decode(r.clientDataJSON)) };
    } catch (e) {
      return { ok: false, name: (e as Error).name };
    }
  }, rpId);

describe('invariants 2 + 3 in the managed browser', () => {
  let h: Harness;
  let port: string;
  const denials = () =>
    h.daemon.broker.audit
      .all()
      .filter((r) => r.event_type === 'denied')
      .map((r) => JSON.parse(r.payload_json) as { reason: string; verifiedOrigin: string | null });

  const serve = async (url: string, body: string) =>
    h.page.route(url, (route) => route.fulfill({ contentType: 'text/html', body }));

  beforeAll(async () => {
    h = await startHarness();
    port = new URL(h.rp.origin).port;
    expect(await signUpAndRegister(h, 'ivy')).toBe('passkey added');
  });
  afterAll(async () => h?.close());

  it('an unrelated origin cannot use the rp.localhost credential by naming its rpId', async () => {
    const before = h.approver.seen.length;
    await serve(`http://evil.localhost:${port}/`, '<h1>totally the real site</h1>');
    await h.page.goto(`http://evil.localhost:${port}/`);
    expect(await callGet(h.page, 'rp.localhost')).toEqual({ ok: false, name: 'SecurityError' });
    expect(denials().at(-1)).toMatchObject({
      reason: 'rp_id_not_allowed_for_origin',
      verifiedOrigin: `http://evil.localhost:${port}`,
    });
    expect(h.approver.seen.length).toBe(before);
  });

  it('an unrelated origin using its own rpId finds no credential', async () => {
    await h.page.goto(`http://evil.localhost:${port}/`);
    expect(await callGet(h.page)).toEqual({ ok: false, name: 'NotAllowedError' });
    expect(denials().at(-1)?.reason).toBe('no_matching_credential');
  });

  it('calling the binding directly with forged origin/frame arguments changes nothing', async () => {
    await h.page.goto(`http://evil.localhost:${port}/`);
    const res = await h.page.evaluate(async (rpOrigin) => {
      const binding = (window as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>)
        .__aabWebAuthn;
      return binding?.(
        'get',
        {
          challenge: { $b: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
          rpId: 'rp.localhost',
          origin: rpOrigin,
        },
        null,
        { frame: { url: `${rpOrigin}/login`, isMainFrame: true }, origin: rpOrigin },
      );
    }, h.rp.origin);
    expect(res).toEqual({ ok: false, name: 'SecurityError' });
    expect(denials().at(-1)?.verifiedOrigin).toBe(`http://evil.localhost:${port}`);
  });

  it('a page overwriting window.location-derived values cannot move its origin', async () => {
    await h.page.goto(`http://evil.localhost:${port}/`);
    await h.page.evaluate(() => {
      try {
        history.replaceState(null, '', '/pretend/rp.localhost');
        Object.defineProperty(document, 'domain', { value: 'rp.localhost' });
        Object.defineProperty(window, 'origin', { value: 'http://rp.localhost' });
      } catch {}
    });
    expect(await callGet(h.page, 'rp.localhost')).toEqual({ ok: false, name: 'SecurityError' });
    expect(denials().at(-1)?.verifiedOrigin).toBe(`http://evil.localhost:${port}`);
  });

  it('requests from iframes are denied, same-origin or cross-origin', async () => {
    await serve(
      `http://rp.localhost:${port}/frames`,
      `<iframe id="same" src="http://rp.localhost:${port}/login"></iframe>
       <iframe id="cross" src="http://evil.localhost:${port}/" allow="publickey-credentials-get *"></iframe>`,
    );
    await h.page.goto(`http://rp.localhost:${port}/frames`);
    const frames = h.page.frames().filter((f) => f !== h.page.mainFrame());
    expect(frames).toHaveLength(2);
    const before = h.approver.seen.length;
    for (const f of frames) {
      await f.waitForLoadState();
      const res = await callGet(f, 'rp.localhost');
      expect(res.ok).toBe(false);
    }
    expect(h.approver.seen.length).toBe(before);
    const reasons = denials()
      .slice(-2)
      .map((d) => d.reason);
    expect(reasons).toEqual(['not_top_level_frame', 'not_top_level_frame']);
  });

  it('a subdomain of the rpId may use the credential, with its own origin signed', async () => {
    await serve(`http://login.rp.localhost:${port}/`, '<h1>login subdomain</h1>');
    await h.page.goto(`http://login.rp.localhost:${port}/`);
    const res = await callGet(h.page, 'rp.localhost');
    expect(res).toEqual({
      ok: true,
      clientData: expect.objectContaining({
        type: 'webauthn.get',
        origin: `http://login.rp.localhost:${port}`,
      }),
    });
    expect(h.approver.seen.at(-1)?.display.verifiedOrigin).toBe(
      `http://login.rp.localhost:${port}`,
    );
  });

  it('the real site still signs in normally afterwards', async () => {
    await h.page.goto(`${h.rp.url}login`);
    await h.page.click('#passkey-login');
    await h.page.waitForURL('**/account');
    expect(await h.page.textContent('#whoami')).toBe('Signed in as ivy');
  });
});
