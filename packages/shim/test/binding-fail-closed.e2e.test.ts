import type { Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { launchManagedBrowser, type ManagedBrowser } from '../src/browser.ts';
import type { ShimWebAuthnRequest, WebAuthnHandler } from '../src/types.ts';

const URL_PAGE = 'http://rp.localhost:3000/login';

const CEREMONY = (kind: 'create' | 'get') => `(async () => {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const call = ${
    kind === 'get'
      ? 'navigator.credentials.get({ publicKey: { challenge, timeout: 3000 } })'
      : "navigator.credentials.create({ publicKey: { challenge, rp: { name: 'probe' }, user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'u', displayName: 'u' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 3000 } })"
  };
  return call.then(() => 'resolved', (e) => e.name);
})()`;

describe('the shim binding fails closed when the handler does not answer', () => {
  let managed: ManagedBrowser;
  let requests: ShimWebAuthnRequest[];

  beforeAll(async () => {
    managed = await launchManagedBrowser();
  });
  afterAll(async () => managed?.close());

  async function pageWith(handler: WebAuthnHandler): Promise<Page> {
    const context = await managed.newContext(handler);
    const page = await context.newPage();
    await page.route('http://rp.localhost:3000/**', (r) =>
      r.fulfill({ contentType: 'text/html', body: '<!doctype html><title>rp</title>' }),
    );
    await page.goto(URL_PAGE);
    return page;
  }

  it.each([
    [
      'throws synchronously',
      () => {
        throw new Error('handler exploded');
      },
    ],
    ['rejects', async () => Promise.reject(new Error('handler rejected'))],
  ])('a handler that %s: the page gets NotAllowedError for get and create', async (_name, boom) => {
    requests = [];
    const page = await pageWith(((req: ShimWebAuthnRequest) => {
      requests.push(req);
      return boom();
    }) as WebAuthnHandler);
    expect(await page.evaluate(CEREMONY('get'))).toBe('NotAllowedError');
    expect(await page.evaluate(CEREMONY('create'))).toBe('NotAllowedError');
    expect(requests.map((r) => r.kind)).toEqual(['get', 'create']);
    expect(requests.every((r) => r.frame.url === URL_PAGE && r.frame.isMainFrame)).toBe(true);
  });

  it('control: a handler that answers ok:false with another name reaches the page unchanged', async () => {
    const page = await pageWith(async () => ({ ok: false, name: 'SecurityError' }));
    expect(await page.evaluate(CEREMONY('get'))).toBe('SecurityError');
  });
});
