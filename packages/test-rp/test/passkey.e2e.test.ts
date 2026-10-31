import { type Browser, chromium } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startTestRp, type TestRp } from '../src/server.ts';

describe('test RP passkey flows (virtual authenticator)', () => {
  let rp: TestRp;
  let browser: Browser;
  beforeAll(async () => {
    rp = await startTestRp();
    browser = await chromium.launch();
  });
  afterAll(async () => {
    await browser?.close();
    await rp?.close();
  });

  it('registers and signs in with a passkey', async () => {
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    });

    await page.goto(`${rp.url}signup`);
    await page.fill('#username', 'carol');
    await page.click('#signup');
    await page.click('#add-passkey');
    await expect.poll(() => page.textContent('#status')).toBe('passkey added');

    await page.click('#logout');
    await page.goto(`${rp.url}login`);
    await page.click('#passkey-login');
    await page.waitForURL('**/account');
    expect(await page.textContent('#whoami')).toBe('Signed in as carol');
    expect(rp.logins.at(-1)).toEqual({ username: 'carol', method: 'passkey' });
    await context.close();
  });
});
