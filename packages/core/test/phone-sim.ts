import { type Browser, chromium, type Page } from 'playwright';

export interface SimulatedPhone {
  page: Page;
  pair(url: string): Promise<void>;
  approve(origin: string, timeoutMs?: number): Promise<string>;
  close(): Promise<void>;
}

export async function startSimulatedPhone(): Promise<SimulatedPhone> {
  const browser: Browser = await chromium.launch({ headless: true });
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
      automaticPresenceSimulation: true,
    },
  });
  return {
    page,
    async pair(url) {
      await page.goto(url);
      await page.click('#pair-button');
      await page.waitForFunction(
        () => document.querySelector('#status')?.textContent === 'No pending requests.',
        undefined,
        { timeout: 20_000 },
      );
    },
    async approve(origin, timeoutMs = 20_000) {
      await page.goto(`${origin}/`);
      const card = page.locator('#requests .card').first();
      await card.waitFor({ timeout: timeoutMs });
      const text = (await card.textContent()) ?? '';
      await card.locator('.approve').click();
      await card.waitFor({ state: 'detached', timeout: timeoutMs });
      return text;
    },
    close: () => browser.close(),
  };
}
