import { describe, expect, it } from 'vitest';
import { launchManagedBrowser, type ManagedBrowserOptions } from '../src/browser.ts';

async function product(opts: ManagedBrowserOptions): Promise<string> {
  const managed = await launchManagedBrowser(opts);
  try {
    const cdp = await managed.browser.newBrowserCDPSession();
    const v = (await cdp.send('Browser.getVersion')) as { product: string };
    await cdp.detach();
    return v.product;
  } finally {
    await managed.close();
  }
}

describe('the managed browser can be the full Chromium in new headless mode', () => {
  it('headless without a channel is the headless shell; channel chromium is the full browser', async () => {
    expect(await product({ headless: true })).toMatch(/^HeadlessChrome\//);
    expect(await product({ headless: true, channel: 'chromium' })).toMatch(/^Chrome\//);
  }, 60_000);
});
