import { appendFileSync } from 'node:fs';
import { chromium } from 'playwright';

const [pairingUrl, logFile] = process.argv.slice(2);
if (!pairingUrl || !logFile) throw new Error('usage: phone.ts PAIRING_URL LOG_FILE');
const log = (o: Record<string, unknown>) => appendFileSync(logFile, `${JSON.stringify(o)}\n`);

const browser = await chromium.launch({ headless: true });
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

await page.goto(pairingUrl);
await page.click('#pair-button');
await page.waitForFunction(
  () => document.querySelector('#status')?.textContent === 'No pending requests.',
  undefined,
  { timeout: 30_000 },
);
log({ event: 'paired' });
process.stdout.write('paired\n');

process.on('SIGTERM', () => void browser.close().then(() => process.exit(0)));
for (;;) {
  const card = page.locator('#requests .card').first();
  try {
    await card.waitFor({ timeout: 5_000 });
  } catch {
    continue;
  }
  const text = (await card.textContent()) ?? '';
  const deny = text.includes('DENY');
  await card.locator(deny ? '.deny' : '.approve').click();
  await card.waitFor({ state: 'detached', timeout: 20_000 }).catch(() => {});
  log({ event: deny ? 'denied' : 'approved', shown: text.replace(/\s+/g, ' ').slice(0, 400) });
}
