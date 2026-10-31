import { existsSync } from 'node:fs';
import { chromium } from 'playwright';

export function chromiumExecutable(): { path: string; present: boolean } {
  let path = '';
  try {
    path = chromium.executablePath();
  } catch {
    return { path: '', present: false };
  }
  return { path, present: path !== '' && existsSync(path) };
}

export async function chromiumLaunchable(
  timeoutMs = 20_000,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const browser = await chromium.launch({
      headless: true,
      timeout: timeoutMs,
      handleSIGINT: false,
      handleSIGTERM: false,
      handleSIGHUP: false,
    });
    await browser.close();
    return { ok: true };
  } catch (err) {
    const first = ((err as Error).message ?? 'launch failed').split('\n')[0] as string;
    return { ok: false, error: first.slice(0, 200) };
  }
}
