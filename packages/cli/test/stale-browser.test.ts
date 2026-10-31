import { describe, expect, it } from 'vitest';
import { staleBrowserPids } from '../src/service/stale-browser.ts';

const BROWSERS = '/opt/keyflap/browsers';
const CHROME = `${BROWSERS}/chromium-1248/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`;
const HELPER = `${BROWSERS}/chromium-1248/chrome-mac-arm64/Google Chrome for Testing.app/Contents/Frameworks/Google Chrome for Testing Framework.framework/Versions/156.0.0.0/Helpers/Google Chrome for Testing Helper (Renderer).app/Contents/MacOS/Google Chrome for Testing Helper (Renderer)`;

const ps = (rows: [number, string][]) =>
  `${rows.map(([pid, cmd]) => `${String(pid).padStart(5)} ${cmd}`).join('\n')}\n`;

describe('stale Chromium sweep at core start (macOS: launchctl kill leaves the detached browser alive)', () => {
  it('selects the processes of this uid that run from the prefix browsers directory', () => {
    const out = ps([
      [4985, `${CHROME} --type=browser --headless --remote-debugging-pipe`],
      [4990, `${HELPER} --type=renderer`],
      [4991, `${HELPER} --type=gpu-process`],
    ]);
    expect(staleBrowserPids(out, { browsersPath: BROWSERS, selfPid: 5000 })).toEqual([
      4985, 4990, 4991,
    ]);
  });

  it('leaves this process, Node, keyflap-launch and anything outside the browsers directory alone', () => {
    const out = ps([
      [5000, '/opt/keyflap/node/bin/node /opt/keyflap/app/packages/cli/src/service/core-main.ts'],
      [5001, '/opt/keyflap/libexec/keyflap-launch --socket intent -- /opt/keyflap/node/bin/node'],
      [5002, '/usr/sbin/distnoted agent'],
      [5003, '/usr/libexec/trustd --agent'],
      [5004, '/opt/keyflap/browsers-old/chromium-1248/chrome'],
      [5005, `/Users/alice/Library/Caches/ms-playwright/chromium-1248/chrome --headless`],
      [5006, `${CHROME} --type=browser`],
    ]);
    expect(staleBrowserPids(out, { browsersPath: BROWSERS, selfPid: 5000 })).toEqual([5006]);
  });

  it('accepts the prefix with or without a trailing slash and ignores malformed lines', () => {
    const out = `garbage\n\n  12 ${CHROME}\n`;
    expect(staleBrowserPids(out, { browsersPath: `${BROWSERS}/`, selfPid: 1 })).toEqual([12]);
    expect(staleBrowserPids('', { browsersPath: BROWSERS, selfPid: 1 })).toEqual([]);
  });

  it('never selects its own pid even when it looks like the browser', () => {
    expect(staleBrowserPids(ps([[77, CHROME]]), { browsersPath: BROWSERS, selfPid: 77 })).toEqual(
      [],
    );
  });
});
