import { readFileSync, statSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { canFakeMac, fakeMac, RELEASE, runInFakeMac, serveRelease, VERSION } from './fake-mac.ts';
import { render } from './screen.ts';

const ARGS = ['--user', 'alice', '--approver-origin', 'https://mac.tail1234.ts.net:8766'];
const INSTALL = [`${RELEASE}/install.sh`, ...ARGS];
const LOG = '/Library/Keyflap/log/install.log';
const STEPS = [
  'Creating service users',
  'Copying Keyflap',
  'Unpacking Node',
  'Downloading Chromium',
  'Creating keys',
  'Preparing data folders',
  'Connecting to Tailscale',
  'Writing settings',
  'Adding the background services',
  'Starting Keyflap',
];
const BAR = (w: number) => `     ${'━'.repeat(w)}`;
const HEADER = `  K  KEYFLAP  install · ${VERSION}`;
const SLOW = { timeout: 90_000 };

const PLAIN = `==> installing ${VERSION}
==> service users _keyflap-core, _keyflap-signer, _keyflap-web
==> code and runtime in /opt/keyflap
==> downloading Chromium 1248 (Playwright's installer)
==> credentials in /Library/Keyflap/credentials
==> data in /Library/Keyflap/data
==> letting _keyflap-signer read Tailscale's token in /Library/Tailscale
==> configuration in /Library/Keyflap/etc
wrote /Library/Keyflap/etc
==> LaunchDaemons com.keyflap.signer, com.keyflap.core, com.keyflap.approver
==> starting

Installed ${VERSION}. The broker runs as _keyflap-core / _keyflap-signer, and the phone approver
page as _keyflap-web on 127.0.0.1:8766 (and [::1]:8766); your user (alice) reaches the broker only through MCP
(with an agent token) and the intent socket (your Claude Code hook).
Managed browser: headless (full Chromium, its own sandbox on); the first start takes up to a minute while macOS scans the new browser.
macOS shows a "Background Items Added" notification for the three Keyflap services (System
Settings > General > Login Items & Extensions); they must stay allowed there.

Next (docs/integrations/service-mode.md):
  sudo keyflap setup                   # guided: pair your phone, add an agent

or step by step:
  sudo keyflap approver pair           # one-time link: open it on your phone
  sudo keyflap agent add "Claude Code" # prints the agent token and Claude Code config
  sudo keyflap status
`;

const labelsShown = (out: string) =>
  STEPS.filter((label) => out.includes(` ${label}`)).map((label) => ({
    at: out.indexOf(label),
    label,
  }));

describe.runIf(canFakeMac)('macOS install.sh progress (a fake Mac in a user namespace)', () => {
  it(
    'without a terminal it prints the plain `==>` lines and the full summary, and writes no log',
    SLOW,
    async () => {
      const mac = fakeMac();
      const r = await runInFakeMac(mac, INSTALL, { tty: false });
      expect(r.code, r.out).toBe(0);
      expect(r.out).toBe(PLAIN);
      expect(() => statSync(`${mac.root}${LOG}`)).toThrow();
    },
  );

  it(
    'on a terminal it shows the steps in order under one bar, then a short summary',
    SLOW,
    async () => {
      const mac = fakeMac();
      const r = await runInFakeMac(mac, INSTALL, { tty: true, env: { FAKE_DELAY: '0.05' } });
      expect(r.code, r.out).toBe(0);
      const shown = labelsShown(r.out);
      expect(shown.map((s) => s.label)).toContain('Downloading Chromium');
      expect(shown.length).toBeGreaterThan(3);
      const at = shown.map((s) => s.at);
      expect(at).toEqual(at.toSorted((a, b) => a - b));
      expect(r.out).toMatch(/\d+\.\d of 162\.5 MB/);
      const screen = render(r.out);
      expect(screen.text()).toBe(
        [
          '',
          HEADER,
          BAR(76),
          '',
          `   ✓ Installed Keyflap ${VERSION}`,
          '',
          '     macOS shows "Background Items Added" for Keyflap. Keep them allowed.',
          '',
          '     Next: sudo keyflap setup',
          `     Details: ${LOG}`,
        ].join('\n'),
      );
      expect(screen.cursorVisible).toBe(true);
      expect(r.out).not.toContain('==>');
      expect(r.out).not.toContain('/Library/Keyflap/credentials');
    },
  );

  it(
    'on a terminal the log gets the detail: the plain lines, each step and the full summary, root-only',
    SLOW,
    async () => {
      const mac = fakeMac();
      const r = await runInFakeMac(mac, INSTALL, { tty: true });
      expect(r.code, r.out).toBe(0);
      const log = readFileSync(mac.log, 'utf8');
      for (const line of PLAIN.split('\n').filter((l) => l !== '')) expect(log).toContain(line);
      STEPS.forEach((label, i) => {
        expect(log).toContain(`-- step ${i + 1} of ${STEPS.length}: ${label}`);
      });
      expect(log).toContain('Chromium downloaded to');
      expect(log).toContain(`==== done: Installed Keyflap ${VERSION}`);
      expect(statSync(mac.log).mode & 0o777).toBe(0o600);
    },
  );

  it('an upgrade says what it kept, and how to check it', SLOW, async () => {
    const mac = fakeMac();
    expect((await runInFakeMac(mac, INSTALL, { tty: false })).code).toBe(0);
    const r = await runInFakeMac(mac, INSTALL, { tty: true });
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain('Stopping Keyflap');
    expect(render(r.out).text()).toContain(
      [
        `   ✓ Upgraded Keyflap to ${VERSION}`,
        '',
        '     Your phone, agents, passwords and saved sign-ins are kept.',
        '',
        '     Check it: sudo keyflap status',
      ].join('\n'),
    );
  });

  it('FileVault off is a warning on screen, not only in the log', SLOW, async () => {
    const mac = fakeMac();
    const r = await runInFakeMac(mac, INSTALL, { tty: true, env: { FAKE_FILEVAULT: 'Off' } });
    expect(r.code, r.out).toBe(0);
    expect(render(r.out).text()).toContain(
      "   ! FileVault is off, so whoever has this Mac's disk can read Keyflap's keys.",
    );
  });

  it('a refusal stops the frame on its step and prints the full reason', SLOW, async () => {
    const mac = fakeMac();
    const r = await runInFakeMac(mac, INSTALL, { tty: true, env: { FAKE_LAUNCHCTL_FAIL: '1' } });
    expect(r.code).toBe(1);
    const screen = render(r.out);
    expect(screen.text()).toContain(
      [
        '   ✗ Starting Keyflap',
        '',
        'install: launchctl bootstrap system/com.keyflap.signer failed: sudo launchctl print system/com.keyflap.signer; sudo tail -n 50 /Library/Keyflap/log/signer/signer.log',
        '',
        `     Details: ${LOG}`,
      ].join('\n'),
    );
    expect(screen.cursorVisible).toBe(true);
    expect(readFileSync(mac.log, 'utf8')).toContain('Bootstrap failed: 5: Input/output error');
  });

  it('a command that fails on its own shows its last lines', SLOW, async () => {
    const mac = fakeMac();
    const r = await runInFakeMac(mac, INSTALL, { tty: true, env: { FAKE_PLAYWRIGHT_FAIL: '1' } });
    expect(r.code).toBe(1);
    const text = render(r.out).text();
    expect(text).toContain('   ✗ Downloading Chromium');
    expect(text).toContain('Stopped: a command failed (exit 1). Its last lines:');
    expect(text).toContain('  Error: Download failure, code=1');
  });

  it('Ctrl-C stops the frame and gives the cursor back', SLOW, async () => {
    const mac = fakeMac();
    const r = await runInFakeMac(mac, INSTALL, {
      tty: true,
      env: { FAKE_DELAY: '0.3' },
      answers: [[/Downloading Chromium/, '\u0003']],
    });
    expect(r.code).not.toBe(0);
    const screen = render(r.out);
    expect(screen.text()).toContain('   ✗ Downloading Chromium');
    expect(screen.text()).toContain(
      'Stopped before the end. Run the same command again to finish.',
    );
    expect(screen.cursorVisible).toBe(true);
  });

  it('the one command keeps one bar from the download to the started services', SLOW, async () => {
    const mac = fakeMac({ staged: false });
    const served = await serveRelease(mac);
    try {
      const r = await runInFakeMac(mac, [served.bootstrap], {
        tty: true,
        cols: 80,
        env: { KEYFLAP_RELEASE_BASE: served.base },
        answers: [[/Choice \[\d\]: $/, '3\r']],
      });
      expect(r.code, r.out).toBe(0);
      expect(r.out.indexOf('Downloading Keyflap')).toBeLessThan(
        r.out.indexOf('Creating service users'),
      );
      const text = render(r.out).text();
      expect(text.match(/KEYFLAP {2}install/g)).toHaveLength(1);
      expect(text).toContain(
        [
          `   ✓ Installed Keyflap ${VERSION}`,
          '',
          '     macOS shows "Background Items Added" for Keyflap. Keep them allowed.',
          '',
          `     Details: ${LOG}`,
          '',
          '     Now the guided setup: your phone, your agent and your passwords.',
        ].join('\n'),
      );
      expect(text).not.toContain('Next: sudo keyflap setup');
      expect(text).toContain(
        [
          '       1) 1Password (a service account token; you paste it next, it is not',
          '          shown)',
        ].join('\n'),
      );
      expect(text).toContain(`     To remove Keyflap later: sudo ${RELEASE}/uninstall.sh`);
      const log = readFileSync(mac.log, 'utf8');
      expect(log).toContain('==> service users _keyflap-core');
      expect(log).toContain(
        `Checked: keyflap-${VERSION}-darwin-arm64.tar.xz matches the pinned SHA-256.`,
      );
      expect(log).toContain('Phone approver: https://mac.tail1234.ts.net:8766');
    } finally {
      served.close();
    }
  });
});
