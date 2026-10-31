import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { type ColorLevel, plainStyle, stripStyle, type TermStyle, termStyle } from '@aab/approver';
import { afterEach, describe, expect, it } from 'vitest';
import { devInstallAt } from '../src/console/dev-install.ts';
import { devSections } from '../src/console/dev-menu.ts';
import { devModeName, openDevConsole } from '../src/console/dev-start.ts';
import { SECTIONS } from '../src/console/menu.ts';
import { UNPROTECTED_FLAP } from '../src/console/unprotected.ts';
import { createKeyFile } from '../src/key-file.ts';
import { FULL_INSTALL_COMMAND } from '../src/simple-install.ts';
import { captureSession, ESC, type Session, type Step } from './console-capture.ts';
import {
  DEV_PASSPHRASE,
  type DevWorld,
  devConsoleWorld,
  type Install,
} from './console-dev-world.ts';
import { tmpDir } from './helpers.ts';
import { FakeSystem } from './setup-fakes.ts';

const size = { cols: 80, rows: 24 };
const worlds: DevWorld[] = [];

afterEach(async () => {
  delete process.env.KEYFLAP_PASSPHRASE;
  for (const w of worlds.splice(0)) await w.close();
});

async function world(install: Install = 'dev'): Promise<DevWorld> {
  const w = await devConsoleWorld(install);
  worlds.push(w);
  return w;
}

function tour(w: DevWorld, steps: Step[], style: TermStyle = plainStyle): Promise<Session> {
  return captureSession(steps, {
    size,
    style,
    mode: devModeName(w.install),
    alert: UNPROTECTED_FLAP,
    run: async (ui) => {
      await w.run(ui, style);
    },
  });
}

const text = (s: { painted: { lines: string[] } }) => stripStyle(s.painted.lines.join('\n'));

function shown(c: Session, caption: RegExp): string {
  const shot = c.shots.find((s) => caption.test(s.caption));
  if (!shot) throw new Error(`no screen captioned ${caption}`);
  return text(shot);
}

function everythingShown(c: Session): string {
  return [
    ...c.shots.map(text),
    ...c.shots.flatMap((s) => s.frame.details),
    ...c.shots.flatMap((s) => s.frame.blocks.map((b) => JSON.stringify(b))),
    c.log,
    c.after,
  ].join('\n');
}

const MANAGE = /^What do you want to manage/;
const NOW = /^What now/;
const OVERVIEW = /^Overview: What do you want to manage/;

const WALK: Step[] = [
  { q: MANAGE, a: '1' },
  { q: NOW, a: '1' },
  { q: NOW, a: ESC },
  { q: MANAGE, a: '2' },
  { q: NOW, a: ESC },
  { q: MANAGE, a: '4' },
  { q: NOW, a: '1' },
  { q: NOW, a: ESC },
  { q: MANAGE, a: '5' },
  { q: NOW, a: '1' },
  { q: NOW, a: ESC },
  { q: MANAGE, a: '6' },
  { q: NOW, a: '1' },
  { q: NOW, a: ESC },
  { q: MANAGE, a: '7' },
  { q: NOW, a: '1' },
  { q: NOW, a: '3' },
  { q: NOW, a: '4' },
  { q: NOW, a: ESC },
  { q: MANAGE, a: ESC },
];

const SGR = new RegExp(`${String.fromCharCode(27)}\\[([0-9;]*)m`, 'g');

function sgrParams(raw: string): number[][] {
  return [...raw.matchAll(SGR)].map((m) =>
    (m[1] ?? '').split(';').map((n) => (n === '' ? 0 : Number(n))),
  );
}

function redCodes(raw: string): string[] {
  const found: string[] = [];
  for (const params of sgrParams(raw)) {
    for (let i = 0; i < params.length; i++) {
      const p = params[i] as number;
      if ([31, 41, 91, 101].includes(p)) found.push(String(p));
      if ((p === 38 || p === 48) && params[i + 1] === 5) {
        const n = params[i + 2] as number;
        const cube = n - 16;
        const [r, g, b] = [Math.floor(cube / 36), Math.floor(cube / 6) % 6, cube % 6];
        if (n === 1 || n === 9 || (cube >= 0 && cube < 216 && r >= 3 && g <= 1 && b <= 1)) {
          found.push(`${p};5;${n}`);
        }
        i += 2;
      } else if ((p === 38 || p === 48) && params[i + 1] === 2) {
        const [r, g, b] = [params[i + 2], params[i + 3], params[i + 4]] as number[];
        if ((r as number) > 150 && (g as number) < 110 && (b as number) < 110) {
          found.push(`${p};2;${r};${g};${b}`);
        }
        i += 4;
      }
    }
  }
  return found;
}

describe('dev console: when it opens', () => {
  it('finds a dev install, a simple install, and nothing in an empty directory', () => {
    const dir = tmpDir();
    try {
      expect(devInstallAt(dir)).toBeNull();
      mkdirSync(join(dir, 'signer'));
      writeFileSync(join(dir, 'signer', 'keys.enc.json'), '{}');
      expect(devInstallAt(dir)).toBe('dev');
      createKeyFile(join(dir, 'simple'));
      expect(devInstallAt(join(dir, 'simple'))).toBe('simple');
      writeFileSync(join(dir, 'broker.sqlite'), '');
      expect(devInstallAt(dir)).toBe('dev');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('keeps every action of the full-install console except trusting a password tool and Disconnect', () => {
    const all = SECTIONS.flatMap((s) => s.actions.map((a) => `${s.title}/${a.label}`));
    const dev = devSections().flatMap((s) => s.actions.map((a) => `${s.title}/${a.label}`));
    expect(all.filter((a) => !dev.includes(a))).toEqual([
      'Password managers/Trust an updated tool',
      'Password managers/Disconnect',
    ]);
    expect(dev.length).toBe(all.length - 2);
  });
});

describe('dev console: it runs as the owner, never as root', () => {
  it('refuses to open as root, before it reads any data directory or opens the screen', async () => {
    const sys = new FakeSystem();
    sys.uid = 0;
    expect(await openDevConsole(sys)).toBe('root');
  });
});

describe('dev console: it is unmissably the unprotected Keyflap', () => {
  for (const install of ['dev', 'simple'] as const) {
    it(`shows the warning screen first, in ${devModeName(install)}`, async () => {
      const w = await world(install);
      const c = await tour(w, [{ q: MANAGE, a: ESC }]);
      const first = c.shots[0];
      expect(first?.caption).toMatch(/Unprotected: Press Enter to continue/);
      const lines = first?.painted.lines.map(stripStyle) ?? [];
      expect(lines[0]?.trim()).toBe('KEYFLAP  console  ! UNPROTECTED');
      const prose = lines.join(' ').replace(/█+/g, '').replace(/\s+/g, ' ');
      expect(prose).toContain('This is the unprotected version of Keyflap.');
      expect(prose).toContain(
        "It runs as you, so an agent running as you can read Keyflap's files and change its code.",
      );
      expect(prose).toContain(
        'The protected version stops that. It is the full install: Tab shows the command.',
      );
      expect(lines.filter((l) => l.includes('████')).length).toBe(5);
      const details = shown(c, /Tab: details/);
      expect(details.replace(/\s+/g, ' ')).toContain(
        FULL_INSTALL_COMMAND.replace(/^curl -fsSL /, '').slice(0, 20),
      );
      expect(details).toContain('sudo bash');
      expect(shown(c, OVERVIEW)).toContain('Passwords');
      expect(c.shots.findIndex((s) => OVERVIEW.test(s.caption))).toBeGreaterThan(0);
    });
  }

  it('puts the flap in the header of every screen, never the service-mode word', async () => {
    const w = await world('dev');
    const c = await tour(w, WALK);
    expect(c.shots.length).toBeGreaterThan(20);
    for (const s of c.shots) {
      const header = stripStyle(s.painted.lines[0] ?? '');
      expect(header, s.caption).toContain('! UNPROTECTED');
      expect(header, s.caption).not.toContain('service mode');
    }
    expect(everythingShown(c)).not.toContain('service mode');
  });

  it('draws the flap as a reverse-video bold flap', async () => {
    const w = await world('dev');
    const c = await tour(w, [{ q: MANAGE, a: ESC }], termStyle(2));
    for (const s of c.shots) {
      expect(s.painted.lines[0], s.caption).toContain('\u001b[7;1m ! UNPROTECTED \u001b[27;22m');
    }
  });

  for (const level of [1, 2, 3] as const) {
    it(`uses no red anywhere, at colour level ${level}`, async () => {
      const w = await world('dev');
      const c = await tour(w, WALK, termStyle(level as ColorLevel));
      const raw = [
        ...c.shots.map((s) => s.painted.lines.join('\n')),
        ...c.shots.flatMap((s) => s.frame.blocks.map((b) => JSON.stringify(b))),
        c.after,
      ].join('\n');
      expect(sgrParams(raw).length).toBeGreaterThan(50);
      expect(redCodes(raw)).toEqual([]);
    });
  }

  it('still shows the shape and the words with no colour at all', async () => {
    const w = await world('dev');
    const c = await tour(w, [{ q: MANAGE, a: ESC }], termStyle(0));
    const raw = c.shots.map((s) => s.painted.lines.join('\n')).join('\n');
    expect(sgrParams(raw)).toEqual([]);
    expect(raw).toContain('████');
    expect(raw).toContain('KEYFLAP  console  ! UNPROTECTED');
  });

  it('keeps the flap on a short terminal', async () => {
    const w = await world('dev');
    const c = await captureSession([{ q: MANAGE, a: ESC }], {
      size: { cols: 60, rows: 9 },
      style: plainStyle,
      mode: 'dev mode',
      alert: UNPROTECTED_FLAP,
      run: async (ui) => {
        await w.run(ui, plainStyle);
      },
    });
    for (const s of c.shots) {
      expect(stripStyle(s.painted.lines[0] ?? ''), s.caption).toContain('! UNPROTECTED');
    }
  });
});

describe('dev console: the key-store passphrase', () => {
  const REMOVE_ONE: Step[] = [
    { q: MANAGE, a: '1' },
    { q: NOW, a: '4' },
    { q: /^Which one/, a: '1' },
    { q: /^Remove the password for/, a: 'y' },
  ];

  it('is asked once, in the secret input, and never reaches a screen, the details or the log', async () => {
    const w = await world('dev');
    const before = w.passwords().length;
    const c = await tour(w, [
      ...REMOVE_ONE,
      { q: /^Key-store passphrase/, a: DEV_PASSPHRASE },
      { q: NOW, a: ESC },
      { q: MANAGE, a: '3' },
      { q: NOW, a: '1' },
      { q: NOW, a: ESC },
      { q: MANAGE, a: ESC },
    ]);
    expect(w.passwords()).toHaveLength(before - 1);
    expect(shown(c, /Phones · See them: Press Enter/)).toContain('No phone paired.');
    const prompt = c.shots.find((s) => /: Key-store passphrase$/.test(s.caption));
    expect(prompt?.frame.input).toMatchObject({ kind: 'line', hidden: true });
    const out = everythingShown(c);
    for (const secret of w.secrets) expect(out).not.toContain(secret);
  });

  it('asks again after a wrong one, and shows neither', async () => {
    const w = await world('dev');
    const c = await tour(w, [
      ...REMOVE_ONE,
      { q: /^Key-store passphrase/, a: 'not-the-passphrase-1' },
      { q: /^Key-store passphrase/, a: DEV_PASSPHRASE },
      { q: NOW, a: ESC },
      { q: MANAGE, a: ESC },
    ]);
    expect(w.passwords()).toHaveLength(1);
    const out = everythingShown(c);
    expect(out).toContain('Wrong passphrase.');
    for (const secret of [...w.secrets, 'not-the-passphrase-1']) expect(out).not.toContain(secret);
  });

  it('is not asked at all when KEYFLAP_PASSPHRASE is set, and the variable is dropped', async () => {
    const w = await world('dev');
    process.env.KEYFLAP_PASSPHRASE = DEV_PASSPHRASE;
    const c = await tour(w, [...REMOVE_ONE, { q: NOW, a: ESC }, { q: MANAGE, a: ESC }]);
    expect(w.passwords()).toHaveLength(1);
    expect(process.env.KEYFLAP_PASSPHRASE).toBeUndefined();
    for (const secret of w.secrets) expect(everythingShown(c)).not.toContain(secret);
  });

  it('is not asked in the simple install: its key file unlocks the store', async () => {
    const w = await world('simple');
    w.launchctl.loaded = false;
    const c = await tour(w, [...REMOVE_ONE, { q: NOW, a: ESC }, { q: MANAGE, a: ESC }]);
    expect(w.passwords()).toHaveLength(1);
    expect(c.shots.some((s) => /passphrase/i.test(s.caption))).toBe(false);
    for (const secret of w.secrets) expect(everythingShown(c)).not.toContain(secret);
  });
});

describe('dev console: an action that needs the daemon stopped', () => {
  it('dev mode: says so, leaves it running on skip, and tells you the command to start it again', async () => {
    const w = await world('dev');
    await w.daemon.start();
    const c = await tour(w, [
      { q: MANAGE, a: '3' },
      { q: NOW, a: '1' },
      { q: /^Stop it there/, a: 'skip' },
      { q: NOW, a: '1' },
      { q: /^Stop it there/, a: '', before: () => w.daemon.stop() },
      { q: /^Key-store passphrase/, a: DEV_PASSPHRASE },
      { q: NOW, a: ESC },
      { q: MANAGE, a: ESC },
    ]);
    const first = shown(c, /Phones · See them: Press Enter to go back/);
    expect(first).toContain('Keyflap is running in another terminal');
    expect(first).toContain('Keyflap is still running, so nothing was changed.');
    const last = c.shots.filter((s) => /Phones · See them: Press Enter to go back/.test(s.caption));
    const done = text(last[1] as (typeof last)[number]);
    expect(done).toContain('No phone paired.');
    expect(done.replace(/\s+/g, ' ')).toContain(
      'The daemon you stopped is not running. Start it again: keyflap daemon --unprotected',
    );
    expect(c.shots.filter((s) => /: Key-store passphrase$/.test(s.caption))).toHaveLength(1);
  });

  it('simple install: offers to stop the background job, defaults to no, and starts it again', async () => {
    const w = await world('simple');
    const c = await tour(w, [
      { q: MANAGE, a: '1' },
      { q: NOW, a: '4' },
      { q: /^Which one/, a: '1' },
      { q: /^Remove the password for/, a: 'y' },
      { q: /^Stop it for now/, a: '' },
      { q: NOW, a: '4' },
      { q: /^Which one/, a: '1' },
      { q: /^Remove the password for/, a: 'y' },
      { q: /^Stop it for now/, a: 'y' },
      { q: NOW, a: ESC },
      { q: MANAGE, a: ESC },
    ]);
    const calls = w.launchctl.calls.map((x) => x.split(' ')[0]);
    expect(calls.filter((x) => x === 'bootout')).toHaveLength(1);
    expect(calls.indexOf('bootout')).toBeLessThan(calls.indexOf('bootstrap'));
    expect(w.launchctl.loaded).toBe(true);
    expect(w.passwords()).toHaveLength(1);
    const refused = c.shots.find((s) => /Remove one: Press Enter to go back/.test(s.caption));
    expect(text(refused as NonNullable<typeof refused>)).toContain(
      'Keyflap is still running, so nothing was changed.',
    );
    const lastBack = c.shots
      .filter((s) => /Remove one: Press Enter to go back/.test(s.caption))
      .at(-1);
    expect(text(lastBack as NonNullable<typeof lastBack>)).toContain(
      '✓ Keyflap is running in the background again.',
    );
  });

  it('simple install: adding a password stops the job once, asks the secret in the no-echo input, and restarts it', async () => {
    const w = await world('simple');
    const c = await tour(w, [
      { q: MANAGE, a: '1' },
      { q: NOW, a: '2' },
      { q: /^Stop it for now/, a: 'y' },
      { q: /^Site/, a: 'notion.so' },
      { q: /^Username/, a: 'sam' },
      { q: /one-time code \(TOTP\)\?/, a: 'n' },
      { q: /^Password/, a: 'typed-secret-pw-8Rv' },
      { q: NOW, a: ESC },
      { q: MANAGE, a: ESC },
    ]);
    expect(w.passwords().map((p) => p.domain)).toContain('notion.so');
    expect(w.launchctl.calls.filter((x) => x.startsWith('bootout'))).toHaveLength(1);
    expect(w.launchctl.loaded).toBe(true);
    expect(everythingShown(c)).not.toContain('typed-secret-pw-8Rv');
  });
});
