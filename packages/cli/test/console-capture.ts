import type { TermStyle } from '@aab/approver';
import { type Dispatch, runConsole } from '../src/console/run.ts';
import { type Frame, type Key, type Painted, paint, type Size } from '../src/setup/screen.ts';
import { type Keys, type Screen, ScreenUi, SetupLog } from '../src/setup/ui.ts';
import { consoleWorld, type Delay, type World } from './console-world.ts';

export const ESC = '\u001b';

export interface Step {
  q: RegExp;
  a: string;
  before?: () => void | Promise<void>;
}

export interface Shot {
  caption: string;
  painted: Painted;
  frame: Frame;
}

export interface ConsoleCapture {
  shots: Shot[];
  world: World;
  after: string;
}

const clone = (f: Frame): Frame => structuredClone(f);

const QUIET = new Set(['Asking Keyflap', 'Reading the status']);

function caption(f: Frame, what: string): string {
  const where = f.section ? f.section.title : 'Overview';
  return `${where}${f.page ? ` · ${f.page}` : ''}: ${what}`;
}

function keysFor(a: string): Key[] {
  if (a === ESC) return [{ kind: 'escape' }];
  return [...Array.from(a, (ch) => ({ kind: 'char', ch }) as Key), { kind: 'enter' }];
}

export interface Session {
  shots: Shot[];
  after: string;
  log: string;
}

export async function captureSession(
  steps: Step[],
  o: {
    size: Size;
    style: TermStyle;
    mode: string;
    alert?: string;
    run: (ui: ScreenUi) => Promise<void>;
  },
): Promise<Session> {
  const script = [...steps];
  const shots: Shot[] = [];
  let last: { painted: Painted; frame: Frame } | null = null;
  let lastStatus: string | null = null;
  let lastDetails = '';
  const shoot = (what: string, f: Frame, painted: Painted) => {
    shots.push({ caption: caption(f, what), painted, frame: clone(f) });
  };
  const screen: Screen = {
    size: () => o.size,
    enter: () => {},
    restore: () => {},
    draw(p, f) {
      last = { painted: p, frame: clone(f) };
      const label = f.status?.label ?? null;
      if (label !== null && label !== lastStatus && !QUIET.has(label)) shoot(label, f, p);
      lastStatus = label;
    },
  };
  const queue: Key[] = [];
  let inputSeen: object | null = null;
  let failure: Error | null = null;
  const fail: (message: string) => never = (message) => {
    failure ??= new Error(message);
    throw failure;
  };
  const keys: Keys = {
    open() {},
    async next(f) {
      const input = f.input;
      if (!input) fail('capture: asked for a key with no input on screen');
      if (input !== inputSeen) {
        inputSeen = input;
        queue.length = 0;
        if (input.kind === 'continue') {
          queue.push({ kind: 'enter' });
        } else {
          const next = script.shift();
          if (!next?.q.test(input.label)) {
            fail(`capture: no canned answer for "${input.label}" (next: ${next?.q})`);
          }
          await next?.before?.();
          queue.push(...keysFor((next as Step).a));
        }
      }
      const k = queue.shift() as Key;
      if ((k.kind === 'enter' || k.kind === 'escape') && last) {
        shoot(k.kind === 'escape' ? `${input.label} (Esc)` : input.label, last.frame, last.painted);
        const details = f.details.join('\n');
        if (details !== '' && details !== lastDetails) {
          lastDetails = details;
          const d = { ...clone(last.frame), view: 'details' as const, scroll: 0 };
          shoot('Tab: details', d, paint(d, o.size, o.style));
        }
      }
      return k;
    },
    flush() {},
    close() {},
  };
  let after = '';
  const log = new SetupLog('2026-10-30T09:00:00.000Z');
  const ui = new ScreenUi({
    screen,
    keys,
    style: o.style,
    mode: o.mode,
    app: 'console',
    ...(o.alert ? { alert: o.alert } : {}),
    log,
    afterLeave: (t) => {
      after += t;
    },
    fallbackPrompt: {
      ask: () => Promise.reject(new Error('capture: prompt after leaving the screen')),
      secret: () => Promise.reject(new Error('capture: prompt after leaving the screen')),
    },
  });
  await o.run(ui);
  if (failure) throw failure;
  if (script.length > 0) {
    throw new Error(`capture: ${script.length} canned answers left over (${script[0]?.q})`);
  }
  return { shots, after, log: log.text() };
}

export async function captureConsole(
  steps: Step[],
  o: {
    size: Size;
    style: TermStyle;
    platform?: 'darwin' | 'linux';
    delay?: Delay;
    passwords?: string[];
    prepare?: (w: World) => void;
    dispatch?: (w: World) => Dispatch;
  },
): Promise<ConsoleCapture> {
  const held: { world: World | null } = { world: null };
  try {
    const session = await captureSession(steps, {
      size: o.size,
      style: o.style,
      mode: 'service mode',
      run: async (ui) => {
        const w = await consoleWorld({
          ui,
          style: o.style,
          ...(o.platform ? { platform: o.platform } : {}),
          ...(o.delay ? { delay: o.delay } : {}),
          ...(o.passwords ? { passwords: o.passwords } : {}),
        });
        held.world = w;
        o.prepare?.(w);
        const dispatch = o.dispatch?.(w) ?? w.dispatch;
        await runConsole({
          ui,
          ctx: w.ctx,
          dispatch,
          style: o.style,
          snapshot: () => w.snapshot(dispatch),
        });
      },
    });
    return { shots: session.shots, world: held.world as World, after: session.after };
  } catch (err) {
    await held.world?.close();
    throw err;
  }
}

export const TOUR: Step[] = [
  { q: /^What do you want to manage\?/, a: '1' },
  { q: /^What now\?/, a: '1' },
  { q: /^What now\?/, a: '2' },
  { q: /^Site/, a: 'notion.so' },
  { q: /^Username/, a: 'sam' },
  { q: /one-time code \(TOTP\)\?/, a: 'n' },
  { q: /^Password/, a: 'tour-typed-pw' },
  { q: /^What now\?/, a: '4' },
  { q: /^Which one\?/, a: '3' },
  { q: /^Remove the password for linear\.app/, a: 'y' },
  { q: /^What now\?/, a: ESC },
  { q: /^What do you want to manage\?/, a: '2' },
  { q: /^What now\?/, a: '1' },
  { q: /^What now\?/, a: ESC },
  { q: /^What do you want to manage\?/, a: '3' },
  { q: /^What now\?/, a: '2' },
  { q: /^Pair another phone/, a: 'y' },
  { q: /^What now\?/, a: ESC },
  { q: /^What do you want to manage\?/, a: '4' },
  { q: /^What now\?/, a: '2' },
  { q: /^Set up an agent for Claude Code\?/, a: '' },
  { q: /^Agent name/, a: 'research' },
  { q: /^Write the Claude Code config/, a: '' },
  { q: /^Which Claude Code config\?/, a: '2' },
  { q: /^Apply these changes\?/, a: 'y' },
  { q: /^What now\?/, a: '3' },
  { q: /^Which one\?/, a: '2' },
  { q: /^Revoke "codex"\?/, a: '' },
  { q: /^What now\?/, a: ESC },
  { q: /^What do you want to manage\?/, a: '5' },
  { q: /^What now\?/, a: '2' },
  { q: /^Site/, a: 'github.com' },
  { q: /^For which agent\?/, a: '' },
  { q: /^What should happen\?/, a: '3' },
  { q: /^For how long/, a: '30m' },
  { q: /^github\.com: skip the prompt/, a: 'y' },
  { q: /^What now\?/, a: '1' },
  { q: /^What now\?/, a: ESC },
  { q: /^What do you want to manage\?/, a: '6' },
  { q: /^What now\?/, a: '2' },
  { q: /^Which agent\?/, a: '2' },
  { q: /^Which site/, a: 'github.com' },
  { q: /^Sign agent "claude-code" out of github\.com\?/, a: 'y' },
  { q: /^What now\?/, a: ESC },
  { q: /^What do you want to manage\?/, a: '7' },
  { q: /^What now\?/, a: '1' },
  { q: /^What now\?/, a: '2' },
  { q: /^What now\?/, a: '3' },
  { q: /^What now\?/, a: ESC },
  { q: /^What do you want to manage\?/, a: ESC },
];

export function devTour(install: 'dev' | 'simple', passphrase: string): Step[] {
  const unlock: Step[] =
    install === 'dev'
      ? [{ q: /^Key-store passphrase/, a: passphrase }]
      : [{ q: /^Stop it for now/, a: 'y' }];
  return [
    { q: /^What do you want to manage\?/, a: '1' },
    { q: /^What now\?/, a: '1' },
    { q: /^What now\?/, a: '4' },
    { q: /^Which one\?/, a: '1' },
    { q: /^Remove the password for/, a: 'y' },
    ...unlock,
    { q: /^What now\?/, a: ESC },
    { q: /^What do you want to manage\?/, a: '4' },
    { q: /^What now\?/, a: '1' },
    { q: /^What now\?/, a: ESC },
    { q: /^What do you want to manage\?/, a: '7' },
    { q: /^What now\?/, a: '1' },
    { q: /^What now\?/, a: '3' },
    { q: /^What now\?/, a: ESC },
    { q: /^What do you want to manage\?/, a: ESC },
  ];
}
