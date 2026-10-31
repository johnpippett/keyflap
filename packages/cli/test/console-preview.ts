import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { type ColorLevel, styleFor, type TermStyle, termStyle } from '@aab/approver';
import { devModeName } from '../src/console/dev-start.ts';
import { runConsole } from '../src/console/run.ts';
import { UNPROTECTED_FLAP } from '../src/console/unprotected.ts';
import { TtyPrompter } from '../src/setup/prompt.ts';
import type { Size } from '../src/setup/screen.ts';
import { ttyKeys, ttyScreen } from '../src/setup/tty-screen.ts';
import { ScreenUi, SetupLog } from '../src/setup/ui.ts';
import { screenHtml, screenPage, TERMINAL_CSS } from './ansi-html.ts';
import { captureConsole, captureSession, devTour, TOUR } from './console-capture.ts';
import { DEV_PASSPHRASE, devConsoleWorld } from './console-dev-world.ts';
import { consoleWorld } from './console-world.ts';
import { realDelay } from './setup-scenarios.ts';

const USAGE = `pnpm console:preview [--mode service|dev|simple] [--platform darwin|linux]
                     [--capture DIR [--size 80x24] [--colors 3|2|1|0]]

Runs the real keyflap console against a throwaway broker: no root, no install, no change to
this machine. --mode service (default) is sudo keyflap: real admin operations on a throwaway
database. --mode dev and --mode simple are the unprotected console you get as your own user:
a throwaway data directory with a real key store (dev passphrase: ${DEV_PASSPHRASE}), and for
simple a pretend background job. Interactive in a terminal; --capture walks a scripted tour
and writes every screen as ANSI and HTML to DIR instead.`;

const { values } = parseArgs({
  options: {
    mode: { type: 'string', default: 'service' },
    platform: { type: 'string', default: 'darwin' },
    capture: { type: 'string' },
    size: { type: 'string', default: '80x24' },
    colors: { type: 'string', default: '3' },
    help: { type: 'boolean', default: false },
  },
});

function fail(message: string): never {
  process.stderr.write(`${message}\n\n${USAGE}\n`);
  process.exit(2);
}

if (values.help) {
  process.stdout.write(`${USAGE}\n`);
  process.exit(0);
}
if (values.platform !== 'darwin' && values.platform !== 'linux') {
  fail(`unknown platform: ${values.platform}`);
}
const platform: 'darwin' | 'linux' = values.platform;
if (values.mode !== 'service' && values.mode !== 'dev' && values.mode !== 'simple') {
  fail(`unknown mode: ${values.mode}`);
}
const mode: 'service' | 'dev' | 'simple' = values.mode;

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 48);

const esc = (s: string) => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;');

async function captureTour(size: Size, style: TermStyle) {
  if (mode === 'service') {
    const c = await captureConsole(TOUR, { size, style, platform });
    await c.world.close();
    return c;
  }
  const world = await devConsoleWorld(mode);
  try {
    return await captureSession(devTour(mode, DEV_PASSPHRASE), {
      size,
      style,
      mode: devModeName(mode),
      alert: UNPROTECTED_FLAP,
      run: async (ui) => {
        await world.run(ui, style);
      },
    });
  } finally {
    await world.close();
  }
}

async function runCapture(dir: string): Promise<void> {
  const m = /^(\d+)x(\d+)$/.exec(values.size);
  if (!m) fail('--size is COLSxROWS, e.g. 80x24');
  const size: Size = { cols: Number(m[1]), rows: Number(m[2]) };
  const level = Number(values.colors) as ColorLevel;
  if (![0, 1, 2, 3].includes(level)) fail('--colors is 3, 2, 1 or 0');
  const style = termStyle(level);
  const c = await captureTour(size, style);
  mkdirSync(dir, { recursive: true });
  const items: string[] = [];
  c.shots.forEach((shot, i) => {
    const base = `${String(i + 1).padStart(2, '0')}-${slug(shot.caption)}`;
    const screen = { lines: shot.painted.lines, cursor: shot.painted.cursor, ...size };
    writeFileSync(join(dir, `${base}.ansi`), `${shot.painted.lines.join('\n')}\u001b[0m\n`);
    writeFileSync(join(dir, `${base}.html`), screenPage(shot.caption, screen));
    items.push(
      `<figure id="s${i + 1}"><figcaption><b>${i + 1}</b> ${esc(shot.caption)}</figcaption>${screenHtml(screen)}</figure>`,
    );
  });
  writeFileSync(join(dir, 'after-exit.txt'), c.after);
  writeFileSync(
    join(dir, 'index.html'),
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Console screens</title><style>
body{margin:0;padding:16px;background:#14161d;color:#c4c8d2;font:16px/1.5 system-ui,sans-serif}
h1,h2,h3{color:#f4f5f7;font-weight:700}
figure{margin:0 0 28px}
figcaption{margin:0 0 8px;color:#9ba1b0}
figcaption b{color:#7b91ff;margin-right:6px}
.wrap{overflow-x:auto}
@media (max-width:760px){.term{--fs:calc((100vw - 58px) / ${size.cols} / 0.602)}}
${TERMINAL_CSS}
</style></head><body>
<h1>${mode === 'service' ? `keyflap console (sudo keyflap), ${esc(platform)}` : `keyflap unprotected console (${esc(devModeName(mode))})`}</h1>
<p>${c.shots.length} screens at ${size.cols}x${size.rows}, ${level === 3 ? '24-bit' : level === 2 ? '256' : level === 1 ? '16' : 'no'} colour. Each is the screen just before the key press that leaves it.</p>
${items.join('\n')}
</body></html>\n`,
  );
  process.stdout.write(`${c.shots.length} screens in ${dir} (index.html)\n`);
}

async function runInteractive(): Promise<void> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    fail('the interactive preview needs a terminal; use --capture DIR for files');
  }
  const style = styleFor(process.stdout);
  const ui = new ScreenUi({
    screen: ttyScreen(process.stdout, process.stdin),
    keys: ttyKeys(process.stdin),
    style,
    mode: mode === 'service' ? 'service mode' : devModeName(mode),
    app: 'console',
    ...(mode === 'service' ? {} : { alert: UNPROTECTED_FLAP }),
    log: new SetupLog(new Date().toISOString()),
    afterLeave: (t) => {
      process.stdout.write(t);
    },
    fallbackPrompt: new TtyPrompter(process.stdin, process.stdout),
  });
  if (mode !== 'service') {
    const dev = await devConsoleWorld(mode);
    try {
      await dev.run(ui, style);
    } finally {
      await dev.close();
    }
    process.stdout.write('\nPreview only: nothing on this machine changed.\n');
    return;
  }
  const world = await consoleWorld({ ui, style, platform, delay: realDelay });
  try {
    await runConsole({
      ui,
      ctx: world.ctx,
      dispatch: world.dispatch,
      style,
      snapshot: world.snapshot,
    });
  } finally {
    await world.close();
  }
  process.stdout.write('\nPreview only: nothing on this machine changed.\n');
}

if (values.capture) await runCapture(resolve(values.capture));
else await runInteractive();
