import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { type ColorLevel, styleFor, termStyle } from '@aab/approver';
import { PromptAborted } from '../src/setup/prompt.ts';
import { runSetupFlow, terminalUi } from '../src/setup/run.ts';
import type { Size } from '../src/setup/screen.ts';
import { screenHtml, screenPage, TERMINAL_CSS } from './ansi-html.ts';
import { capture, type Shot } from './setup-capture.ts';
import {
  type Platform,
  realDelay,
  SCENARIOS,
  type ScenarioName,
  scenario,
} from './setup-scenarios.ts';

const USAGE = `pnpm setup:preview [--scenario ${SCENARIOS.join('|')}] [--platform darwin|linux]
                   [--plain]
                   [--capture DIR [--size 80x24] [--colors 3|2|1|0]]

Runs the real keyflap setup screens against fakes: no root, no install, no network, and no
change to this machine. Interactive in a terminal; --capture writes every screen as ANSI and
HTML to DIR instead.`;

for (const k of [
  'KEYFLAP_PASSPHRASE',
  'AAB_PASSPHRASE',
  'OP_SERVICE_ACCOUNT_TOKEN',
  'PROTON_PASS_PERSONAL_ACCESS_TOKEN',
]) {
  delete process.env[k];
}

const { values } = parseArgs({
  options: {
    scenario: { type: 'string', default: 'mac-fresh' },
    platform: { type: 'string' },
    plain: { type: 'boolean', default: false },
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
const name = values.scenario as ScenarioName;
if (!SCENARIOS.includes(name)) fail(`unknown scenario: ${values.scenario}`);
const platform = values.platform as Platform | undefined;
if (platform !== undefined && platform !== 'darwin' && platform !== 'linux') {
  fail(`unknown platform: ${platform}`);
}

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 48);

const esc = (s: string) => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;');

async function runCapture(dir: string): Promise<void> {
  const m = /^(\d+)x(\d+)$/.exec(values.size);
  if (!m) fail(`--size is COLSxROWS, e.g. 80x24`);
  const size: Size = { cols: Number(m[1]), rows: Number(m[2]) };
  const level = Number(values.colors) as ColorLevel;
  if (![0, 1, 2, 3].includes(level)) fail('--colors is 3, 2, 1 or 0');
  const style = termStyle(level);
  const c = await capture(name, { size, style, ...(platform ? { platform } : {}) });
  mkdirSync(dir, { recursive: true });
  const figure = (shot: Pick<Shot, 'painted'>) =>
    screenHtml({ lines: shot.painted.lines, cursor: shot.painted.cursor, ...size });
  const items: string[] = [];
  c.shots.forEach((shot, i) => {
    const base = `${String(i + 1).padStart(2, '0')}-${slug(shot.caption)}`;
    writeFileSync(join(dir, `${base}.ansi`), `${shot.painted.lines.join('\n')}\u001b[0m\n`);
    writeFileSync(
      join(dir, `${base}.html`),
      screenPage(shot.caption, { lines: shot.painted.lines, cursor: shot.painted.cursor, ...size }),
    );
    items.push(
      `<figure id="s${i + 1}"><figcaption><b>${i + 1}</b> ${esc(shot.caption)}</figcaption>${figure(shot)}</figure>`,
    );
  });
  writeFileSync(join(dir, 'setup.log'), c.log);
  writeFileSync(join(dir, 'after-exit.txt'), c.after);
  writeFileSync(
    join(dir, 'index.html'),
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Setup screens</title><style>
body{margin:0;padding:16px;background:#14161d;color:#c4c8d2;font:16px/1.5 system-ui,sans-serif}
h1,h2,h3{color:#f4f5f7;font-weight:700}
figure{margin:0 0 28px}
figcaption{margin:0 0 8px;color:#9ba1b0}
figcaption b{color:#7b91ff;margin-right:6px}
.wrap{overflow-x:auto}
@media (max-width:760px){.term{--fs:calc((100vw - 58px) / ${size.cols} / 0.602)}}
${TERMINAL_CSS}
</style></head><body>
<h1>keyflap setup, ${esc(name)}${platform ? ` (${platform})` : ''}</h1>
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
  const ui = terminalUi({
    stdin: process.stdin,
    stdout: process.stdout,
    env: values.plain ? { ...process.env, TERM: 'dumb' } : process.env,
    style: styleFor(process.stdout),
    mode: 'service mode',
    started: new Date().toISOString(),
  });
  const run = scenario(name, { ui, delay: realDelay, ...(platform ? { platform } : {}) });
  try {
    await runSetupFlow(run.ctx, { mode: run.mode });
  } catch (err) {
    if (err instanceof PromptAborted) {
      process.stderr.write('\nPreview stopped.\n');
      process.exit(130);
    }
    throw err;
  }
  process.stdout.write(
    `\nPreview only: nothing on this machine changed. Run it again with --scenario ${SCENARIOS.filter((s) => s !== name).join(' or --scenario ')}.\n`,
  );
}

if (values.capture) await runCapture(resolve(values.capture));
else await runInteractive();
