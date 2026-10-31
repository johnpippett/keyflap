import { encodeQr, type QrCode, stripStyle, styleFor, type TermStyle } from '@aab/approver';
import { beforeAll, describe, expect, it } from 'vitest';
import { UNPROTECTED_FLAP } from '../src/console/unprotected.ts';
import { bodyText, type Frame, NO_ROOM_FOR_CODE, paint, type Size } from '../src/setup/screen.ts';
import { captureConsole, ESC } from './console-capture.ts';
import { capture } from './setup-capture.ts';

type Colour = string | null;

interface Cell {
  ch: string;
  fg: Colour;
  bg: Colour;
}

type Op = ['reset'] | ['reverse', boolean] | ['fg' | 'bg', Colour];

function colourAt(ps: number[], i: number): { colour: Colour; used: number } {
  if (ps[i + 1] === 5) return { colour: `i${ps[i + 2]}`, used: 2 };
  const hex = [ps[i + 2], ps[i + 3], ps[i + 4]].map((v) => (v ?? 0).toString(16).padStart(2, '0'));
  return { colour: `#${hex.join('')}`, used: 4 };
}

function sgrOps(params: string): Op[] {
  const ps = (params === '' ? '0' : params).split(';').map(Number);
  const ops: Op[] = [];
  for (let i = 0; i < ps.length; i++) {
    const p = ps[i] as number;
    if (p === 0) ops.push(['reset']);
    else if (p === 7 || p === 27) ops.push(['reverse', p === 7]);
    else if (p === 39) ops.push(['fg', null]);
    else if (p === 49) ops.push(['bg', null]);
    else if (p === 38 || p === 48) {
      const { colour, used } = colourAt(ps, i);
      i += used;
      ops.push([p === 38 ? 'fg' : 'bg', colour]);
    } else if (p >= 30 && p <= 37) ops.push(['fg', `p${p - 30}`]);
    else if (p >= 90 && p <= 97) ops.push(['fg', `p${p - 82}`]);
    else if (p >= 40 && p <= 47) ops.push(['bg', `p${p - 40}`]);
    else if (p >= 100 && p <= 107) ops.push(['bg', `p${p - 92}`]);
  }
  return ops;
}

const SGR_OPS = new Map<string, Op[]>();

function cellsOf(line: string): Cell[] {
  const cells: Cell[] = [];
  let fg: Colour = null;
  let bg: Colour = null;
  let reverse = false;
  let i = 0;
  while (i < line.length) {
    if (line.charCodeAt(i) === 0x1b && line[i + 1] === '[') {
      let j = i + 2;
      for (
        let c = line.charCodeAt(j);
        j < line.length && (c < 64 || c > 126);
        c = line.charCodeAt(++j)
      );
      if (line[j] === 'm') {
        const params = line.slice(i + 2, j);
        let ops = SGR_OPS.get(params);
        if (!ops) {
          ops = sgrOps(params);
          SGR_OPS.set(params, ops);
        }
        for (const op of ops) {
          if (op[0] === 'reset') {
            fg = null;
            bg = null;
            reverse = false;
          } else if (op[0] === 'reverse') reverse = op[1];
          else if (op[0] === 'fg') fg = op[1];
          else bg = op[1];
        }
      }
      i = j + 1;
      continue;
    }
    const code = line.codePointAt(i) as number;
    const ch = String.fromCodePoint(code);
    cells.push(reverse ? { ch, fg: bg, bg: fg } : { ch, fg, bg });
    i += ch.length;
  }
  return cells;
}

const INKS: Record<number, { dark: string; light: string; sgr: RegExp }> = {
  0: { dark: 'p0', light: 'p15', sgr: /[[;](?:30|40|97|107)[;m]/ },
  1: { dark: 'p0', light: 'p15', sgr: /[[;](?:30|40|97|107)[;m]/ },
  2: { dark: 'i16', light: 'i231', sgr: /[34]8;5;(?:16|231)[;m]/ },
  3: { dark: '#000000', light: '#ffffff', sgr: /[34]8;2;(?:0;0;0|255;255;255)[;m]/ },
};

type Seen =
  | { kind: 'code'; drawing: 'cells' | 'half-blocks'; modules: boolean[][] }
  | { kind: 'no code' };

function read(lines: string[], st: TermStyle, cols: number): Seen {
  const ink = INKS[st.level] as { dark: string; light: string; sgr: RegExp };
  const isInk = (c: Colour) => c === ink.dark || c === ink.light;
  const grid = lines.map((l) => (ink.sgr.test(l) ? cellsOf(l) : []));
  const codeCell = (c: Cell | undefined) =>
    c !== undefined &&
    ((c.ch === ' ' && isInk(c.bg)) || (c.ch === '▀' && isInk(c.fg) && isInk(c.bg)));
  let top = -1;
  let bottom = -1;
  let left = Number.POSITIVE_INFINITY;
  let right = -1;
  grid.forEach((row, y) => {
    row.forEach((c, x) => {
      if (!codeCell(c)) return;
      if (top < 0) top = y;
      bottom = y;
      left = Math.min(left, x);
      right = Math.max(right, x);
    });
  });
  if (top < 0) return { kind: 'no code' };
  if (right > cols - 2) throw new Error(`the code reaches the last column (${right} of ${cols})`);
  const box: Cell[][] = [];
  for (let y = top; y <= bottom; y++) {
    const row = (grid[y] as Cell[]).slice(left, right + 1);
    if (row.length !== right - left + 1 || !row.every(codeCell)) {
      throw new Error(`painted row ${y} is not all code between columns ${left} and ${right}`);
    }
    box.push(row);
  }
  const chars = new Set(box.flat().map((c) => c.ch));
  if (chars.size !== 1) throw new Error('the code mixes full cells and half blocks');
  const dark = (c: Colour) => c === ink.dark;
  if (chars.has(' ')) {
    if (box[0]?.length === undefined || box[0].length % 2 !== 0) {
      throw new Error('a full-cell code must be an even number of cells wide');
    }
    const modules = box.map((row) => {
      const out: boolean[] = [];
      for (let x = 0; x < row.length; x += 2) {
        const a = row[x] as Cell;
        const b = row[x + 1] as Cell;
        if (a.bg !== b.bg) throw new Error('a module is split across its two cells');
        out.push(dark(a.bg));
      }
      return out;
    });
    return { kind: 'code', drawing: 'cells', modules };
  }
  const modules = box.flatMap((row) => [row.map((c) => dark(c.fg)), row.map((c) => dark(c.bg))]);
  return { kind: 'code', drawing: 'half-blocks', modules };
}

function expected(q: QrCode): boolean[][] {
  const quiet = 4;
  const n = q.size + quiet * 2;
  return Array.from({ length: n }, (_, y) =>
    Array.from({ length: n }, (_, x) => q.modules[y - quiet]?.[x - quiet] === true),
  );
}

function sameCode(seen: boolean[][], q: QrCode): boolean {
  const want = expected(q);
  const extra = seen.length - want.length;
  if (extra !== 0 && extra !== 1) return false;
  if (extra === 1 && (seen.at(-1) as boolean[]).some(Boolean)) return false;
  return JSON.stringify(seen.slice(0, want.length)) === JSON.stringify(want);
}

const words = (lines: string[]) => lines.map(stripStyle).join(' ').replace(/\s+/g, ' ');

const NO_ROOM_WORDS = NO_ROOM_FOR_CODE.replace(/^! /, '');

const tty = { isTTY: true };
const TERMINALS: Record<string, TermStyle> = {
  'Terminal.app': styleFor(tty, { TERM_PROGRAM: 'Apple_Terminal', TERM: 'xterm-256color' }),
  'Terminal.app under sudo': styleFor(tty, { TERM: 'xterm-256color' }),
  'unknown, light background': styleFor(tty, { TERM: 'xterm-256color', COLORFGBG: '0;15' }),
  'unknown, 16 colours': styleFor(tty, { TERM: 'xterm' }),
  'NO_COLOR on a terminal': styleFor(tty, { TERM: 'xterm-256color', NO_COLOR: '1' }),
  Ghostty: styleFor(tty, {
    TERM_PROGRAM: 'ghostty',
    TERM: 'xterm-ghostty',
    COLORTERM: 'truecolor',
  }),
  'kitty under sudo': styleFor(tty, { TERM: 'xterm-kitty' }),
  'iTerm2 over ssh': styleFor(tty, { TERM: 'xterm-256color', LC_TERMINAL: 'iTerm2' }),
  'tmux inside Ghostty': styleFor(tty, {
    TERM: 'tmux-256color',
    TERM_PROGRAM: 'tmux',
    TMUX: '/tmp/tmux-1000/default,1,0',
    GHOSTTY_RESOURCES_DIR: '/usr/share/ghostty',
    COLORTERM: 'truecolor',
  }),
};

const URLS = {
  'a pairing link (version 6)': `https://devbox.tail1a2b3c.ts.net:8766/pair#${'Ab3_'.repeat(10)}xY-`,
  'a short host (version 5)': `https://m.a.ts.net:8766/pair#${'Ab3_'.repeat(10)}xY-`,
  'a long host (version 7)': `https://keyflap-office-mac-mini.tailnet-0123ab.ts.net:8766/pair#${'Ab3_'.repeat(10)}xY-`,
};

const withCode = (f: Frame, q: QrCode): Frame => ({
  ...f,
  blocks: f.blocks.map((b) => (b.kind === 'figure' ? { ...b, qr: q } : b)),
});

function verdict(f: Frame, q: QrCode, size: Size, st: TermStyle): Seen {
  const painted = paint(f, size, st);
  if (painted.lines.length !== size.rows) throw new Error(`${size.cols}x${size.rows}: line count`);
  const seen = read(painted.lines, st, size.cols);
  const text = words(painted.lines);
  if (seen.kind === 'code') {
    if (!sameCode(seen.modules, q)) throw new Error(`${size.cols}x${size.rows}: wrong modules`);
    if (seen.drawing === 'half-blocks' && !st.drawsBlocks) {
      throw new Error(
        `${size.cols}x${size.rows}: half blocks on a terminal that may not fill them`,
      );
    }
    if (text.includes(NO_ROOM_WORDS)) throw new Error('both the code and the replacement');
  } else if (!text.includes(NO_ROOM_WORDS)) {
    throw new Error(`${size.cols}x${size.rows}: neither the code nor the replacement line`);
  }
  return seen;
}

function sizes(colStep: number, rowStep: number, from = 40, to = 260): Size[] {
  const out: Size[] = [];
  for (let cols = from; cols <= to; cols += colStep) {
    for (let rows = 12; rows <= 80; rows += rowStep) out.push({ cols, rows });
  }
  return out;
}

const PICK: Size = { cols: 120, rows: 40 };

async function consolePairing(): Promise<Frame> {
  const c = await captureConsole(
    [
      { q: /^What do you want to manage\?/, a: '3' },
      { q: /^What now\?/, a: '2' },
      { q: /^Pair another phone/, a: 'y' },
      { q: /^What now\?/, a: ESC },
      { q: /^What do you want to manage\?/, a: ESC },
    ],
    { size: PICK, style: TERMINALS.Ghostty as TermStyle },
  );
  await c.world.close();
  const shot = c.shots.find((s) => s.frame.blocks.some((b) => b.kind === 'figure'));
  if (!shot) throw new Error('the console never showed the pairing code');
  return shot.frame;
}

async function setupPairing(): Promise<Frame> {
  const c = await capture('mac-fresh', { size: PICK, style: TERMINALS.Ghostty as TermStyle });
  const shot = c.shots.find((s) => /Scan the code: Waiting for your phone/.test(s.caption));
  if (!shot) throw new Error('setup never showed the pairing code');
  return shot.frame;
}

describe('the pairing code on the full screen: the whole code or the replacement line, never part of one', () => {
  const frames: Record<string, Frame> = {};
  beforeAll(async () => {
    frames['console, Phones > Pair'] = await consolePairing();
    frames['setup, step 3'] = await setupPairing();
  });

  const tally = (st: TermStyle, grid: Size[]) => {
    const q = encodeQr(URLS['a pairing link (version 6)']);
    const f = withCode(frames['console, Phones > Pair'] as Frame, q);
    const counts = { cells: 0, 'half-blocks': 0, 'no code': 0 };
    for (const size of grid) {
      const seen = verdict(f, q, size, st);
      counts[seen.kind === 'code' ? seen.drawing : 'no code']++;
    }
    return counts;
  };

  for (const [terminal, every] of [
    ['Terminal.app under sudo', 6],
    ['Ghostty', 10],
  ] as const) {
    const st = TERMINALS[terminal] as TermStyle;
    it(`${terminal}: every column from 40 to 260, at every ${every}th row`, () => {
      const counts = tally(st, sizes(1, every));
      expect(counts.cells).toBeGreaterThan(0);
      expect(counts['no code']).toBeGreaterThan(0);
      expect(counts['half-blocks'] > 0).toBe(st.drawsBlocks);
    });
    it(`${terminal}: every row from 12 to 80, at every ${every}th column`, () => {
      const counts = tally(st, sizes(every, 1));
      expect(counts.cells).toBeGreaterThan(0);
      expect(counts['no code']).toBeGreaterThan(0);
      expect(counts['half-blocks'] > 0).toBe(st.drawsBlocks);
    });
  }

  for (const [terminal, st] of Object.entries(TERMINALS)) {
    it(`${terminal}: every 8th column and 5th row from 40x12 to 260x80`, () => {
      const counts = tally(st, sizes(8, 5));
      expect(counts.cells).toBeGreaterThan(0);
      expect(counts['no code']).toBeGreaterThan(0);
      if (st.drawsBlocks) expect(counts['half-blocks']).toBeGreaterThan(0);
      else expect(counts['half-blocks']).toBe(0);
    });
  }

  for (const [where, url] of Object.entries(URLS)) {
    it(`${where}, both screens, three terminals, every 15th column and 8th row`, () => {
      const q = encodeQr(url);
      for (const frame of Object.values(frames)) {
        const f = withCode(frame, q);
        for (const name of ['Terminal.app', 'Ghostty', 'unknown, 16 colours']) {
          for (const size of sizes(15, 8)) verdict(f, q, size, TERMINALS[name] as TermStyle);
        }
      }
    });
  }

  it('needs 130x49 for full cells with the text beside, or 99 columns and 61 rows with it below', () => {
    const q = encodeQr(URLS['a pairing link (version 6)']);
    const f = withCode(frames['console, Phones > Pair'] as Frame, q);
    const at = (cols: number, rows: number, terminal = 'Terminal.app') => {
      const seen = verdict(f, q, { cols, rows }, TERMINALS[terminal] as TermStyle);
      return seen.kind === 'code' ? seen.drawing : seen.kind;
    };
    expect([at(130, 49), at(130, 48), at(129, 60), at(129, 61), at(99, 61), at(98, 80)]).toEqual([
      'cells',
      'no code',
      'no code',
      'cells',
      'cells',
      'no code',
    ]);
    expect([at(90, 25, 'Ghostty'), at(90, 24, 'Ghostty'), at(50, 40, 'Ghostty')]).toEqual([
      'half-blocks',
      'no code',
      'half-blocks',
    ]);
  });

  it('with the unprotected header on, never cuts a row of the code: the header is never trimmed away', () => {
    const q = encodeQr(URLS['a pairing link (version 6)']);
    const f = {
      ...withCode(frames['console, Phones > Pair'] as Frame, q),
      alert: UNPROTECTED_FLAP,
    };
    for (const name of ['Terminal.app', 'Ghostty']) {
      const st = TERMINALS[name] as TermStyle;
      for (const size of [...sizes(1, 6, 40, 140), ...sizes(6, 1, 40, 140)]) {
        verdict(f, q, size, st);
        expect(stripStyle(paint(f, size, st).lines[0] as string)).toContain(UNPROTECTED_FLAP);
      }
    }
  });

  it('leaves neither the code nor the Tab hint in the scrollback once the screen closes', () => {
    const q = encodeQr(URLS['a pairing link (version 6)']);
    const f = withCode(frames['console, Phones > Pair'] as Frame, q);
    const figure = f.blocks.find((b) => b.kind === 'figure') as { beside: string };
    for (const name of ['Terminal.app', 'Ghostty']) {
      const st = TERMINALS[name] as TermStyle;
      for (const size of [
        { cols: 213, rows: 54 },
        { cols: 60, rows: 20 },
      ]) {
        const left = bodyText(f, size, st).split('\n');
        expect(read(left, st, size.cols)).toEqual({ kind: 'no code' });
        expect(words(left)).not.toContain(NO_ROOM_WORDS);
        expect(words(left)).toContain(words(figure.beside.split('\n')).split(' ')[0] as string);
      }
    }
  });

  it('shows the code drawn in full cells in the window the owner used (Terminal.app, 213x54)', () => {
    const q = encodeQr(URLS['a pairing link (version 6)']);
    const f = withCode(frames['console, Phones > Pair'] as Frame, q);
    const seen = verdict(f, q, { cols: 213, rows: 54 }, TERMINALS['Terminal.app'] as TermStyle);
    expect(seen).toMatchObject({ kind: 'code', drawing: 'cells' });
  });

  it('re-picks the drawing on every paint, so a zoom or resize can bring the code back', () => {
    const q = encodeQr(URLS['a pairing link (version 6)']);
    const f = withCode(frames['console, Phones > Pair'] as Frame, q);
    const st = TERMINALS.Ghostty as TermStyle;
    const kinds = [
      { cols: 213, rows: 54 },
      { cols: 100, rows: 32 },
      { cols: 60, rows: 20 },
      { cols: 213, rows: 54 },
    ].map((size) => {
      const seen = verdict(f, q, size, st);
      return seen.kind === 'code' ? seen.drawing : seen.kind;
    });
    expect(kinds).toEqual(['cells', 'half-blocks', 'no code', 'cells']);
  });

  it('draws the code in pure black and white at 256 colours and 24-bit colour', () => {
    const q = encodeQr(URLS['a pairing link (version 6)']);
    const f = withCode(frames['console, Phones > Pair'] as Frame, q);
    for (const [name, inks] of [
      ['Terminal.app', ['48;5;16m', '48;5;231m']],
      ['Ghostty', ['48;2;0;0;0m', '48;2;255;255;255m']],
    ] as const) {
      const out = paint(f, { cols: 213, rows: 54 }, TERMINALS[name] as TermStyle).lines.join('\n');
      for (const ink of inks) expect(out, name).toContain(ink);
    }
  });
});
