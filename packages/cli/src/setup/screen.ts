import {
  drawQr,
  type QrCode,
  type QrDrawing,
  qrExtent,
  stripStyle,
  type TermStyle,
} from '@aab/approver';

export const STEP_COUNT = 6;
export const STEP_NAMES = [
  'Preflight',
  'Approval address',
  'Pair your phone',
  'Agent',
  'Credentials',
  'Finish',
];

export interface QrFigure {
  qr: QrCode;
  beside: string;
}

export interface ArtFigure {
  art: string;
  beside: string;
}

export type Short = string | ArtFigure | (QrFigure & { printed: string });

export type Block =
  | { kind: 'text'; text: string }
  | ({ kind: 'figure' } & (QrFigure | ArtFigure))
  | { kind: 'answer'; question: string; answer: string };

export type Input =
  | { kind: 'line'; label: string; hint: string; value: string; hidden: boolean }
  | { kind: 'menu'; label: string; options: readonly string[]; selected: number }
  | { kind: 'continue'; label: string };

export type App = 'setup' | 'console';

export interface Place {
  n: number;
  of: number;
  title: string;
}

export interface Frame {
  app: App;
  mode: string;
  alert: string | null;
  step: { n: number; title: string } | null;
  section: Place | null;
  page: string | null;
  blocks: Block[];
  details: string[];
  view: 'main' | 'details';
  scroll: number;
  input: Input | null;
  status: { label: string; tick: number } | null;
  footnote: string | null;
}

export interface Size {
  cols: number;
  rows: number;
}

export interface Painted {
  lines: string[];
  cursor: { row: number; col: number } | null;
}

export const GUTTER = 5;
const MAX_WIDTH = 76;
const SPINNER = ['▀', '▬', '▄', '▬'];

export function emptyFrame(mode: string, app: App = 'setup', alert: string | null = null): Frame {
  return {
    app,
    mode,
    alert,
    step: null,
    section: null,
    page: null,
    blocks: [],
    details: [],
    view: 'main',
    scroll: 0,
    input: null,
    status: null,
    footnote: null,
  };
}

export function textWidth(cols: number): number {
  return Math.max(20, Math.min(MAX_WIDTH, cols - GUTTER - 2));
}

export const visible = (s: string): number => Array.from(stripStyle(s)).length;

const RESET = '\u001b[0m';
const ESC = '\u001b';

interface Piece {
  text: string;
  sgr: boolean;
}

function pieces(s: string): Piece[] {
  const out: Piece[] = [];
  let i = 0;
  while (i < s.length) {
    if (s[i] === ESC && s[i + 1] === '[') {
      let j = i + 2;
      while (j < s.length && !/[A-Za-z]/.test(s[j] as string)) j++;
      out.push({ text: s.slice(i, j + 1), sgr: true });
      i = j + 1;
      continue;
    }
    const ch = String.fromCodePoint(s.codePointAt(i) as number);
    out.push({ text: ch, sgr: false });
    i += ch.length;
  }
  return out;
}

export function wrap(line: string, width: number, hang = 0): string[] {
  if (visible(line) <= width) return [line];
  const ps = pieces(line);
  const lines: string[] = [];
  let open: string[] = [];
  let cur = '';
  let curWidth = 0;
  let lastSpace = -1;
  let lastSpaceWidth = 0;
  let openAtSpace: string[] = [];
  const limit = () => (lines.length === 0 ? width : width - hang);
  const flush = (text: string, rest: string, carried: string[]) => {
    lines.push(carried.length > 0 || text.includes(ESC) ? `${text}${RESET}` : text);
    cur = carried.join('') + rest;
    curWidth = visible(rest);
    lastSpace = -1;
  };
  for (const p of ps) {
    if (p.sgr) {
      cur += p.text;
      open = p.text === RESET || p.text === `${ESC}[m` ? [] : [...open, p.text];
      continue;
    }
    if (p.text === ' ') {
      lastSpace = cur.length;
      lastSpaceWidth = curWidth;
      openAtSpace = open;
    }
    cur += p.text;
    curWidth++;
    if (curWidth > limit()) {
      if (lastSpace > 0 && lastSpaceWidth > 0) {
        const head = cur.slice(0, lastSpace);
        const tail = cur.slice(lastSpace + 1);
        flush(head, tail, openAtSpace);
      } else {
        const head = cur.slice(0, -p.text.length);
        flush(head, p.text, open);
      }
    }
  }
  if (stripStyle(cur).trim() !== '' || lines.length === 0) lines.push(cur);
  const pad = ' '.repeat(hang);
  return lines.map((l, i) => (i === 0 ? l : pad + l));
}

function dedent(text: string): string[] {
  const lines = text.replace(/\n+$/, '').replace(/^\n+/, '').split('\n');
  const indents = lines
    .filter((l) => stripStyle(l).trim() !== '')
    .map((l) => (/^ */.exec(stripStyle(l)) as RegExpExecArray)[0].length);
  const cut = indents.length > 0 ? Math.min(...indents) : 0;
  return lines.map((l) => (l.startsWith(' '.repeat(cut)) ? l.slice(cut) : l));
}

const MARKS = ['✓', '✗', '!'];

function markOf(line: string): { mark: string; rest: string } | null {
  const plain = stripStyle(line);
  const m = MARKS.find((k) => plain.startsWith(`${k} `));
  if (!m) return null;
  return { mark: m, rest: line.slice(line.indexOf(m) + m.length + 1) };
}

function gutterMark(mark: string, st: TermStyle): string {
  if (mark === '✓') return `   ${st.ok('✓')} `;
  if (mark === '✗') return st.level === 0 ? '   ✗ ' : `  ${st.bad('✗')}`;
  if (mark === '›') return `   ${st.ok('›')} `;
  return `   ${st.bold(mark)} `;
}

const pad = (n: number) => ' '.repeat(Math.max(0, n));

function textLines(text: string, width: number, st: TermStyle): string[] {
  const out: string[] = [];
  for (const raw of dedent(text)) {
    if (stripStyle(raw).trim() === '') {
      out.push('');
      continue;
    }
    const m = markOf(raw);
    if (m) {
      const [first, ...rest] = wrap(m.rest, width, 0);
      out.push(gutterMark(m.mark, st) + first, ...rest.map((l) => pad(GUTTER) + l.trimStart()));
      continue;
    }
    const indent = (/^ */.exec(stripStyle(raw)) as RegExpExecArray)[0].length;
    for (const l of wrap(raw, width, indent)) out.push(pad(GUTTER) + l);
  }
  return out;
}

export const NO_ROOM_FOR_CODE =
  '! Make the window bigger or zoom out to see the code, or press Tab for the link.';

function figureArt(
  b: QrFigure | ArtFigure,
  st: TermStyle,
  drawing: QrDrawing,
): { art: string[]; width: number } {
  if ('art' in b) {
    const art = b.art.split('\n');
    return { art, width: Math.max(...art.map(visible)) };
  }
  return { art: drawQr(b.qr, drawing, st.level), width: qrExtent(b.qr, drawing).cols };
}

function figureLines(
  b: QrFigure | ArtFigure,
  cols: number,
  st: TermStyle,
  drawing: QrDrawing | null,
): string[] | null {
  if (drawing === null && 'qr' in b) {
    return textLines(`${NO_ROOM_FOR_CODE}\n\n${b.beside}`, textWidth(cols), st);
  }
  const { art, width: artWidth } = figureArt(b, st, drawing ?? 'cells');
  const indent = Math.min(GUTTER, cols - 1 - artWidth);
  if (indent < 0) return null;
  const sideCol = indent + artWidth + 3;
  const sideWidth = Math.min(40, cols - sideCol - 2);
  if (sideWidth < 22) {
    return [...art.map((l) => pad(indent) + l), '', ...textLines(b.beside, textWidth(cols), st)];
  }
  const side = dedent(b.beside).flatMap((l) => (l.trim() === '' ? [''] : wrap(l, sideWidth)));
  const top = 1;
  const rows = Math.max(art.length, side.length + top);
  const out: string[] = [];
  for (let i = 0; i < rows; i++) {
    const a = art[i] ?? '';
    const s = side[i - top] ?? '';
    out.push(pad(indent) + a + pad(sideCol - indent - visible(a)) + s);
  }
  return out;
}

const compact = (b: Block): boolean =>
  b.kind === 'answer' ||
  (b.kind === 'text' &&
    dedent(b.text).length === 1 &&
    markOf(dedent(b.text)[0] as string) !== null);

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, Math.max(0, n - 1))}…` : s);

function answerLine(b: { question: string; answer: string }, width: number, st: TermStyle) {
  const a = clip(b.answer, Math.floor(width / 2));
  const q = clip(b.question.replace(/ \(.*\)$/, ''), width - a.length - 2);
  return `   ${st.dim('·')} ${st.dim(q)}${a ? `  ${st.ok(a)}` : ''}`;
}

function spinner(status: { label: string; tick: number }, st: TermStyle): string {
  const f = SPINNER[status.tick % SPINNER.length] as string;
  return ` ${st.tile(f)} ${status.label}`;
}

interface Body {
  lines: string[];
  spacers: Set<number>;
  cursor: { row: number; col: number } | null;
  whole: boolean;
  keep: number | null;
}

function bodyLines(f: Frame, size: Size, st: TermStyle, drawing: QrDrawing | null): Body {
  const width = textWidth(size.cols);
  const lines: string[] = [];
  let whole = true;
  let keep: number | null = null;
  const spacers = new Set<number>();
  const space = () => {
    if (lines.length > 0) {
      spacers.add(lines.length);
      lines.push('');
    }
  };
  let prev: Block | null = null;
  const statusInFigure =
    f.status !== null && f.blocks.at(-1)?.kind === 'figure' && f.input === null;
  f.blocks.forEach((b, i) => {
    if (prev && !(compact(prev) && compact(b))) space();
    if (b.kind === 'text') lines.push(...textLines(b.text, width, st));
    else if (b.kind === 'answer') lines.push(answerLine(b, width, st));
    else {
      const last = i === f.blocks.length - 1;
      const beside =
        last && statusInFigure && f.status
          ? `${b.beside}\n\n${st.tile(SPINNER[f.status.tick % SPINNER.length] as string)} ${f.status.label}`
          : b.beside;
      if (drawing === null && 'qr' in b) keep ??= lines.length;
      const drawn = figureLines({ ...b, beside }, size.cols, st, drawing);
      if (drawn) lines.push(...drawn);
      else whole = false;
    }
    prev = b;
  });
  let cursor: Body['cursor'] = null;
  const input = f.input;
  if (input) {
    space();
    if (input.kind === 'continue') {
      lines.push(`${gutterMark('›', st)}${st.dim(input.label)}`);
    } else if (input.kind === 'line') {
      lines.push(
        ...wrap(
          `${pad(GUTTER)}${st.bold(input.label)}${input.hidden ? st.dim('  not shown') : ''}`,
          width + GUTTER,
          GUTTER,
        ),
      );
      const shown = input.hidden ? '' : input.value;
      const tail = shown.length > width - 1 ? `…${shown.slice(-(width - 2))}` : shown;
      cursor = { row: lines.length, col: GUTTER + Array.from(tail).length };
      lines.push(
        `${gutterMark('›', st)}${tail === '' && !input.hidden && input.hint ? st.dim(input.hint) : tail}`,
      );
    } else {
      lines.push(...wrap(`${pad(GUTTER)}${st.bold(input.label)}`, width + GUTTER, GUTTER));
      lines.push('');
      input.options.forEach((label, i) => {
        const n = `${i + 1}`;
        const chosen = i === input.selected;
        const wrapped = wrap(label, width - 4, 0);
        wrapped.forEach((l, j) => {
          const lead =
            j > 0
              ? pad(GUTTER + 4)
              : `${chosen ? gutterMark('›', st) : pad(GUTTER)}${chosen ? st.ok(n.padEnd(4)) : st.dim(n.padEnd(4))}`;
          lines.push(lead + (chosen ? st.ok(l.trimStart()) : l.trimStart()));
        });
      });
    }
  }
  if (f.status && !statusInFigure) {
    space();
    lines.push(spinner(f.status, st));
  }
  return { lines, spacers, cursor, whole, keep };
}

function barLine(f: Frame, size: Size, st: TermStyle): string {
  const w = textWidth(size.cols);
  if (f.step) {
    const done = Math.round((w * f.step.n) / STEP_COUNT);
    return `${pad(GUTTER)}${st.ok('━'.repeat(done))}${st.dim('─'.repeat(w - done))}`;
  }
  if (f.app !== 'console') return '';
  const s = f.section;
  if (!s) return `${pad(GUTTER)}${st.dim('─'.repeat(w))}`;
  const from = Math.round((w * (s.n - 1)) / s.of);
  const to = Math.round((w * s.n) / s.of);
  const lead = from > 0 ? st.dim('─'.repeat(from)) : '';
  return `${pad(GUTTER)}${lead}${st.ok('━'.repeat(to - from))}${st.dim('─'.repeat(w - to))}`;
}

function headerLine(f: Frame, size: Size, st: TermStyle): string {
  const left = f.alert
    ? ` ${st.header(f.app)}  ${st.bad(f.alert)}`
    : ` ${st.header(`${f.app} · ${f.mode}`)}`;
  const right = f.step ? st.dim(`STEP ${f.step.n} OF ${STEP_COUNT}`) : '';
  const gap = size.cols - 2 - visible(left) - visible(right);
  return gap >= 2 ? `${left}${pad(gap)}${right}` : left;
}

function titleLine(f: Frame, st: TermStyle): string {
  if (f.view === 'details')
    return `${pad(GUTTER)}${st.head('DETAILS')}${st.dim('  what this screen leaves out')}`;
  const title = (
    f.step?.title ??
    f.section?.title ??
    (f.app === 'console' ? 'Overview' : 'Setup')
  ).toUpperCase();
  return `${pad(GUTTER)}${st.head(title)}${f.page ? st.dim(`  ·  ${f.page.toUpperCase()}`) : ''}`;
}

function footerLine(f: Frame, st: TermStyle): string {
  const hints: string[] = [];
  if (f.view === 'details') {
    hints.push('↑↓ scroll', 'Tab back');
  } else {
    const i = f.input;
    if (i?.kind === 'menu') hints.push('↑↓ choose', 'Enter select');
    else if (i?.kind === 'line') hints.push('Enter confirm');
    else if (i?.kind === 'continue') hints.push('Enter continue');
    if (f.details.length > 0) hints.push('Tab details');
    if (i && f.app === 'console') hints.push(f.section ? 'Esc back' : 'Esc quit');
    else if (i) hints.push('Ctrl-C quit');
  }
  const note = f.footnote && f.view === 'main' ? `${pad(4)}${f.footnote}` : '';
  return `${pad(GUTTER)}${st.dim(hints.join('   ') + note)}`;
}

const BLOCK_INDENT = 3;

const LIST_START = /^(?:[•✓✗!+~$#>-]|\d+\)|\w+:\s|[A-Z][A-Z ]+\s{2})/;

export function reflow(lines: string[]): string[] {
  const out: string[] = [];
  const indentOf = (l: string) => (/^ */.exec(stripStyle(l)) as RegExpExecArray)[0].length;
  for (const l of lines) {
    const prev = out.at(-1);
    const body = stripStyle(l).trim();
    const joinable =
      prev !== undefined &&
      stripStyle(prev).trim() !== '' &&
      body !== '' &&
      !LIST_START.test(body) &&
      !/\S {2,}\S/.test(body) &&
      !/\S {2,}\S/.test(stripStyle(prev).trim()) &&
      !/[:.]$/.test(stripStyle(prev).trimEnd()) &&
      indentOf(l) <= indentOf(prev) + 2 &&
      indentOf(l) >= indentOf(prev) &&
      !(indentOf(l) >= BLOCK_INDENT && indentOf(prev) >= BLOCK_INDENT);
    if (joinable) out[out.length - 1] = `${prev} ${l.trim()}`;
    else out.push(l);
  }
  return out;
}

function detailLines(f: Frame, size: Size): string[] {
  const width = textWidth(size.cols);
  const lines: string[] = [];
  f.details.forEach((d, i) => {
    if (i > 0) lines.push('');
    for (const l of reflow(dedent(d))) {
      const indent = (/^ */.exec(stripStyle(l)) as RegExpExecArray)[0].length;
      for (const w of wrap(l, width, Math.min(indent + 2, 12))) lines.push(pad(GUTTER) + w);
    }
  });
  return lines;
}

export function maxScroll(f: Frame, size: Size): number {
  return Math.max(0, detailLines(f, size).length - Math.max(1, size.rows - 7));
}

const STAGES = [
  { top: 5, bottom: 2, spacers: true },
  { top: 5, bottom: 0, spacers: true },
  { top: 5, bottom: 0, spacers: false },
  { top: 2, bottom: 0, spacers: false },
  { top: 1, bottom: 0, spacers: false },
  { top: 0, bottom: 0, spacers: false },
] as const;

const shownLines = (body: Body, spacers: boolean) =>
  spacers ? body.lines.length : body.lines.length - body.spacers.size;

const stagesFor = (f: Frame) => (f.alert ? STAGES.filter((s) => s.top > 0) : STAGES);

const fitsWhole = (body: Body, rows: number, stages: readonly (typeof STAGES)[number][]) =>
  body.whole &&
  stages.some((stage) => stage.top + shownLines(body, stage.spacers) + stage.bottom <= rows);

function mainBody(f: Frame, size: Size, st: TermStyle): Body {
  if (f.blocks.some((b) => b.kind === 'figure' && 'qr' in b)) {
    const drawings: QrDrawing[] = st.drawsBlocks ? ['cells', 'half-blocks'] : ['cells'];
    for (const drawing of drawings) {
      const body = bodyLines(f, size, st, drawing);
      if (fitsWhole(body, size.rows, stagesFor(f))) return body;
    }
  }
  return bodyLines(f, size, st, null);
}

export function paint(f: Frame, size: Size, st: TermStyle): Painted {
  const chrome = [headerLine(f, size, st), barLine(f, size, st), '', titleLine(f, st), ''];
  const footer = ['', footerLine(f, st)];
  let body: Body;
  if (f.view === 'details') {
    const all = detailLines(f, size);
    const room = Math.max(1, size.rows - 7);
    const from = Math.min(f.scroll, Math.max(0, all.length - room));
    body = {
      lines: all.slice(from, from + room),
      spacers: new Set(),
      cursor: null,
      whole: true,
      keep: null,
    };
  } else {
    body = mainBody(f, size, st);
  }
  const stages = stagesFor(f);
  for (const stage of stages) {
    const lines = stage.spacers ? body.lines : body.lines.filter((_, i) => !body.spacers.has(i));
    const removedBefore = (row: number) =>
      stage.spacers ? 0 : [...body.spacers].filter((s) => s < row).length;
    if (stage.top + lines.length + stage.bottom > size.rows && stage !== stages.at(-1)) continue;
    const top =
      stage.top === 2 ? [chrome[0] as string, chrome[3] as string] : chrome.slice(0, stage.top);
    const room = size.rows - top.length - stage.bottom;
    const keepAt = body.keep === null ? lines.length : body.keep - removedBefore(body.keep);
    const cut = Math.min(Math.max(0, lines.length - room), keepAt);
    const shown = lines.slice(cut, cut + room);
    const out = [...top, ...shown];
    while (out.length < size.rows - stage.bottom) out.push('');
    if (stage.bottom > 0) out.push(...footer);
    const cursor = body.cursor
      ? {
          row: top.length + body.cursor.row - removedBefore(body.cursor.row) - cut,
          col: body.cursor.col,
        }
      : null;
    return {
      lines: out.slice(0, size.rows),
      cursor: cursor && cursor.row >= 0 && cursor.row < size.rows ? cursor : null,
    };
  }
  return { lines: [], cursor: null };
}

export function bodyText(f: Frame, size: Size, st: TermStyle): string {
  const blocks = f.blocks.map(
    (b): Block => (b.kind === 'figure' && 'qr' in b ? { kind: 'text', text: b.beside } : b),
  );
  const lines = mainBody({ ...f, blocks, input: null, status: null }, size, st).lines;
  return `${lines.join('\n')}\n`;
}

export type Key =
  | { kind: 'char'; ch: string }
  | {
      kind:
        | 'enter'
        | 'backspace'
        | 'clear'
        | 'tab'
        | 'up'
        | 'down'
        | 'pageup'
        | 'pagedown'
        | 'escape'
        | 'interrupt'
        | 'eof';
    };

const SEQUENCES: Record<string, Key['kind']> = {
  '[A': 'up',
  '[B': 'down',
  OA: 'up',
  OB: 'down',
  '[5~': 'pageup',
  '[6~': 'pagedown',
};

export class KeyDecoder {
  private partial = '';

  decode(chunk: string): Key[] {
    const s = this.partial + chunk;
    this.partial = '';
    const keys: Key[] = [];
    for (let i = 0; i < s.length; i++) {
      const ch = s[i] as string;
      if (ch === ESC) {
        const rest = s.slice(i + 1);
        if (rest[0] !== '[' && rest[0] !== 'O') {
          keys.push({ kind: 'escape' });
          continue;
        }
        let j = 1;
        while (j < rest.length && !/[A-Za-z~]/.test(rest[j] as string)) j++;
        if (j >= rest.length) {
          this.partial = s.slice(i);
          break;
        }
        const seq = rest.slice(0, j + 1);
        const kind = SEQUENCES[seq];
        if (kind) keys.push({ kind } as Key);
        i += seq.length;
        continue;
      }
      if (ch === '\r' || ch === '\n') {
        keys.push({ kind: 'enter' });
        if (ch === '\r' && s[i + 1] === '\n') i++;
        continue;
      }
      if (ch === '\u0003') keys.push({ kind: 'interrupt' });
      else if (ch === '\u0004') keys.push({ kind: 'eof' });
      else if (ch === '\u007f' || ch === '\b') keys.push({ kind: 'backspace' });
      else if (ch === '\u0015') keys.push({ kind: 'clear' });
      else if (ch === '\t') keys.push({ kind: 'tab' });
      else if (ch >= ' ') keys.push({ kind: 'char', ch });
    }
    return keys;
  }
}
