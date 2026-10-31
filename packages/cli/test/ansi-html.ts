const PALETTE16 = [
  '#000000',
  '#cd0000',
  '#00cd00',
  '#cdcd00',
  '#0000ee',
  '#cd00cd',
  '#00cdcd',
  '#e5e5e5',
  '#7f7f7f',
  '#ff0000',
  '#00ff00',
  '#ffff00',
  '#5c5cff',
  '#ff00ff',
  '#00ffff',
  '#ffffff',
];

export const TERMINAL_FG = '#d4d7de';
export const TERMINAL_BG = '#0a0b0f';

const hex2 = (n: number) => n.toString(16).padStart(2, '0');
const rgb = (r: number, g: number, b: number) => `#${hex2(r)}${hex2(g)}${hex2(b)}`;

function color256(n: number): string {
  if (n < 16) return PALETTE16[n] as string;
  if (n >= 232) {
    const v = 8 + (n - 232) * 10;
    return rgb(v, v, v);
  }
  const i = n - 16;
  const level = (c: number) => (c === 0 ? 0 : 55 + c * 40);
  return rgb(level(Math.floor(i / 36)), level(Math.floor(i / 6) % 6), level(i % 6));
}

interface Pen {
  fg: string | null;
  bg: string | null;
  bold: boolean;
  dim: boolean;
  reverse: boolean;
}

const plainPen = (): Pen => ({ fg: null, bg: null, bold: false, dim: false, reverse: false });

function applySgr(pen: Pen, params: number[]): void {
  const p = params.length === 0 ? [0] : params;
  for (let i = 0; i < p.length; i++) {
    const c = p[i] as number;
    if (c === 0) Object.assign(pen, plainPen());
    else if (c === 1) pen.bold = true;
    else if (c === 2) pen.dim = true;
    else if (c === 22) {
      pen.bold = false;
      pen.dim = false;
    } else if (c === 7) pen.reverse = true;
    else if (c === 27) pen.reverse = false;
    else if (c >= 30 && c <= 37) pen.fg = PALETTE16[c - 30] as string;
    else if (c >= 90 && c <= 97) pen.fg = PALETTE16[c - 90 + 8] as string;
    else if (c === 39) pen.fg = null;
    else if (c >= 40 && c <= 47) pen.bg = PALETTE16[c - 40] as string;
    else if (c >= 100 && c <= 107) pen.bg = PALETTE16[c - 100 + 8] as string;
    else if (c === 49) pen.bg = null;
    else if (c === 38 || c === 48) {
      const mode = p[i + 1];
      let value: string | null = null;
      if (mode === 5) {
        value = color256(p[i + 2] as number);
        i += 2;
      } else if (mode === 2) {
        value = rgb(p[i + 2] as number, p[i + 3] as number, p[i + 4] as number);
        i += 4;
      }
      if (c === 38) pen.fg = value;
      else pen.bg = value;
    }
  }
}

interface Cell {
  ch: string;
  pen: Pen;
}

function cells(line: string): Cell[] {
  const out: Cell[] = [];
  const pen = plainPen();
  let i = 0;
  while (i < line.length) {
    if (line.charCodeAt(i) === 27 && line[i + 1] === '[') {
      let j = i + 2;
      while (j < line.length && !/[A-Za-z]/.test(line[j] as string)) j++;
      if (line[j] === 'm') {
        const body = line.slice(i + 2, j);
        applySgr(pen, body === '' ? [] : body.split(';').map(Number));
      }
      i = j + 1;
      continue;
    }
    const ch = String.fromCodePoint(line.codePointAt(i) as number);
    out.push({ ch, pen: { ...pen } });
    i += ch.length;
  }
  return out;
}

const escapeHtml = (s: string) =>
  s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

function style(pen: Pen, ch: string): string {
  let fg = pen.fg ?? TERMINAL_FG;
  let bg = pen.bg;
  if (pen.reverse) {
    const f = fg;
    fg = bg ?? TERMINAL_BG;
    bg = f;
  }
  const parts: string[] = [];
  if (ch === '▀' || ch === '▄') {
    const top = ch === '▀' ? fg : (bg ?? TERMINAL_BG);
    const bottom = ch === '▀' ? (bg ?? TERMINAL_BG) : fg;
    parts.push(`background:linear-gradient(${top} 50%,${bottom} 50%)`);
  } else {
    if (fg !== TERMINAL_FG) parts.push(`color:${fg}`);
    if (bg) parts.push(`background:${bg}`);
  }
  if (pen.bold) parts.push('font-weight:700');
  if (pen.dim) parts.push('opacity:.58');
  return parts.join(';');
}

export interface Screenshot {
  lines: string[];
  cols: number;
  rows: number;
  cursor: { row: number; col: number } | null;
}

export function screenHtml(s: Screenshot): string {
  const rows: string[] = [];
  for (let r = 0; r < s.rows; r++) {
    const cs = cells(s.lines[r] ?? '');
    while (cs.length < s.cols) cs.push({ ch: ' ', pen: plainPen() });
    if (s.cursor && s.cursor.row === r) {
      const at = cs[s.cursor.col];
      if (at) at.pen = { ...at.pen, reverse: !at.pen.reverse };
    }
    let html = '';
    let run = '';
    let runStyle = '';
    const flush = () => {
      if (run === '') return;
      html += runStyle ? `<span style="${runStyle}">${escapeHtml(run)}</span>` : escapeHtml(run);
      run = '';
    };
    for (const c of cs.slice(0, s.cols)) {
      const st = style(c.pen, c.ch);
      const ch = c.ch === '▀' || c.ch === '▄' ? ' ' : c.ch;
      if (st !== runStyle) {
        flush();
        runStyle = st;
      }
      run += ch;
    }
    flush();
    rows.push(`<div class="r">${html}</div>`);
  }
  return `<div class="term" style="--cols:${s.cols}">${rows.join('')}</div>`;
}

export const TERMINAL_CSS = `
.term{font-family:Menlo,"SF Mono",ui-monospace,Consolas,"DejaVu Sans Mono",monospace;
  font-size:var(--fs,13px);line-height:1.2;background:${TERMINAL_BG};color:${TERMINAL_FG};
  padding:10px 12px;border-radius:8px;width:calc(var(--cols) * 1ch);box-sizing:content-box;
  overflow:hidden;border:1px solid #2c303b}
.term .r{height:1.2em;white-space:pre}
.term .r span{display:inline-block;height:1.2em;vertical-align:top}
`;

export function screenPage(title: string, s: Screenshot): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><style>body{margin:0;padding:16px;background:#14161d}${TERMINAL_CSS}</style></head><body>${screenHtml(s)}</body></html>\n`;
}
