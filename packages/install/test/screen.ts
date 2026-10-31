export interface Pen {
  fg: string | null;
  bg: string | null;
  bold: boolean;
  dim: boolean;
  inverse: boolean;
}

interface Cell {
  ch: string;
  pen: Pen;
}

const ESC = String.fromCharCode(27);
const CSI = new RegExp(`^${ESC}\\[([?0-9;]*)([A-Za-z])`);

const PLAIN: Pen = { fg: null, bg: null, bold: false, dim: false, inverse: false };

const CUBE = [0, 95, 135, 175, 215, 255];
const BASIC = [
  '#000000',
  '#cd3131',
  '#0dbc79',
  '#e5e510',
  '#2472c8',
  '#bc3fbc',
  '#11a8cd',
  '#e5e5e5',
  '#666666',
  '#f14c4c',
  '#23d18b',
  '#f5f543',
  '#3b8eea',
  '#d670d6',
  '#29b8db',
  '#ffffff',
];

const hex = (r: number, g: number, b: number) =>
  `#${[r, g, b].map((v) => v.toString(16).padStart(2, '0')).join('')}`;

function color256(n: number): string {
  if (n < 16) return BASIC[n] as string;
  if (n >= 232) {
    const v = 8 + (n - 232) * 10;
    return hex(v, v, v);
  }
  const i = n - 16;
  return hex(
    CUBE[Math.floor(i / 36)] as number,
    CUBE[Math.floor(i / 6) % 6] as number,
    CUBE[i % 6] as number,
  );
}

export class Screen {
  private lines: Cell[][] = [[]];
  private row = 0;
  private col = 0;
  private pen: Pen = { ...PLAIN };
  private pending = '';
  cursorVisible = true;

  write(data: string): void {
    const s = this.pending + data;
    this.pending = '';
    let i = 0;
    while (i < s.length) {
      const c = s[i] as string;
      if (c === ESC) {
        const m = CSI.exec(s.slice(i));
        if (!m) {
          if (s.length - i < 32) this.pending = s.slice(i);
          break;
        }
        this.csi(m[1] as string, m[2] as string);
        i += m[0].length;
        continue;
      }
      if (c === '\r') this.col = 0;
      else if (c === '\n') this.down();
      else if (c >= ' ') {
        const ch = String.fromCodePoint(s.codePointAt(i) as number);
        this.put(ch);
        i += ch.length;
        continue;
      }
      i++;
    }
  }

  private line(): Cell[] {
    while (this.lines.length <= this.row) this.lines.push([]);
    return this.lines[this.row] as Cell[];
  }

  private down(): void {
    this.row++;
    this.line();
  }

  private put(ch: string): void {
    const l = this.line();
    while (l.length < this.col) l.push({ ch: ' ', pen: { ...PLAIN } });
    l[this.col] = { ch, pen: { ...this.pen } };
    this.col++;
  }

  private csi(params: string, cmd: string): void {
    const n = Number.parseInt(params, 10);
    if (cmd === 'A') this.row = Math.max(0, this.row - (Number.isNaN(n) ? 1 : n));
    else if (cmd === 'K') {
      const l = this.line();
      if (params === '2') l.length = 0;
      else l.length = Math.min(l.length, this.col);
    } else if (cmd === 'h' && params === '?25') this.cursorVisible = true;
    else if (cmd === 'l' && params === '?25') this.cursorVisible = false;
    else if (cmd === 'm') this.sgr(params === '' ? [0] : params.split(';').map(Number));
  }

  private sgr(p: number[]): void {
    for (let i = 0; i < p.length; i++) {
      const v = p[i] as number;
      if (v === 0) this.pen = { ...PLAIN };
      else if (v === 1) this.pen.bold = true;
      else if (v === 2) this.pen.dim = true;
      else if (v === 22) {
        this.pen.bold = false;
        this.pen.dim = false;
      } else if (v === 7) this.pen.inverse = true;
      else if (v === 27) this.pen.inverse = false;
      else if (v === 39) this.pen.fg = null;
      else if (v === 49) this.pen.bg = null;
      else if (v >= 30 && v <= 37) this.pen.fg = BASIC[v - 30] as string;
      else if (v >= 90 && v <= 97) this.pen.fg = BASIC[v - 82] as string;
      else if (v >= 40 && v <= 47) this.pen.bg = BASIC[v - 40] as string;
      else if (v === 38 || v === 48) {
        const key = v === 38 ? 'fg' : 'bg';
        if (p[i + 1] === 5) {
          this.pen[key] = color256(p[i + 2] as number);
          i += 2;
        } else if (p[i + 1] === 2) {
          this.pen[key] = hex(p[i + 2] as number, p[i + 3] as number, p[i + 4] as number);
          i += 4;
        }
      }
    }
  }

  text(): string {
    return this.lines
      .map((l) =>
        l
          .map((c) => c.ch)
          .join('')
          .trimEnd(),
      )
      .join('\n')
      .replace(/\n+$/, '');
  }

  html(colors: { fg: string; bg: string }): string {
    const esc = (s: string) => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;');
    const style = (p: Pen) => {
      let fg = p.fg ?? colors.fg;
      let bg = p.bg;
      if (p.inverse) [fg, bg] = [bg ?? colors.bg, fg];
      const css = [`color:${fg}`];
      if (bg) css.push(`background:${bg}`);
      if (p.bold) css.push('font-weight:700');
      if (p.dim) css.push('opacity:.55');
      return css.join(';');
    };
    return this.lines
      .map((l) => {
        let out = '';
        let run = '';
        let cur = '';
        for (const c of l) {
          const s = style(c.pen);
          if (s !== cur && run) {
            out += `<span style="${cur}">${esc(run)}</span>`;
            run = '';
          }
          cur = s;
          run += c.ch;
        }
        if (run) out += `<span style="${cur}">${esc(run)}</span>`;
        return out;
      })
      .join('\n');
  }
}

export function render(out: string): Screen {
  const s = new Screen();
  s.write(out);
  return s;
}
