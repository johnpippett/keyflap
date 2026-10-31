import type { QrCode } from './qr.ts';
import { type ColorLevel, colorLevel, drawsBlockElements } from './term-style.ts';

const QR_QUIET_ZONE = 4;

export type QrDrawing = 'cells' | 'half-blocks';

interface Ink {
  fg: string;
  bg: string;
}

function inks(level: ColorLevel): { dark: Ink; light: Ink } {
  if (level === 3) {
    return {
      dark: { fg: '38;2;0;0;0', bg: '48;2;0;0;0' },
      light: { fg: '38;2;255;255;255', bg: '48;2;255;255;255' },
    };
  }
  if (level === 2) {
    return { dark: { fg: '38;5;16', bg: '48;5;16' }, light: { fg: '38;5;231', bg: '48;5;231' } };
  }
  return { dark: { fg: '30', bg: '40' }, light: { fg: '97', bg: '107' } };
}

export function qrExtent(q: QrCode, drawing: QrDrawing): { cols: number; rows: number } {
  const n = q.size + QR_QUIET_ZONE * 2;
  return drawing === 'cells' ? { cols: n * 2, rows: n } : { cols: n, rows: Math.ceil(n / 2) };
}

export function drawQr(q: QrCode, drawing: QrDrawing, level: ColorLevel): string[] {
  const n = q.size + QR_QUIET_ZONE * 2;
  const dark = (x: number, y: number) => {
    const qx = x - QR_QUIET_ZONE;
    const qy = y - QR_QUIET_ZONE;
    return qy >= 0 && qy < q.size && (q.modules[qy] as boolean[])[qx] === true;
  };
  const ink = inks(level);
  const of = (d: boolean) => (d ? ink.dark : ink.light);
  const line = (cell: (x: number) => { sgr: string; text: string }) => {
    let out = '';
    let open = '';
    for (let x = 0; x < n; x++) {
      const c = cell(x);
      if (c.sgr !== open) out += `\x1b[${c.sgr}m`;
      open = c.sgr;
      out += c.text;
    }
    return `${out}\x1b[0m`;
  };
  const lines: string[] = [];
  if (drawing === 'cells') {
    for (let y = 0; y < n; y++) lines.push(line((x) => ({ sgr: of(dark(x, y)).bg, text: '  ' })));
    return lines;
  }
  for (let y = 0; y < n; y += 2) {
    lines.push(
      line((x) => ({
        sgr: `${of(dark(x, y)).fg};${of(y + 1 < n && dark(x, y + 1)).bg}`,
        text: '▀',
      })),
    );
  }
  return lines;
}

export const NO_ROOM_FOR_PRINTED_CODE =
  '! Make the window wider or zoom out and run this again to see the code, or open the link on your phone.';

export function renderQrTerminal(
  q: QrCode,
  out: { columns?: number; isTTY?: boolean } = {},
  env: Record<string, string | undefined> = process.env,
): string {
  const level = colorLevel(out, env);
  const columns = out.columns;
  if (columns === undefined) return drawQr(q, 'cells', level).join('\n');
  const fits = (drawing: QrDrawing) => qrExtent(q, drawing).cols < columns;
  if (fits('cells')) return drawQr(q, 'cells', level).join('\n');
  if (drawsBlockElements(env) && fits('half-blocks')) {
    return drawQr(q, 'half-blocks', level).join('\n');
  }
  return NO_ROOM_FOR_PRINTED_CODE;
}
