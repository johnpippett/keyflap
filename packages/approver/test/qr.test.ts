import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { encodeQr, QR_MAX_BYTES } from '../src/qr.ts';
import { drawQr, NO_ROOM_FOR_PRINTED_CODE, renderQrTerminal } from '../src/qr-draw.ts';
import { stripStyle } from '../src/term-style.ts';

const url = `https://broker.tail1234.ts.net:8766/pair#${'A'.repeat(43)}`;

function finderOk(m: boolean[][], x0: number, y0: number): boolean {
  for (let y = 0; y < 7; y++) {
    for (let x = 0; x < 7; x++) {
      const ring = Math.max(Math.abs(x - 3), Math.abs(y - 3));
      if ((m[y0 + y] as boolean[])[x0 + x] !== (ring !== 2)) return false;
    }
  }
  return true;
}

describe('QR encoder', () => {
  it('picks the smallest version and draws the fixed patterns', () => {
    expect(encodeQr('hi').size).toBe(21);
    const q = encodeQr(url);
    expect(q.size).toBe(37);
    const n = q.size;
    expect(finderOk(q.modules, 0, 0)).toBe(true);
    expect(finderOk(q.modules, n - 7, 0)).toBe(true);
    expect(finderOk(q.modules, 0, n - 7)).toBe(true);
    for (let i = 8; i < n - 8; i++) {
      expect((q.modules[6] as boolean[])[i]).toBe(i % 2 === 0);
      expect((q.modules[i] as boolean[])[6]).toBe(i % 2 === 0);
    }
    expect((q.modules[n - 8] as boolean[])[8]).toBe(true);
  });

  it('is deterministic (known output for a fixed link and mask)', () => {
    const q = encodeQr(url, { mask: 3 });
    const bits = q.modules.map((r) => r.map((d) => (d ? '1' : '0')).join('')).join('\n');
    expect(createHash('sha256').update(bits).digest('hex')).toBe(
      '734207d28c73a3c2cf814d4c7638fae0519e3d3eb557975028c5ef68085197b6',
    );
    expect(encodeQr(url)).toEqual(encodeQr(url));
  });

  it('refuses text beyond version 10', () => {
    expect(encodeQr('x'.repeat(QR_MAX_BYTES)).size).toBe(57);
    expect(() => encodeQr('x'.repeat(QR_MAX_BYTES + 1))).toThrow();
  });

  it('prints full cells, two spaces a module, when the terminal is wide enough, with a 4-module quiet zone', () => {
    const q = encodeQr('hi');
    const n = q.size + 8;
    const out = renderQrTerminal(
      q,
      { isTTY: true, columns: 2 * n + 1 },
      { TERM: 'xterm-256color' },
    );
    const lines = out.split('\n');
    expect(lines).toHaveLength(n);
    expect(lines.every((l) => stripStyle(l) === ' '.repeat(2 * n))).toBe(true);
    expect(lines[0]).toBe(`\x1b[48;5;231m${' '.repeat(2 * n)}\x1b[0m`);
    expect(out).toContain('\x1b[48;5;16m');
  });

  it('prints full cells when the width is unknown, as when the output is not a terminal', () => {
    const q = encodeQr('hi');
    const n = q.size + 8;
    const lines = renderQrTerminal(q, {}, { TERM: 'xterm-256color' }).split('\n');
    expect(lines).toHaveLength(n);
    expect(lines.every((l) => stripStyle(l) === ' '.repeat(2 * n))).toBe(true);
  });

  it('falls back to half blocks, two module rows a line, only on a terminal known to draw them', () => {
    const q = encodeQr('hi');
    const n = q.size + 8;
    const narrow = { isTTY: true, columns: 2 * n };
    const lines = renderQrTerminal(q, narrow, { TERM: 'xterm-ghostty' }).split('\n');
    expect(lines).toHaveLength(Math.ceil(n / 2));
    expect(lines.every((l) => stripStyle(l) === '▀'.repeat(n))).toBe(true);
    for (const env of [
      { TERM: 'xterm-256color', TERM_PROGRAM: 'Apple_Terminal' },
      { TERM: 'xterm-256color' },
    ]) {
      expect(renderQrTerminal(q, narrow, env)).toBe(NO_ROOM_FOR_PRINTED_CODE);
    }
  });

  it('prints a line instead of a wrapped code when even half blocks do not fit', () => {
    const q = encodeQr('hi');
    const n = q.size + 8;
    const out = renderQrTerminal(q, { isTTY: true, columns: n }, { TERM: 'xterm-ghostty' });
    expect(out).toBe(NO_ROOM_FOR_PRINTED_CODE);
  });

  it('uses pure black and white where the terminal has 256 or 24-bit colour', () => {
    const q = encodeQr('hi');
    const at = (level: 1 | 2 | 3) => drawQr(q, 'cells', level).join('');
    expect(at(3)).toContain('48;2;0;0;0m');
    expect(at(3)).toContain('48;2;255;255;255m');
    expect(at(2)).toContain('48;5;16m');
    expect(at(2)).toContain('48;5;231m');
    expect(at(1)).toContain('40m');
    expect(at(1)).toContain('107m');
  });
});
