import { readFileSync } from 'node:fs';
import { createContext, runInContext } from 'node:vm';
import { describe, expect, it } from 'vitest';

interface View {
  s: number;
  tx: number;
  ty: number;
}
interface Pt {
  x: number;
  y: number;
}
interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}
interface AabZoom {
  MIN: number;
  MAX: number;
  fit(v: View, W: number, H: number): View;
  zoomAt(v: View, factor: number, px: number, py: number, W: number, H: number): View;
  panBy(v: View, dx: number, dy: number, W: number, H: number): View;
  pinch(v0: View, a0: Pt, b0: Pt, a1: Pt, b1: Pt, W: number, H: number): View;
  toPage(v: View, px: number, py: number, W: number, H: number): Pt;
  visible(v: View, W: number, H: number): Rect;
  clipParam(r: Rect, margin: number): { rect: Rect; param: string };
}

function load(): AabZoom {
  const src = readFileSync(new URL('../src/page/handoff-zoom.js', import.meta.url), 'utf8');
  const ctx = createContext({ Math, Number });
  runInContext(src, ctx);
  return (ctx as unknown as { AabZoom: AabZoom }).AabZoom;
}

const Z = load();
const W = 344;
const H = 193.5;
const onScreen = (v: View, p: Pt) => ({ x: v.tx + v.s * p.x * W, y: v.ty + v.s * p.y * H });
const close = (a: Pt, b: Pt) => {
  expect(a.x).toBeCloseTo(b.x, 9);
  expect(a.y).toBeCloseTo(b.y, 9);
};

describe('live view zoom: a tap maps to the page point under the finger', () => {
  it('unzoomed, the box is the page', () => {
    const v = { s: 1, tx: 0, ty: 0 };
    close(Z.toPage(v, 0, 0, W, H), { x: 0, y: 0 });
    close(Z.toPage(v, W / 2, H / 4, W, H), { x: 0.5, y: 0.25 });
    close(Z.toPage(v, W, H, W, H), { x: 1, y: 1 });
  });

  it('round trip at any zoom and pan: drawn at p, tapped there, is p', () => {
    const page: Pt[] = [
      { x: 0.1, y: 0.2 },
      { x: 0.5, y: 0.5 },
      { x: 0.83, y: 0.07 },
    ];
    for (const s of [1, 1.5, 2.25, 3, 4]) {
      for (const [fx, fy] of [
        [0, 0],
        [0.3, 0.7],
        [1, 1],
      ] as const) {
        const v = Z.fit({ s, tx: -fx * (s - 1) * W, ty: -fy * (s - 1) * H }, W, H);
        for (const p of page) {
          const at = onScreen(v, p);
          if (at.x < 0 || at.x > W || at.y < 0 || at.y > H) continue;
          close(Z.toPage(v, at.x, at.y, W, H), p);
        }
      }
    }
  });

  it('zooming with + keeps the centre on the same page point; pan keeps the mapping', () => {
    let v = { s: 1, tx: 0, ty: 0 };
    const centre = Z.toPage(v, W / 2, H / 2, W, H);
    v = Z.zoomAt(v, 1.5, W / 2, H / 2, W, H);
    v = Z.zoomAt(v, 1.5, W / 2, H / 2, W, H);
    expect(v.s).toBeCloseTo(2.25, 9);
    close(Z.toPage(v, W / 2, H / 2, W, H), centre);
    const right = Z.toPage(v, W / 2 + 40, H / 2, W, H);
    v = Z.panBy(v, -40, 0, W, H);
    close(Z.toPage(v, W / 2, H / 2, W, H), right);
  });

  it('pinch: the page point between the fingers follows their midpoint', () => {
    const v0 = { s: 1, tx: 0, ty: 0 };
    const a0 = { x: 60, y: 50 };
    const b0 = { x: 100, y: 70 };
    const mid0 = Z.toPage(v0, 80, 60, W, H);
    const a1 = { x: 50, y: 45 };
    const b1 = { x: 130, y: 85 };
    const v = Z.pinch(v0, a0, b0, a1, b1, W, H);
    expect(v.s).toBeCloseTo(2, 9);
    close(Z.toPage(v, 90, 65, W, H), mid0);
    const pan = Z.pinch(v, a1, b1, { x: 40, y: 45 }, { x: 120, y: 85 }, W, H);
    expect(pan.s).toBeCloseTo(2, 9);
    expect(pan.tx).toBeCloseTo(v.tx - 10, 9);
  });

  it('never outside the page: zoom 1..4, no empty edge, taps clamped to 0..1', () => {
    expect(Z.fit({ s: 0.2, tx: 50, ty: 50 }, W, H)).toEqual({ s: 1, tx: 0, ty: 0 });
    const big = Z.fit({ s: 9, tx: -1e6, ty: 1e6 }, W, H);
    expect(big).toEqual({ s: 4, tx: W - 4 * W, ty: 0 });
    expect(Z.fit({ s: Number.NaN, tx: Number.NaN, ty: 0 }, W, H)).toEqual({ s: 1, tx: 0, ty: 0 });
    const p = { x: 100, y: 100 };
    const q = { x: 200, y: 100 };
    expect(Z.pinch({ s: 1, tx: 0, ty: 0 }, p, q, p, { x: 110, y: 100 }, W, H).s).toBe(1);
    expect(Z.pinch({ s: 3, tx: 0, ty: 0 }, p, q, p, { x: 900, y: 100 }, W, H).s).toBe(4);
    const v = Z.fit({ s: 2, tx: -W / 2, ty: -H / 2 }, W, H);
    for (const [px, py] of [
      [-500, -500],
      [W + 500, H + 500],
      [-1, H / 2],
    ] as const) {
      const t = Z.toPage(v, px, py, W, H);
      expect(t.x >= 0 && t.x <= 1 && t.y >= 0 && t.y <= 1).toBe(true);
    }
  });

  it('the sharp region covers what is on screen, inside the page, in the server’s format', () => {
    const v = Z.fit({ s: 3, tx: -W, ty: -H * 0.4 }, W, H);
    const r = Z.visible(v, W, H);
    expect(r.w).toBeCloseTo(1 / 3, 9);
    const { rect, param } = Z.clipParam(r, 0.05);
    expect(rect.x).toBeLessThanOrEqual(r.x);
    expect(rect.y).toBeLessThanOrEqual(r.y);
    expect(rect.x + rect.w).toBeGreaterThanOrEqual(r.x + r.w);
    expect(rect.y + rect.h).toBeGreaterThanOrEqual(r.y + r.h);
    expect(rect.x + rect.w).toBeLessThanOrEqual(1);
    expect(param).toMatch(/^(?:[01](?:\.\d{1,4})?,){3}[01](?:\.\d{1,4})?$/);
    const corner = Z.clipParam(Z.visible(Z.fit({ s: 4, tx: -1e6, ty: -1e6 }, W, H), W, H), 0.05);
    expect(corner.rect.x + corner.rect.w).toBeCloseTo(1, 9);
    expect(corner.rect.y + corner.rect.h).toBeCloseTo(1, 9);
  });
});
