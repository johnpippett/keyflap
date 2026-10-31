globalThis.AabZoom = (() => {
  const MIN = 1;
  const MAX = 4;
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const finite = (v) => typeof v === 'number' && Number.isFinite(v);

  function fit(v, W, H) {
    const s = clamp(finite(v.s) ? v.s : 1, MIN, MAX);
    const tx = clamp(finite(v.tx) ? v.tx : 0, W - s * W, 0);
    const ty = clamp(finite(v.ty) ? v.ty : 0, H - s * H, 0);
    return { s, tx, ty };
  }

  function zoomAt(v, factor, px, py, W, H) {
    const s = clamp(v.s * factor, MIN, MAX);
    const ux = (px - v.tx) / v.s;
    const uy = (py - v.ty) / v.s;
    return fit({ s, tx: px - ux * s, ty: py - uy * s }, W, H);
  }

  function panBy(v, dx, dy, W, H) {
    return fit({ s: v.s, tx: v.tx + dx, ty: v.ty + dy }, W, H);
  }

  function pinch(v0, a0, b0, a1, b1, W, H) {
    const d0 = Math.hypot(b0.x - a0.x, b0.y - a0.y);
    const d1 = Math.hypot(b1.x - a1.x, b1.y - a1.y);
    const s = clamp(d0 > 0 ? (v0.s * d1) / d0 : v0.s, MIN, MAX);
    const m0 = { x: (a0.x + b0.x) / 2, y: (a0.y + b0.y) / 2 };
    const m1 = { x: (a1.x + b1.x) / 2, y: (a1.y + b1.y) / 2 };
    const ux = (m0.x - v0.tx) / v0.s;
    const uy = (m0.y - v0.ty) / v0.s;
    return fit({ s, tx: m1.x - ux * s, ty: m1.y - uy * s }, W, H);
  }

  function toPage(v, px, py, W, H) {
    return {
      x: clamp((px - v.tx) / (v.s * W), 0, 1),
      y: clamp((py - v.ty) / (v.s * H), 0, 1),
    };
  }

  function visible(v, W, H) {
    const w = 1 / v.s;
    const h = 1 / v.s;
    return {
      x: clamp(-v.tx / (v.s * W), 0, 1 - w),
      y: clamp(-v.ty / (v.s * H), 0, 1 - h),
      w,
      h,
    };
  }

  function clipParam(r, margin) {
    const x0 = clamp(r.x - margin, 0, 1);
    const y0 = clamp(r.y - margin, 0, 1);
    const x1 = clamp(r.x + r.w + margin, 0, 1);
    const y1 = clamp(r.y + r.h + margin, 0, 1);
    const down = (n) => Math.floor(n * 1e4) / 1e4;
    const up = (n) => Math.min(1, Math.ceil(n * 1e4) / 1e4);
    const x = down(x0);
    const y = down(y0);
    const w = Math.min(up(x1 - x), 1 - x);
    const h = Math.min(up(y1 - y), 1 - y);
    const out = { x, y, w: Math.round(w * 1e4) / 1e4, h: Math.round(h * 1e4) / 1e4 };
    return { rect: out, param: `${out.x},${out.y},${out.w},${out.h}` };
  }

  return { MIN, MAX, fit, zoomAt, panBy, pinch, toPage, visible, clipParam };
})();
