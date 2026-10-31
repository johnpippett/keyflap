import type { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { emptyFrame } from '../src/setup/screen.ts';
import { ttyScreen } from '../src/setup/tty-screen.ts';

function fakeTty(cols: number, rows: number) {
  const out = new PassThrough() as PassThrough & { columns: number; rows: number; isTTY: true };
  out.columns = cols;
  out.rows = rows;
  out.isTTY = true;
  let written = '';
  out.on('data', (c: Buffer) => {
    written += c.toString('utf8');
  });
  const take = () => {
    const w = written;
    written = '';
    return w;
  };
  return { out, take };
}

describe('the full-screen terminal on resize', () => {
  it('clears the screen and repaints every line at the new size', async () => {
    const { out, take } = fakeTty(80, 24);
    const screen = ttyScreen(out, new PassThrough());
    const lines = ['one', 'two', 'three'];
    let redraws = 0;
    screen.enter(() => {
      redraws++;
      screen.draw({ lines, cursor: null }, emptyFrame('service mode'));
    });
    screen.draw({ lines, cursor: null }, emptyFrame('service mode'));
    await new Promise((r) => setImmediate(r));
    take();
    out.columns = 120;
    out.rows = 40;
    out.emit('resize');
    await new Promise((r) => setImmediate(r));
    const after = take();
    expect(redraws).toBe(1);
    expect(screen.size()).toEqual({ cols: 120, rows: 40 });
    expect(after).toContain('\u001b[2J');
    for (const l of lines) expect(after).toContain(l);
    screen.restore();
    expect((out as EventEmitter).listenerCount('resize')).toBe(0);
  });
});
