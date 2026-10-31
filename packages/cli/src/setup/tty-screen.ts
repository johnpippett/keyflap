import type { Readable, Writable } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
import type { Frame, Key, Painted } from './screen.ts';
import { KeyDecoder } from './screen.ts';
import type { Keys, Screen } from './ui.ts';

const CSI = '\u001b[';
const ENTER_ALT = `${CSI}?1049h${CSI}?25l${CSI}H${CSI}2J`;
const LEAVE_ALT = `${CSI}0m${CSI}?25h${CSI}?1049l`;

export interface TtyOut extends Writable {
  isTTY?: boolean;
  columns?: number;
  rows?: number;
}

export interface TtyIn extends Readable {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => unknown;
}

export function ttyScreen(stdout: TtyOut, stdin: TtyIn): Screen {
  let prev: string[] = [];
  let entered = false;
  let redraw = () => {};
  const onResize = () => {
    prev = [];
    stdout.write(`${CSI}2J`);
    redraw();
  };
  const onExit = () => {
    if (entered) stdout.write(LEAVE_ALT);
    stdin.setRawMode?.(false);
  };
  const onSigint = () => {
    if (process.listenerCount('SIGINT') > 1) return;
    screen.restore();
    process.kill(process.pid, 'SIGINT');
  };
  const screen: Screen = {
    size: () => ({ cols: stdout.columns || 80, rows: stdout.rows || 24 }),
    enter(repaint) {
      redraw = repaint;
      entered = true;
      stdout.write(ENTER_ALT);
      stdout.on('resize', onResize);
      process.on('exit', onExit);
      process.on('SIGINT', onSigint);
    },
    draw(p: Painted, _f: Frame) {
      let s = `${CSI}?25l`;
      p.lines.forEach((line, i) => {
        if (prev[i] !== line) s += `${CSI}${i + 1};1H${line}${CSI}0m${CSI}K`;
      });
      if (prev.length > p.lines.length) s += `${CSI}${p.lines.length + 1};1H${CSI}J`;
      prev = p.lines;
      if (p.cursor) s += `${CSI}${p.cursor.row + 1};${p.cursor.col + 1}H${CSI}?25h`;
      stdout.write(s);
    },
    restore() {
      if (!entered) return;
      entered = false;
      stdin.setRawMode?.(false);
      stdout.write(LEAVE_ALT);
      stdout.off('resize', onResize);
      process.off('exit', onExit);
      process.off('SIGINT', onSigint);
    },
  };
  return screen;
}

export function ttyKeys(stdin: TtyIn): Keys {
  const decoder = new KeyDecoder();
  const text = new StringDecoder('utf8');
  const queue: Key[] = [];
  let waiter: ((k: Key) => void) | null = null;
  let started = false;
  const onData = (chunk: Buffer | string) => {
    const keys = decoder.decode(typeof chunk === 'string' ? chunk : text.write(chunk));
    for (const k of keys) {
      if (k.kind === 'interrupt' && !waiter) {
        process.kill(process.pid, 'SIGINT');
        continue;
      }
      if (waiter) {
        const w = waiter;
        waiter = null;
        w(k);
      } else {
        queue.push(k);
      }
    }
  };
  const start = () => {
    if (started) return;
    started = true;
    stdin.setRawMode?.(true);
    stdin.on('data', onData);
    stdin.resume();
  };
  return {
    open: start,
    next() {
      start();
      const k = queue.shift();
      if (k) return Promise.resolve(k);
      return new Promise((resolve) => {
        waiter = resolve;
      });
    },
    flush() {
      queue.length = 0;
    },
    close() {
      if (!started) return;
      started = false;
      stdin.off('data', onData);
      stdin.setRawMode?.(false);
      stdin.pause();
    },
  };
}
