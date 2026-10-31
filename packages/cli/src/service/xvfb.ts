import { type ChildProcess, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export interface XvfbDisplay {
  env: { DISPLAY: string; XAUTHORITY: string };
  process: ChildProcess;
  stop(): Promise<void>;
}

export function xauthorityEntry(display: number, cookie: Buffer): Buffer {
  const field = (b: Buffer) => {
    const len = Buffer.alloc(2);
    len.writeUInt16BE(b.length);
    return Buffer.concat([len, b]);
  };
  const family = Buffer.alloc(2);
  family.writeUInt16BE(0xffff);
  return Buffer.concat([
    family,
    field(Buffer.alloc(0)),
    field(Buffer.from(String(display))),
    field(Buffer.from('MIT-MAGIC-COOKIE-1')),
    field(cookie),
  ]);
}

export async function startXvfb(opts: {
  bin: string;
  display: number;
  dir: string;
  log?: (line: string) => void;
  timeoutMs?: number;
}): Promise<XvfbDisplay> {
  if (!Number.isInteger(opts.display) || opts.display < 1 || opts.display > 999) {
    throw new Error('bad display number');
  }
  mkdirSync(opts.dir, { recursive: true, mode: 0o700 });
  chmodSync(opts.dir, 0o700);
  const auth = join(opts.dir, 'Xauthority');
  writeFileSync(auth, xauthorityEntry(opts.display, randomBytes(16)), { mode: 0o600 });
  chmodSync(auth, 0o600);
  const child = spawn(
    opts.bin,
    [
      `:${opts.display}`,
      '-nolisten',
      'tcp',
      '-nolisten',
      'local',
      '-auth',
      auth,
      '-screen',
      '0',
      '1366x900x24',
      '-nocursor',
    ],
    { stdio: ['ignore', 'ignore', 'pipe'], env: { PATH: process.env.PATH ?? '/usr/bin:/bin' } },
  );
  let stderr = '';
  child.stderr?.setEncoding('utf8');
  child.stderr?.on('data', (d: string) => {
    stderr = (stderr + d).slice(-2000);
  });
  const socket = `/tmp/.X11-unix/X${opts.display}`;
  const deadline = Date.now() + (opts.timeoutMs ?? 10_000);
  for (;;) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`Xvfb exited at start: ${stderr.trim().split('\n').slice(-3).join(' | ')}`);
    }
    try {
      if (lstatSync(socket).isSocket()) break;
    } catch {}
    if (Date.now() > deadline) {
      child.kill('SIGKILL');
      throw new Error('Xvfb did not come up');
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  child.on('exit', (code, signal) => opts.log?.(`Xvfb exited (${code ?? signal})`));
  return {
    env: { DISPLAY: `:${opts.display}`, XAUTHORITY: auth },
    process: child,
    async stop() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      await new Promise<void>((resolve) => {
        child.once('exit', () => resolve());
        child.kill('SIGTERM');
      });
    },
  };
}
