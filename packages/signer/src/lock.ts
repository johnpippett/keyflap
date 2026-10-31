import { randomBytes } from 'node:crypto';
import { linkSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';

export class LockHeldError extends Error {}

export interface FileLock {
  path: string;
  release(): void;
}

export function acquireLock(path: string): FileLock {
  const mine = `${process.pid}\n`;
  if (!tryLink(path, mine)) {
    const holder = readHolder(path);
    if (holder !== null && isAlive(holder)) {
      throw new LockHeldError(`key store is locked by a live process (pid ${holder})`);
    }
    try {
      unlinkSync(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    if (!tryLink(path, mine)) throw new LockHeldError('key store lock was taken concurrently');
  }
  let released = false;
  return {
    path,
    release() {
      if (released) return;
      released = true;
      try {
        if (readFileSync(path, 'utf8') === mine) unlinkSync(path);
      } catch {}
    },
  };
}

function tryLink(path: string, content: string): boolean {
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  writeFileSync(tmp, content, { mode: 0o600, flag: 'wx' });
  try {
    linkSync(tmp, path);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw err;
  } finally {
    unlinkSync(tmp);
  }
}

function readHolder(path: string): number | null {
  try {
    const text = readFileSync(path, 'utf8').trim();
    if (!/^[1-9][0-9]{0,9}$/.test(text)) return null;
    return Number(text);
  } catch {
    return null;
  }
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}
