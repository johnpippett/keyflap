import { randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  renameSync,
  type Stats,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, normalize } from 'node:path';

export interface FileOwner {
  uid: number;
  gid: number;
}

export class UnsafePathError extends Error {}

const MAX_READ = 4 * 1024 * 1024;
const MAX_LINKS = 32;

export function asOwner<T>(owner: FileOwner, fn: () => T): T {
  const euid = process.geteuid?.();
  if (euid === undefined || euid === owner.uid) return fn();
  if (euid !== 0) {
    throw new UnsafePathError(`can't act for uid ${owner.uid} as uid ${euid}`);
  }
  const { setgroups, setegid, seteuid, getegid, getgroups } = process;
  if (!setgroups || !setegid || !seteuid || !getegid || !getgroups) {
    throw new UnsafePathError('this platform cannot switch to the user');
  }
  const egid = getegid();
  const groups = getgroups();
  try {
    setgroups([owner.gid]);
    setegid(owner.gid);
    seteuid(owner.uid);
    return fn();
  } finally {
    seteuid(0);
    setegid(egid);
    setgroups(groups);
  }
}

function rootOnly(st: Stats): boolean {
  return st.isDirectory() && st.uid === 0 && (st.mode & 0o022) === 0;
}

function errno(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException).code;
}

export function checkUserPath(path: string): void {
  if (!isAbsolute(path) || normalize(path) !== path || path.includes('\0') || path.endsWith('/')) {
    throw new UnsafePathError(`${path}: not a plain absolute path`);
  }
  let parts = path.split('/').filter(Boolean);
  let real = '/';
  let trusted = rootOnly(lstatSync('/'));
  let links = 0;
  while (parts.length > 0) {
    const name = parts.shift() as string;
    const next = join(real, name);
    let st: Stats;
    try {
      st = lstatSync(next);
    } catch (err) {
      if (errno(err) === 'ENOENT') return;
      throw err;
    }
    if (st.isSymbolicLink()) {
      if (parts.length === 0) throw new UnsafePathError(`${path} is a symbolic link`);
      if (!trusted) {
        throw new UnsafePathError(`${next} is a symbolic link in a directory you can change`);
      }
      if (++links > MAX_LINKS) throw new UnsafePathError(`${path}: too many symbolic links`);
      const target = readlinkSync(next);
      parts = [
        ...normalize(isAbsolute(target) ? target : join(real, target))
          .split('/')
          .filter(Boolean),
        ...parts,
      ];
      real = '/';
      trusted = rootOnly(lstatSync('/'));
      continue;
    }
    if (parts.length > 0 && !st.isDirectory()) {
      throw new UnsafePathError(`${next} is not a directory`);
    }
    if (parts.length > 0) trusted = trusted && rootOnly(st);
    real = next;
  }
}

function checkOpened(fd: number, path: string, owner: FileOwner): Stats {
  const st = fstatSync(fd);
  if (!st.isFile()) throw new UnsafePathError(`${path} is not a regular file`);
  if (st.uid !== owner.uid) {
    throw new UnsafePathError(`${path} is owned by uid ${st.uid}, not by you (uid ${owner.uid})`);
  }
  return st;
}

export function readUserFile(path: string, owner: FileOwner): string | null {
  return asOwner(owner, () => {
    checkUserPath(path);
    let fd: number;
    try {
      fd = openSync(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY,
      );
    } catch (err) {
      if (errno(err) === 'ENOENT') return null;
      if (errno(err) === 'ELOOP') throw new UnsafePathError(`${path} is a symbolic link`);
      throw err;
    }
    try {
      const st = checkOpened(fd, path, owner);
      if (st.size > MAX_READ) throw new UnsafePathError(`${path} is too large`);
      return readFileSync(fd, 'utf8');
    } finally {
      closeSync(fd);
    }
  });
}

export function userFileMode(path: string, owner: FileOwner): number | null {
  return asOwner(owner, () => {
    checkUserPath(path);
    try {
      const st = lstatSync(path);
      if (!st.isFile()) throw new UnsafePathError(`${path} is not a regular file`);
      return st.mode & 0o7777;
    } catch (err) {
      if (errno(err) === 'ENOENT') return null;
      throw err;
    }
  });
}

function writeAll(fd: number, data: string): void {
  const buf = Buffer.from(data, 'utf8');
  let off = 0;
  while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
}

const CREATE =
  constants.O_WRONLY |
  constants.O_CREAT |
  constants.O_EXCL |
  constants.O_NOFOLLOW |
  constants.O_NOCTTY;

export function writeUserFile(
  path: string,
  data: string,
  mode: number,
  owner: FileOwner,
  opts: { exclusive?: boolean } = {},
): void {
  asOwner(owner, () => {
    checkUserPath(path);
    const dir = dirname(path);
    const d = lstatSync(dir);
    if (!d.isDirectory()) throw new UnsafePathError(`${dir} is not a directory`);
    if (opts.exclusive) {
      const fd = openSync(path, CREATE, mode);
      try {
        checkOpened(fd, path, owner);
        fchmodSync(fd, mode);
        writeAll(fd, data);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      return;
    }
    try {
      const st = lstatSync(path);
      if (!st.isFile()) throw new UnsafePathError(`${path} is not a regular file`);
      if (st.uid !== owner.uid) {
        throw new UnsafePathError(
          `${path} is owned by uid ${st.uid}, not by you (uid ${owner.uid})`,
        );
      }
    } catch (err) {
      if (errno(err) !== 'ENOENT') throw err;
    }
    const tmp = join(dir, `.${basename(path)}.${randomBytes(8).toString('hex')}.keyflap-tmp`);
    const fd = openSync(tmp, CREATE, mode);
    let renamed = false;
    try {
      try {
        checkOpened(fd, tmp, owner);
        fchmodSync(fd, mode);
        writeAll(fd, data);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, path);
      renamed = true;
    } finally {
      if (!renamed) {
        try {
          unlinkSync(tmp);
        } catch {}
      }
    }
  });
}

export function mkdirUser(path: string, mode: number, owner: FileOwner): void {
  asOwner(owner, () => {
    checkUserPath(path);
    const missing: string[] = [];
    let p = path;
    for (;;) {
      try {
        const st = lstatSync(p);
        if (!st.isDirectory()) throw new UnsafePathError(`${p} is not a directory`);
        break;
      } catch (err) {
        if (errno(err) !== 'ENOENT') throw err;
        missing.push(p);
        const up = dirname(p);
        if (up === p) break;
        p = up;
      }
    }
    for (const m of missing.reverse()) {
      mkdirSync(m, { mode });
      const st = lstatSync(m);
      if (!st.isDirectory() || st.uid !== owner.uid) {
        throw new UnsafePathError(`${m} is not a directory of yours`);
      }
    }
  });
}
