import { spawn } from 'node:child_process';
import {
  accessSync,
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fchownSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect, type LookupFunction } from 'node:net';
import { delimiter, join } from 'node:path';
import { unixSocketPathProblem } from '@aab/signer/platform';
import { checkTool, type ToolCheck, type ToolSpec } from '@aab/sources';
import {
  type FileOwner,
  mkdirUser,
  readUserFile,
  userFileMode,
  writeUserFile,
} from './user-files.ts';

export type { FileOwner } from './user-files.ts';

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
  error?: string;
}

export interface ExecOptions {
  env?: Record<string, string | undefined>;
  cleanEnv?: boolean;
  input?: string;
  cwd?: string;
  timeoutMs?: number;
  uid?: number;
  gid?: number;
}

export interface FileStat {
  uid: number;
  gid: number;
  mode: number;
  isFile: boolean;
  isDirectory: boolean;
  isSocket: boolean;
}

export interface HttpProbe {
  status: number | null;
  error?: string;
  tlsError?: boolean;
}

export interface RootFiles {
  writeRootFile(
    path: string,
    data: string,
    o: { mode: number; owner?: { uid: number; gid: number } },
  ): void;
  promoteRootFile(tmp: string, path: string, mode: number): void;
  removeRootFile(path: string): void;
  mkdirRoot(path: string, mode: number): void;
}

export interface System extends RootFiles {
  exec(cmd: string, args: string[], opts?: ExecOptions): Promise<ExecResult>;
  which(cmd: string): string | null;
  readFile(path: string): string | null;
  readUserFile(path: string, owner: FileOwner): string | null;
  userFileMode(path: string, owner: FileOwner): number | null;
  writeUserFile(
    path: string,
    data: string,
    mode: number,
    owner: FileOwner,
    opts?: { exclusive?: boolean },
  ): void;
  mkdirUser(path: string, mode: number, owner: FileOwner): void;
  exists(path: string): boolean;
  stat(path: string): FileStat | null;
  checkTool(path: string, spec: ToolSpec, pin?: string): ToolCheck;
  http(url: string, opts?: { method?: string; timeoutMs?: number }): Promise<HttpProbe>;
  connectUnix(path: string, timeoutMs?: number): Promise<boolean>;
  sleep(ms: number): Promise<void>;
  now(): number;
  env: NodeJS.ProcessEnv;
  platform: string;
  uid: number;
  gid: number;
  cwd: string;
}

const loopbackLookup = ((_host: string, opts: unknown, cb: (...a: unknown[]) => void) => {
  if ((opts as { all?: boolean }).all) cb(null, [{ address: '127.0.0.1', family: 4 }]);
  else cb(null, '127.0.0.1', 4);
}) as unknown as LookupFunction;

const TLS_CODES =
  /CERT|SELF_SIGNED|UNABLE_TO_VERIFY|UNABLE_TO_GET_ISSUER|ALTNAME|ERR_TLS|EPROTO|SSL/;

function writeRootFile(
  path: string,
  data: string,
  o: { mode: number; owner?: { uid: number; gid: number } },
): void {
  const tmp = `${path}.tmp-${process.pid}`;
  rmSync(tmp, { force: true });
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    if (o.owner) fchownSync(fd, o.owner.uid, o.owner.gid);
    fchmodSync(fd, o.mode);
    writeSync(fd, data);
  } catch (err) {
    closeSync(fd);
    rmSync(tmp, { force: true });
    throw err;
  }
  closeSync(fd);
  renameSync(tmp, path);
}

export function realSystem(): System {
  const env = process.env;
  return {
    writeRootFile,
    promoteRootFile(tmp, path, mode) {
      chmodSync(tmp, mode);
      renameSync(tmp, path);
    },
    removeRootFile: (path) => rmSync(path, { force: true }),
    mkdirRoot: (path, mode) => {
      mkdirSync(path, { recursive: true, mode });
    },
    exec(cmd, args, opts = {}) {
      return new Promise((resolve) => {
        const merged: Record<string, string> = {};
        for (const [k, v] of Object.entries(opts.cleanEnv ? {} : env)) {
          if (v !== undefined) merged[k] = v;
        }
        for (const [k, v] of Object.entries(opts.env ?? {})) {
          if (v === undefined) delete merged[k];
          else merged[k] = v;
        }
        let child: ReturnType<typeof spawn>;
        try {
          child = spawn(cmd, args, {
            env: merged,
            stdio: ['pipe', 'pipe', 'pipe'],
            ...(opts.cwd ? { cwd: opts.cwd } : {}),
            ...(opts.uid !== undefined ? { uid: opts.uid } : {}),
            ...(opts.gid !== undefined ? { gid: opts.gid } : {}),
          });
        } catch (err) {
          resolve({ code: null, stdout: '', stderr: '', error: (err as Error).message });
          return;
        }
        const out: Buffer[] = [];
        const errb: Buffer[] = [];
        let error: string | undefined;
        const timer = opts.timeoutMs
          ? setTimeout(() => {
              error = 'timed out';
              child.kill('SIGKILL');
            }, opts.timeoutMs)
          : null;
        child.stdout?.on('data', (c: Buffer) => out.push(c));
        child.stderr?.on('data', (c: Buffer) => errb.push(c));
        child.stdin?.on('error', () => {});
        child.on('error', (err) => {
          error = (err as NodeJS.ErrnoException).code ?? err.message;
        });
        child.on('close', (code) => {
          if (timer) clearTimeout(timer);
          resolve({
            code: error ? null : code,
            stdout: Buffer.concat(out).toString('utf8'),
            stderr: Buffer.concat(errb).toString('utf8'),
            ...(error ? { error } : {}),
          });
        });
        child.stdin?.end(opts.input ?? '');
      });
    },
    which(cmd) {
      if (cmd.includes('/')) return existsSync(cmd) ? cmd : null;
      for (const dir of (env.PATH ?? '').split(delimiter)) {
        if (!dir) continue;
        const p = join(dir, cmd);
        try {
          accessSync(p, constants.X_OK);
          if (statSync(p).isFile()) return p;
        } catch {}
      }
      return null;
    },
    readFile(path) {
      try {
        return readFileSync(path, 'utf8');
      } catch {
        return null;
      }
    },
    readUserFile,
    userFileMode,
    checkTool: (path, spec, pin) => checkTool(path, spec, pin),
    writeUserFile,
    mkdirUser,
    exists: (path) => existsSync(path),
    stat(path) {
      try {
        const s = statSync(path);
        return {
          uid: s.uid,
          gid: s.gid,
          mode: s.mode & 0o7777,
          isFile: s.isFile(),
          isDirectory: s.isDirectory(),
          isSocket: s.isSocket(),
        };
      } catch {
        return null;
      }
    },
    http(url, opts = {}) {
      return new Promise((resolve) => {
        let u: URL;
        try {
          u = new URL(url);
        } catch {
          resolve({ status: null, error: 'not a URL' });
          return;
        }
        const local = u.hostname === 'localhost' || u.hostname.endsWith('.localhost');
        const req = (u.protocol === 'https:' ? httpsRequest : httpRequest)(
          u,
          {
            method: opts.method ?? 'GET',
            timeout: opts.timeoutMs ?? 5_000,
            ...(local
              ? {
                  lookup: loopbackLookup,
                }
              : {}),
          },
          (res) => {
            res.resume();
            resolve({ status: res.statusCode ?? null });
          },
        );
        req.on('timeout', () => req.destroy(new Error('timed out')));
        req.on('error', (err) => {
          const code = (err as NodeJS.ErrnoException).code ?? '';
          resolve({
            status: null,
            error: code || err.message,
            ...(TLS_CODES.test(code) ? { tlsError: true } : {}),
          });
        });
        req.end();
      });
    },
    connectUnix(path, timeoutMs = 2_000) {
      return new Promise((resolve) => {
        if (unixSocketPathProblem(path, 'socket')) {
          resolve(false);
          return;
        }
        const s = connect(path);
        const done = (ok: boolean) => {
          clearTimeout(t);
          s.destroy();
          resolve(ok);
        };
        const t = setTimeout(() => done(false), timeoutMs);
        s.once('connect', () => done(true));
        s.once('error', () => done(false));
      });
    },
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    now: () => Date.now(),
    env,
    platform: process.platform,
    uid: process.geteuid?.() ?? -1,
    gid: process.getegid?.() ?? -1,
    cwd: process.cwd(),
  };
}
