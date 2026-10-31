import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readlinkSync,
  readSync,
} from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';
import { rootOnlyProblem } from '@aab/sources';

export const LOCALAPI_DETAIL = {
  notRunning: 'Tailscale is not running',
  tokenUnreadable: "Tailscale's token cannot be read",
  tokenRefused: 'Tailscale refused the token',
  tooLarge: 'output too large',
} as const;

export type LocalApiRead =
  | { kind: 'body'; body: string }
  | { kind: 'untrusted'; detail: string }
  | { kind: 'failed'; detail: string };

export interface LocalApiOptions {
  checkOwners: boolean;
  timeoutMs: number;
  maxBytes: number;
}

const LOCALAPI_PATH = {
  serveConfig: '/localapi/v0/serve-config',
  status: '/localapi/v0/status?peers=false',
} as const;
const PORT_RE = /^[1-9][0-9]{0,4}$/;
const TOKEN_RE = /^[\x21-\x7e]{1,128}$/;
const TOKEN_READ_LIMIT = 256;

export function localApiDirProblem(dir: string): string | null {
  return rootOnlyProblem(dir, 'directory')?.detail ?? null;
}

const failed = (detail: string): LocalApiRead => ({ kind: 'failed', detail });

function localApiPort(dir: string, checkOwners: boolean): number | LocalApiRead {
  if (checkOwners) {
    const bad = localApiDirProblem(dir);
    if (bad !== null) return { kind: 'untrusted', detail: bad };
  }
  const link = join(dir, 'ipnport');
  let target: string;
  try {
    const st = lstatSync(link);
    if (!st.isSymbolicLink())
      return { kind: 'untrusted', detail: `${link} is not a symbolic link` };
    if (checkOwners && st.uid !== 0) {
      return {
        kind: 'untrusted',
        detail: `${link} is owned by uid ${st.uid}, not root: its owner can repoint it`,
      };
    }
    target = readlinkSync(link);
  } catch {
    return failed(LOCALAPI_DETAIL.notRunning);
  }
  const port = Number(target);
  if (!PORT_RE.test(target) || port > 65_535) {
    return { kind: 'untrusted', detail: `${link} does not name a port` };
  }
  return port;
}

function readToken(dir: string, port: number): string | LocalApiRead {
  let fd: number;
  try {
    fd = openSync(join(dir, `sameuserproof-${port}`), constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (err) {
    return failed(
      (err as NodeJS.ErrnoException).code === 'ENOENT'
        ? LOCALAPI_DETAIL.notRunning
        : LOCALAPI_DETAIL.tokenUnreadable,
    );
  }
  try {
    if (!fstatSync(fd).isFile()) return failed(LOCALAPI_DETAIL.tokenUnreadable);
    const buf = Buffer.alloc(TOKEN_READ_LIMIT);
    const n = readSync(fd, buf, 0, buf.length, 0);
    const token = buf.subarray(0, n).toString('latin1').trim();
    return TOKEN_RE.test(token) ? token : failed(LOCALAPI_DETAIL.tokenUnreadable);
  } catch {
    return failed(LOCALAPI_DETAIL.tokenUnreadable);
  } finally {
    closeSync(fd);
  }
}

function getLocalApi(
  port: number,
  token: string,
  path: string,
  o: LocalApiOptions,
): Promise<LocalApiRead> {
  return new Promise((resolve) => {
    let settled = false;
    const req = request({
      host: '127.0.0.1',
      port,
      path,
      method: 'GET',
      auth: `:${token}`,
      headers: { 'Sec-Tailscale': 'localapi' },
      agent: false,
    });
    const settle = (r: LocalApiRead) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.destroy();
      resolve(r);
    };
    const timer = setTimeout(() => settle(failed('tailscale timed out')), o.timeoutMs);
    req.on('error', (err: NodeJS.ErrnoException) =>
      settle(failed(err.code === 'ECONNREFUSED' ? LOCALAPI_DETAIL.notRunning : 'tailscale failed')),
    );
    req.on('response', (res) => {
      const status = res.statusCode ?? 0;
      if (status === 401 || status === 403) return settle(failed(LOCALAPI_DETAIL.tokenRefused));
      if (status !== 200) return settle(failed(`tailscale answered ${status}`));
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c: Buffer) => {
        size += c.length;
        if (size > o.maxBytes) return settle(failed(LOCALAPI_DETAIL.tooLarge));
        chunks.push(c);
      });
      res.on('end', () => settle({ kind: 'body', body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', () => settle(failed('tailscale failed')));
    });
    req.end();
  });
}

async function readLocalApi(dir: string, path: string, o: LocalApiOptions): Promise<LocalApiRead> {
  const port = localApiPort(dir, o.checkOwners);
  if (typeof port !== 'number') return port;
  const token = readToken(dir, port);
  if (typeof token !== 'string') return token;
  return getLocalApi(port, token, path, o);
}

export function readLocalApiServeConfig(dir: string, o: LocalApiOptions): Promise<LocalApiRead> {
  return readLocalApi(dir, LOCALAPI_PATH.serveConfig, o);
}

export function readLocalApiStatus(dir: string, o: LocalApiOptions): Promise<LocalApiRead> {
  return readLocalApi(dir, LOCALAPI_PATH.status, o);
}
