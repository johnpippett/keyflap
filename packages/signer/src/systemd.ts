import { lstatSync, readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

export const SD_LISTEN_FDS_START = 3;
const MAX_LISTEN_FDS = 64;
const CREDENTIAL_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;

export function listenFds(
  env: NodeJS.ProcessEnv = process.env,
  pid: number = process.pid,
): Map<string, number> {
  const out = new Map<string, number>();
  if (env.LISTEN_PID === undefined && env.LISTEN_FDS === undefined) return out;
  if (env.LISTEN_PID !== String(pid)) return out;
  const count = env.LISTEN_FDS ?? '';
  if (!/^[1-9][0-9]?$/.test(count) || Number(count) > MAX_LISTEN_FDS) {
    throw new Error('bad LISTEN_FDS');
  }
  const n = Number(count);
  const names = env.LISTEN_FDNAMES === undefined ? [] : env.LISTEN_FDNAMES.split(':');
  if (names.length !== n) throw new Error('LISTEN_FDNAMES does not match LISTEN_FDS');
  for (let i = 0; i < n; i++) {
    const name = names[i] as string;
    if (!CREDENTIAL_NAME.test(name)) throw new Error('bad LISTEN_FDNAMES entry');
    if (out.has(name)) throw new Error(`socket name "${name}" passed twice`);
    out.set(name, SD_LISTEN_FDS_START + i);
  }
  return out;
}

export function clearListenEnv(env: NodeJS.ProcessEnv = process.env): void {
  delete env.LISTEN_PID;
  delete env.LISTEN_FDS;
  delete env.LISTEN_FDNAMES;
}

export class CredentialError extends Error {}

export function credentialPrivate(st: { mode: number; uid: number; gid: number }): boolean {
  if ((st.mode & 0o007) !== 0 || (st.mode & 0o020) !== 0) return false;
  if ((st.mode & 0o070) === 0) return true;
  return st.uid === 0 && st.gid === 0;
}

export function readCredential(
  name: string,
  opts: { env?: NodeJS.ProcessEnv; maxBytes?: number; optional?: boolean } = {},
): Buffer | null {
  const env = opts.env ?? process.env;
  if (!CREDENTIAL_NAME.test(name)) throw new CredentialError(`bad credential name "${name}"`);
  const dir = env.CREDENTIALS_DIRECTORY;
  if (!dir || !isAbsolute(dir)) {
    if (opts.optional) return null;
    throw new CredentialError(
      `no $CREDENTIALS_DIRECTORY: credential "${name}" must come from the unit's LoadCredentialEncrypted=`,
    );
  }
  const path = join(dir, name);
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT' && opts.optional) return null;
    throw new CredentialError(
      `credential "${name}" unreadable (${(err as NodeJS.ErrnoException).code ?? 'error'})`,
    );
  }
  if (!st.isFile()) throw new CredentialError(`credential "${name}" is not a regular file`);
  if (!credentialPrivate(st)) {
    throw new CredentialError(`credential "${name}" is accessible to other users`);
  }
  const max = opts.maxBytes ?? 64 * 1024;
  if (st.size > max) throw new CredentialError(`credential "${name}" is too large`);
  return readFileSync(path);
}

export function readProvisionedFile(path: string, maxBytes = 256 * 1024): string {
  if (!isAbsolute(path)) throw new Error('config path must be absolute');
  const st = lstatSync(path);
  if (!st.isFile()) throw new Error(`${path} is not a regular file`);
  const self = typeof process.getuid === 'function' ? process.getuid() : -1;
  if (st.uid !== 0 && st.uid !== self) throw new Error(`${path} must be owned by root`);
  if ((st.mode & 0o022) !== 0) throw new Error(`${path} is writable by group or others`);
  if (st.size > maxBytes) throw new Error(`${path} is too large`);
  return readFileSync(path, 'utf8');
}
