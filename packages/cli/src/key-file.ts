import { randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  writeSync,
} from 'node:fs';
import { join } from 'node:path';

export const KEY_FILE_NAME = 'unlock.key';
export const KEY_FILE_BYTES = 32;

export class KeyFileError extends Error {}

export const keyFilePath = (dataDir: string) => join(dataDir, KEY_FILE_NAME);
const storePath = (dataDir: string) => join(dataDir, 'signer', 'keys.enc.json');

export function hasKeyFile(dataDir: string): boolean {
  try {
    lstatSync(keyFilePath(dataDir));
    return true;
  } catch {
    return false;
  }
}

export function readKeyFile(path: string, uid: number | undefined = process.getuid?.()): string {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new KeyFileError(
      code === 'ELOOP' ? `${path} is a symbolic link` : `cannot open ${path} (${code})`,
    );
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new KeyFileError(`${path} is not a regular file`);
    if (uid !== undefined && st.uid !== uid) {
      throw new KeyFileError(`${path} belongs to uid ${st.uid}, not to you`);
    }
    if ((st.mode & 0o077) !== 0) {
      throw new KeyFileError(
        `${path} is mode ${(st.mode & 0o777).toString(8)}: it must be 0600 (chmod 600 '${path}')`,
      );
    }
    if (st.size !== KEY_FILE_BYTES) {
      throw new KeyFileError(`${path} must hold exactly ${KEY_FILE_BYTES} bytes`);
    }
    const key = Buffer.alloc(KEY_FILE_BYTES);
    if (readSync(fd, key, 0, KEY_FILE_BYTES, 0) !== KEY_FILE_BYTES) {
      throw new KeyFileError(`${path} is shorter than ${KEY_FILE_BYTES} bytes`);
    }
    const passphrase = key.toString('base64url');
    key.fill(0);
    return passphrase;
  } finally {
    closeSync(fd);
  }
}

export function createKeyFile(dataDir: string): string {
  if (existsSync(storePath(dataDir))) {
    throw new KeyFileError(
      `${dataDir} already has a key store, made with a passphrase (keyflap daemon --unprotected), ` +
        `and no ${KEY_FILE_NAME}. Move it away first (mv '${dataDir}' '${dataDir}.dev'), or use it with its passphrase.`,
    );
  }
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const path = keyFilePath(dataDir);
  const fd = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  const key = randomBytes(KEY_FILE_BYTES);
  try {
    writeSync(fd, key);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
    key.fill(0);
  }
  return readKeyFile(path);
}

export function unlockFromKeyFile(dataDir: string, o: { create: boolean }): string | null {
  if (hasKeyFile(dataDir)) return readKeyFile(keyFilePath(dataDir));
  return o.create ? createKeyFile(dataDir) : null;
}
