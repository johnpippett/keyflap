import { spawnSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { listenUnix } from '../src/unix-socket.ts';

describe('listenUnix fails closed on a path it cannot prove is a dead socket', () => {
  let dir: string;
  let path: string;
  let server: Server;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'keyflap-us-'));
    path = join(dir, 'run', 'x.sock');
    server = createServer();
  });
  afterEach(() => {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('a regular file at the path is refused and left untouched', async () => {
    mkdirSync(join(dir, 'run'));
    writeFileSync(path, 'precious');
    await expect(listenUnix(server, path, 'test socket')).rejects.toThrow(
      /test socket: socket path exists and is not a socket/,
    );
    expect(server.listening).toBe(false);
    expect(readFileSync(path, 'utf8')).toBe('precious');
  });

  it('a directory at the path is refused and left in place', async () => {
    mkdirSync(path, { recursive: true });
    await expect(listenUnix(server, path, 'test socket')).rejects.toThrow(/not a socket/);
    expect(lstatSync(path).isDirectory()).toBe(true);
  });

  it('a symlink at the path is refused, not followed or replaced', async () => {
    mkdirSync(join(dir, 'run'));
    const target = join(dir, 'elsewhere');
    writeFileSync(target, 'precious');
    symlinkSync(target, path);
    await expect(listenUnix(server, path, 'test socket')).rejects.toThrow(/not a socket/);
    expect(readlinkSync(path)).toBe(target);
    expect(readFileSync(target, 'utf8')).toBe('precious');
  });

  it('a socket something is listening on is refused and keeps working', async () => {
    const holder = createServer();
    await listenUnix(holder, path, 'holder');
    try {
      await expect(listenUnix(server, path, 'test socket')).rejects.toThrow(
        /test socket: something is already listening on/,
      );
      expect(server.listening).toBe(false);
      expect(holder.listening).toBe(true);
    } finally {
      holder.close();
    }
  });

  it('control: a dead socket file left by a killed process is replaced, mode 0600, in a 0700 dir', async () => {
    mkdirSync(join(dir, 'run'));
    spawnSync(process.execPath, [
      '-e',
      `require('node:net').createServer().listen(${JSON.stringify(path)}, () => process.kill(process.pid, 'SIGKILL'))`,
    ]);
    expect(existsSync(path)).toBe(true);
    expect(lstatSync(path).isSocket()).toBe(true);
    await listenUnix(server, path, 'test socket');
    expect(server.listening).toBe(true);
    expect(lstatSync(path).mode & 0o777).toBe(0o600);
    expect(lstatSync(join(dir, 'run')).mode & 0o777).toBe(0o700);
  });
});
