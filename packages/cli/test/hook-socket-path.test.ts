import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { maxUnixSocketPathBytes } from '@aab/signer/platform';
import { afterEach, describe, expect, it } from 'vitest';
import { type HookOptions, runHook } from '../src/hook-core.ts';
import { tmpDir } from './helpers.ts';

const TOKEN = 'A'.repeat(43);
const AGENT = '0b9d6c1e-2f4a-4c3b-9e8d-7a6b5c4d3e2f';
const parse = () => ({ prompt: 'sign in to the test RP' });

describe('the hook never sends the host token to a socket path the OS would shorten', () => {
  const cleanup: (() => void | Promise<void>)[] = [];
  afterEach(async () => {
    for (const c of cleanup.splice(0)) await c();
  });

  function options(dataDir: string, log: string[]): HookOptions {
    return {
      dataDir,
      agentId: AGENT,
      stdin: Readable.from([Buffer.from('{}')]),
      log: (line) => log.push(line),
    };
  }

  function dataDirWithToken(base: string): string {
    mkdirSync(base, { recursive: true, mode: 0o700 });
    writeFileSync(join(base, 'host-token'), `${TOKEN}\n`, { mode: 0o600 });
    cleanup.push(() => rmSync(base, { recursive: true, force: true }));
    return base;
  }

  it('a --data-dir whose run/intent.sock is too long is refused with the limit named', async () => {
    const root = tmpDir();
    const filler = 'd'.repeat(maxUnixSocketPathBytes());
    const dataDir = dataDirWithToken(join(root, filler));
    cleanup.push(() => rmSync(root, { recursive: true, force: true }));
    const log: string[] = [];
    expect(await runHook(options(dataDir, log), parse)).toBe('failed');
    expect(log).toHaveLength(1);
    expect(log[0]).toMatch(
      /^keyflap hook: intent not recorded: intent socket: .*limited to \d+ bytes/,
    );
    expect(log[0]).not.toMatch(/cannot reach/);
    expect(log[0]).not.toContain(TOKEN);
  });

  it('a path within the limit still reaches the intent socket', async () => {
    const dataDir = dataDirWithToken(tmpDir());
    mkdirSync(join(dataDir, 'run'), { mode: 0o700 });
    const seen: { auth: string | undefined; url: string | undefined }[] = [];
    const server: Server = createServer((req, res) => {
      seen.push({ auth: req.headers.authorization, url: req.url });
      req.resume();
      res.writeHead(201).end('{}');
    });
    await new Promise<void>((resolve) =>
      server.listen(join(dataDir, 'run', 'intent.sock'), resolve),
    );
    cleanup.push(() => new Promise((resolve) => server.close(() => resolve())));
    const log: string[] = [];
    expect(await runHook(options(dataDir, log), parse)).toBe('recorded');
    expect(log).toEqual([]);
    expect(seen).toEqual([{ auth: `Bearer ${TOKEN}`, url: '/v1/intents' }]);
  });
});
