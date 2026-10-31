import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { serveConfig } from '@aab/sources/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { AddressState } from '../src/approver-address.ts';
import { SignerDenied, type SpawnedSigner, spawnSigner } from '../src/client.ts';
import {
  LOCALAPI_DETAIL,
  type LocalApiOptions,
  readLocalApiServeConfig,
  readLocalApiStatus,
} from '../src/tailscale-localapi.ts';
import { type FakeLocalApi, fakeLocalApi } from './fake-localapi.ts';
import { clientData, statement, testApprover, tmpDir } from './helpers.ts';

const HOST = 'mac.tail1234.ts.net';
const PORT = 8766;
const TARGET = 'http://127.0.0.1:8766';
const ORIGIN = `https://${HOST}:${PORT}`;
const CORRECT = serveConfig({ host: HOST, port: PORT, target: TARGET });
const WRONG = serveConfig({ host: HOST, port: PORT, target: 'http://127.0.0.1:9999' });
const SAME_USER: LocalApiOptions = { checkOwners: false, timeoutMs: 400, maxBytes: 1024 * 1024 };
const SYSTEM: LocalApiOptions = { ...SAME_USER, checkOwners: true };
const isRoot = process.getuid?.() === 0;

const fakes: FakeLocalApi[] = [];
const signers: SpawnedSigner[] = [];
afterEach(async () => {
  for (const s of signers.splice(0)) await s.stop();
  for (const f of fakes.splice(0)) await f.close();
});

async function fake(config: unknown = CORRECT): Promise<FakeLocalApi> {
  const f = await fakeLocalApi(config);
  fakes.push(f);
  return f;
}

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

describe('invariant 5 (the approval address): the signer reads the serve setting from tailscaled over loopback', () => {
  it('sends the token as basic auth with the LocalAPI header, and returns the serve config', async () => {
    const f = await fake();
    expect(await readLocalApiServeConfig(f.dir, SAME_USER)).toEqual({
      kind: 'body',
      body: JSON.stringify(CORRECT),
    });
    expect(f.requests()).toEqual([
      {
        method: 'GET',
        path: '/localapi/v0/serve-config',
        authorization: `Basic ${Buffer.from(`:${f.token}`).toString('base64')}`,
        secTailscale: 'localapi',
      },
    ]);
  });

  it('reads the status the same way, without the peer list', async () => {
    const f = await fake();
    const status = { BackendState: 'NoState', TailscaleIPs: null, Self: { InNetworkMap: false } };
    f.status(status);
    expect(await readLocalApiStatus(f.dir, SAME_USER)).toEqual({
      kind: 'body',
      body: JSON.stringify(status),
    });
    expect(f.requests()).toEqual([
      {
        method: 'GET',
        path: '/localapi/v0/status?peers=false',
        authorization: `Basic ${Buffer.from(`:${f.token}`).toString('base64')}`,
        secTailscale: 'localapi',
      },
    ]);
  });

  it('a token tailscaled refuses is unreadable, never a pass', async () => {
    const f = await fake();
    writeFileSync(join(f.dir, `sameuserproof-${f.port}`), 'someone-elses-token');
    expect(await readLocalApiServeConfig(f.dir, SAME_USER)).toEqual({
      kind: 'failed',
      detail: LOCALAPI_DETAIL.tokenRefused,
    });
  });

  it('no port file means Tailscale is not running', async () => {
    const f = await fake();
    rmSync(join(f.dir, 'ipnport'));
    expect(await readLocalApiServeConfig(f.dir, SAME_USER)).toEqual({
      kind: 'failed',
      detail: LOCALAPI_DETAIL.notRunning,
    });
  });

  it('nothing listening on the port, or no token for it, means Tailscale is not running', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'keyflap-localapi-down-'));
    const port = await freePort();
    symlinkSync(String(port), join(dir, 'ipnport'));
    expect(await readLocalApiServeConfig(dir, SAME_USER)).toEqual({
      kind: 'failed',
      detail: LOCALAPI_DETAIL.notRunning,
    });
    writeFileSync(join(dir, `sameuserproof-${port}`), 'token-for-a-closed-port');
    expect(await readLocalApiServeConfig(dir, SAME_USER)).toEqual({
      kind: 'failed',
      detail: LOCALAPI_DETAIL.notRunning,
    });
  });

  it.skipIf(isRoot)(
    'a token the signer may not read says so, which the installer fixes',
    async () => {
      const f = await fake();
      chmodSync(join(f.dir, `sameuserproof-${f.port}`), 0o000);
      expect(await readLocalApiServeConfig(f.dir, SAME_USER)).toEqual({
        kind: 'failed',
        detail: LOCALAPI_DETAIL.tokenUnreadable,
      });
      expect(f.requests()).toHaveLength(0);
    },
  );

  it('an empty or multi-line token file is unreadable and is never sent', async () => {
    const f = await fake();
    const proof = join(f.dir, `sameuserproof-${f.port}`);
    for (const text of ['', '\n', 'a b', 'line\ninjected: 1']) {
      writeFileSync(proof, text);
      expect(await readLocalApiServeConfig(f.dir, SAME_USER)).toEqual({
        kind: 'failed',
        detail: LOCALAPI_DETAIL.tokenUnreadable,
      });
    }
    expect(f.requests()).toHaveLength(0);
  });

  it('a port file that is not a symbolic link to a port number is refused', async () => {
    const f = await fake();
    const link = join(f.dir, 'ipnport');
    rmSync(link);
    writeFileSync(link, String(f.port));
    expect(await readLocalApiServeConfig(f.dir, SAME_USER)).toEqual({
      kind: 'untrusted',
      detail: `${link} is not a symbolic link`,
    });
    for (const target of ['../etc/passwd', '0', '65536', '08766']) {
      rmSync(link);
      symlinkSync(target, link);
      expect(await readLocalApiServeConfig(f.dir, SAME_USER)).toEqual({
        kind: 'untrusted',
        detail: `${link} does not name a port`,
      });
    }
    expect(f.requests()).toHaveLength(0);
  });

  it.skipIf(isRoot)(
    'in service mode a port file someone other than root can repoint is refused before anything is read',
    async () => {
      const f = await fake();
      const r = await readLocalApiServeConfig(f.dir, SYSTEM);
      expect(r).toMatchObject({ kind: 'untrusted' });
      expect(r.kind === 'untrusted' ? r.detail : '').toMatch(
        /is owned by uid \d+, not root|writable by every user/,
      );
      expect(f.requests()).toHaveLength(0);
      expect(await readLocalApiServeConfig('Library/Tailscale', SYSTEM)).toEqual({
        kind: 'untrusted',
        detail: 'Library/Tailscale: not an absolute path',
      });
    },
  );

  it('a hang, an error answer and an oversized answer are unreadable', async () => {
    const f = await fake();
    const cases: ['hang' | 'error' | 'huge', string][] = [
      ['hang', 'tailscale timed out'],
      ['error', 'tailscale answered 500'],
      ['huge', 'output too large'],
    ];
    for (const [mode, detail] of cases) {
      f.set(mode);
      expect(await readLocalApiServeConfig(f.dir, SAME_USER)).toEqual({ kind: 'failed', detail });
    }
  });
});

describe('invariant 5 (the approval address): a signer reading through the LocalAPI trips and pauses like one running the CLI', () => {
  const terminal = testApprover('terminal');
  const QUICK = { idle: 150, fast: 50, timeout: 400 };

  async function start(f: { dir: string }) {
    const dir = tmpDir();
    const logs: string[] = [];
    const signer = await spawnSigner({
      socketPath: join(dir, 'run', 's.sock'),
      storePath: join(dir, 'keys'),
      passphrase: 'pw',
      trustedApproverKeys: terminal.trusted,
      approverAddress: {
        origin: ORIGIN,
        target: TARGET,
        tailscale: { via: 'localapi', dir: f.dir },
        pollMs: QUICK,
      },
      onLog: (line) => logs.push(line),
    });
    signers.push(signer);
    return { signer, logs };
  }

  const state = async (s: SpawnedSigner): Promise<AddressState> =>
    (await s.client.approverAddress({ pending: false })).state;

  async function waitKind(s: SpawnedSigner, kind: AddressState['kind']): Promise<AddressState> {
    const until = Date.now() + 6_000;
    for (;;) {
      const now = await state(s);
      if (now.kind === kind) return now;
      if (Date.now() > until) throw new Error(`still ${JSON.stringify(now)}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  async function create(s: SpawnedSigner): Promise<string> {
    const cd = clientData('webauthn.create', 'https://example.com');
    const st = statement({
      kind: 'webauthn.create',
      rpId: 'example.com',
      verifiedOrigin: 'https://example.com',
      clientDataJSON: cd,
    });
    try {
      await s.client.createCredential({
        rpId: 'example.com',
        userHandle: 'dXNlcg',
        clientDataJSON: cd,
        approval: terminal.sign(st),
      });
      return 'ok';
    } catch (err) {
      return err instanceof SignerDenied ? err.message : `other: ${(err as Error).message}`;
    }
  }

  it('a serve setting over the size cap latches; each check asks for the status first, then the setting once', async () => {
    const f = await fake();
    const { signer } = await start(f);
    expect(await state(signer)).toMatchObject({ kind: 'ok' });
    f.serve({ Web: { x: 'a'.repeat(1_100_000) } });
    expect(await waitKind(signer, 'latched')).toMatchObject({
      seen: 'the serve setting is over 1 MiB',
    });
    const paths = f.requests().map((q) => q.path);
    if (paths.at(-1) === '/localapi/v0/status?peers=false') paths.pop();
    expect(paths.length).toBeGreaterThanOrEqual(4);
    expect(paths).toEqual(
      paths.map((_, i) =>
        i % 2 === 0 ? '/localapi/v0/status?peers=false' : '/localapi/v0/serve-config',
      ),
    );
  });

  it('correct allows, Tailscale down pauses, a repoint latches; the token never reaches the log', async () => {
    const f = await fake();
    const { signer, logs } = await start(f);
    expect(await state(signer)).toMatchObject({ kind: 'ok' });
    expect(await create(signer)).toBe('ok');

    rmSync(join(f.dir, 'ipnport'));
    expect(await waitKind(signer, 'paused')).toMatchObject({
      detail: LOCALAPI_DETAIL.notRunning,
    });
    expect(await create(signer)).toBe('approver_address_unverified');
    symlinkSync(String(f.port), join(f.dir, 'ipnport'));
    await waitKind(signer, 'ok');

    f.serve(WRONG);
    expect(await waitKind(signer, 'latched')).toMatchObject({
      seen: `${HOST}:${PORT} proxies to "http://127.0.0.1:9999"`,
    });
    expect(await create(signer)).toBe('approver_address_latched');
    expect(f.requests().length).toBeGreaterThan(2);
    expect(logs.join('\n')).not.toContain(f.token);
    expect(logs.join('\n')).not.toContain(Buffer.from(`:${f.token}`).toString('base64'));
  });
});
