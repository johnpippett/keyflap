import { type ChildProcess, spawn } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fakeTailscale, serveConfig } from '@aab/sources/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { adminCall } from '../src/admin-wire.ts';
import type { AddressState } from '../src/approver-address.ts';
import { connectSigner, SignerDenied } from '../src/client.ts';
import { servicePlatform } from '../src/platform.ts';
import { fakeLocalApi } from './fake-localapi.ts';
import { tmpDir } from './helpers.ts';

const MAIN = fileURLToPath(new URL('../src/main.ts', import.meta.url));

interface Setup {
  dir: string;
  creds: string;
  config: string;
  socketPath: string;
  adminPath: string;
  channelKey: Buffer;
}

function setup(
  opts: { kek?: Buffer; configExtra?: Record<string, unknown>; activated?: boolean } = {},
): Setup {
  const dir = tmpDir();
  const creds = join(dir, 'creds');
  mkdirSync(creds, { mode: 0o700 });
  const channelKey = randomBytes(32);
  writeFileSync(join(creds, 'channel-key'), channelKey, { mode: 0o400 });
  writeFileSync(join(creds, 'kek'), opts.kek ?? randomBytes(32), { mode: 0o400 });
  const socketPath = join(dir, 'run', 'signer.sock');
  const adminPath = join(dir, 'run', 'admin.sock');
  const config = join(dir, 'signer.json');
  writeFileSync(
    config,
    JSON.stringify({
      storePath: join(dir, 'keys.enc.json'),
      ...(opts.activated ? {} : { socketPath, adminSocketPath: adminPath }),
      ...opts.configExtra,
    }),
    { mode: 0o644 },
  );
  chmodSync(config, 0o644);
  return { dir, creds, config, socketPath, adminPath, channelKey };
}

function putCred(s: Setup, name: string, data: Buffer): void {
  rmSync(join(s.creds, name), { force: true });
  writeFileSync(join(s.creds, name), data, { mode: 0o400 });
}

const running: ChildProcess[] = [];
afterEach(() => {
  for (const c of running.splice(0)) c.kill('SIGKILL');
});

function startService(
  s: Setup,
  opts: { stdio?: (number | 'ignore' | 'pipe')[]; shell?: string } = {},
): Promise<ChildProcess> {
  const env = { PATH: process.env.PATH ?? '', CREDENTIALS_DIRECTORY: s.creds };
  const args = ['--disable-warning=ExperimentalWarning', MAIN, '--service', '--config', s.config];
  const child = opts.shell
    ? spawn('sh', ['-c', opts.shell, process.execPath, ...args], {
        env,
        stdio: opts.stdio ?? ['ignore', 'pipe', 'pipe'],
      })
    : spawn(process.execPath, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  running.push(child);
  return new Promise((resolve, reject) => {
    let err = '';
    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (d: string) => {
      err += d;
      if (/"event":"ready"/.test(err)) resolve(child);
    });
    child.once('exit', (code) => reject(new Error(`exited ${code}: ${err}`)));
  });
}

function approverKey() {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  return {
    credentialId: randomBytes(16).toString('base64url'),
    x: jwk.x as string,
    y: jwk.y as string,
    rpId: 'approver.localhost',
    origin: 'http://approver.localhost:8766',
  };
}

describe.skipIf(servicePlatform() !== null)('signer service mode off Linux and macOS', () => {
  it('main.ts --service refuses to start, before reading its config', async () => {
    const s = setup();
    await expect(startService(s)).rejects.toThrow(/service mode needs Linux with systemd or macOS/);
  });
});

describe.runIf(servicePlatform() !== null)('signer service mode (S2/S3)', () => {
  it('unlocks its store with the KEK credential and serves the core over the channel key', async () => {
    const s = setup();
    await startService(s);
    const signer = await connectSigner({ socketPath: s.socketPath, channelKey: s.channelKey });
    expect(await signer.client.ping()).toEqual({ pong: true });
    expect(signer.process).toBeNull();
    await expect(
      connectSigner({ socketPath: s.socketPath, channelKey: randomBytes(32) }),
    ).rejects.toThrow();
    await signer.stop();
    const file = readFileSync(join(s.dir, 'keys.enc.json'), 'utf8');
    expect(file).not.toContain(readFileSync(join(s.creds, 'kek')).toString('base64url'));
  });

  it('reopens the same store with the same KEK and refuses a different one', async () => {
    const kek = randomBytes(32);
    const s = setup({ kek });
    const first = await startService(s);
    const signer = await connectSigner({ socketPath: s.socketPath, channelKey: s.channelKey });
    await signer.client.addApprover({ key: approverKey() });
    await signer.stop();
    first.kill('SIGTERM');
    await new Promise((r) => first.once('exit', r));

    await startService(s);
    const again = await connectSigner({ socketPath: s.socketPath, channelKey: s.channelKey });
    expect((await again.client.listApprovers()).approvers).toHaveLength(1);
    await again.stop();
    for (const c of running.splice(0)) c.kill('SIGKILL');
    await new Promise((r) => setTimeout(r, 100));

    putCred(s, 'kek', randomBytes(32));
    await expect(startService(s)).rejects.toThrow(/fatal/);
  });

  it('fails closed without its credentials or with a config it does not know', async () => {
    const s = setup();
    putCred(s, 'kek', Buffer.alloc(16));
    await expect(startService(s)).rejects.toThrow(/kek.{1,4} must be 32 bytes/);
    const t = setup({ configExtra: { trustedApproverKeys: { k: 'x' } } });
    await expect(startService(t)).rejects.toThrow(/unknown key .{1,2}trustedApproverKeys/);
    const u = setup();
    chmodSync(join(u.creds, 'channel-key'), 0o444);
    await expect(startService(u)).rejects.toThrow(/accessible to other users/);
  });

  it('the admin socket can remove the last phone; the core channel cannot', async () => {
    const s = setup();
    await startService(s);
    const signer = await connectSigner({ socketPath: s.socketPath, channelKey: s.channelKey });
    const key = approverKey();
    await signer.client.addApprover({ key });
    await expect(signer.client.removeApprover(key.credentialId)).rejects.toThrow(
      new SignerDenied('last_approver_needs_admin'),
    );
    expect(await adminCall(s.adminPath, 'status')).toMatchObject({
      approvers: 1,
      phoneLatched: true,
    });
    const listed = await adminCall<{ approvers: { credentialId: string }[] }>(
      s.adminPath,
      'approver.list',
    );
    expect(listed.approvers.map((a) => a.credentialId)).toEqual([key.credentialId]);
    expect(
      await adminCall(s.adminPath, 'approver.remove', { credentialId: key.credentialId }),
    ).toEqual({
      removed: true,
    });
    expect((await signer.client.listApprovers()).approvers).toHaveLength(0);
    await expect(adminCall(s.adminPath, 'sign')).rejects.toThrow(/unknown admin command/);
    await signer.stop();
  });

  it('watches the approval address: a tailscale nobody but root can change is required, the admin socket reports and clears', async () => {
    const fake = fakeTailscale(
      serveConfig({ host: 'approver.localhost', port: 8766, target: 'http://127.0.0.1:8766' }),
    );
    const approverAddress = {
      origin: 'http://approver.localhost:8766',
      target: 'http://127.0.0.1:8766',
      tailscale: { via: 'cli', bin: fake.bin, env: fake.env },
    };
    const s = setup({ configExtra: { approverAddress } });
    await startService(s);
    const status = await adminCall<{ address: AddressState }>(s.adminPath, 'status');
    expect(status.address).toMatchObject({
      kind: 'paused',
      detail: expect.stringMatching(/tailscale is not trusted: .*not in a system bin directory/),
    });
    const signer = await connectSigner({ socketPath: s.socketPath, channelKey: s.channelKey });
    await expect(signer.client.addApprover({ key: approverKey() })).rejects.toThrow(
      new SignerDenied('approver_address_unverified'),
    );
    await expect(signer.client.clearApproverAddress()).rejects.toThrow(
      new SignerDenied('admin_required'),
    );
    expect(await adminCall(s.adminPath, 'approver.address.clear')).toMatchObject({
      state: { kind: 'paused' },
    });
    expect(fake.calls()).toEqual([]);
    await signer.stop();

    const plain = setup();
    await startService(plain);
    expect(await adminCall(plain.adminPath, 'status')).toMatchObject({
      address: { kind: 'unwatched' },
    });

    const timed = setup({
      configExtra: {
        approverAddress: { ...approverAddress, pollMs: { idle: 1, fast: 1, timeout: 1 } },
      },
    });
    await expect(startService(timed)).rejects.toThrow(/pollMs is for dev mode and tests only/);
  });

  it.skipIf(process.getuid?.() === 0)(
    'reading through the LocalAPI, the Tailscale directory must be root-only too, or nothing is read',
    async () => {
      const api = await fakeLocalApi(
        serveConfig({ host: 'approver.localhost', port: 8766, target: 'http://127.0.0.1:8766' }),
      );
      try {
        const s = setup({
          configExtra: {
            approverAddress: {
              origin: 'http://approver.localhost:8766',
              target: 'http://127.0.0.1:8766',
              tailscale: { via: 'localapi', dir: api.dir },
            },
          },
        });
        await startService(s);
        const status = await adminCall<{ address: AddressState }>(s.adminPath, 'status');
        expect(status.address).toMatchObject({
          kind: 'paused',
          detail: expect.stringMatching(/^tailscale is not trusted: .*(not root|writable by)/),
        });
        expect(api.requests()).toEqual([]);
      } finally {
        await api.close();
      }
    },
  );

  it('serves sockets handed over by the service manager (socket activation)', async () => {
    const s = setup({ activated: true });
    const listen = async (path: string) => {
      const srv: Server = createServer();
      await new Promise<void>((r) => srv.listen(path, () => r()));
      return srv;
    };
    mkdirSync(join(s.dir, 'run'));
    const a = await listen(join(s.dir, 'run', 'a'));
    const b = await listen(join(s.dir, 'run', 'b'));
    const fd = (srv: Server) => (srv as unknown as { _handle: { fd: number } })._handle.fd;
    const ready = startService(s, {
      shell:
        'LISTEN_PID=$$ LISTEN_FDS=2 LISTEN_FDNAMES=signer:signer-admin; export LISTEN_PID LISTEN_FDS LISTEN_FDNAMES; exec "$0" "$@"',
      stdio: ['ignore', 'pipe', 'pipe', fd(a), fd(b)],
    });
    await ready;
    renameSync(join(s.dir, 'run', 'a'), s.socketPath);
    renameSync(join(s.dir, 'run', 'b'), s.adminPath);
    await new Promise<void>((r) => a.close(() => r()));
    await new Promise<void>((r) => b.close(() => r()));
    const signer = await connectSigner({ socketPath: s.socketPath, channelKey: s.channelKey });
    expect(await signer.client.ping()).toEqual({ pong: true });
    expect(await adminCall(s.adminPath, 'status')).toMatchObject({ approvers: 0 });
    await signer.stop();
  });
});
