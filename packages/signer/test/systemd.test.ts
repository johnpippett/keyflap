import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { connect, type Server } from 'node:net';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AdminCallError,
  AdminError,
  AdminOps,
  adminCall,
  startAdminServer,
} from '../src/admin-wire.ts';
import {
  buildSources,
  OP_TOKEN_CREDENTIAL,
  parseServiceConfig,
  withServiceSecrets,
} from '../src/service.ts';
import {
  CredentialError,
  clearListenEnv,
  credentialPrivate,
  listenFds,
  readCredential,
  readProvisionedFile,
} from '../src/systemd.ts';
import { tmpDir } from './helpers.ts';

describe('socket activation (sd_listen_fds)', () => {
  it('maps names to fds from 3, only for our pid', () => {
    const env = { LISTEN_PID: '42', LISTEN_FDS: '2', LISTEN_FDNAMES: 'intent:admin' };
    expect([...listenFds(env, 42)]).toEqual([
      ['intent', 3],
      ['admin', 4],
    ]);
    expect(listenFds(env, 43).size).toBe(0);
    expect(listenFds({}, 42).size).toBe(0);
  });

  it('refuses malformed or ambiguous variables', () => {
    const bad = [
      { LISTEN_PID: '1', LISTEN_FDS: '0', LISTEN_FDNAMES: '' },
      { LISTEN_PID: '1', LISTEN_FDS: 'x', LISTEN_FDNAMES: 'a' },
      { LISTEN_PID: '1', LISTEN_FDS: '2', LISTEN_FDNAMES: 'a' },
      { LISTEN_PID: '1', LISTEN_FDS: '2', LISTEN_FDNAMES: 'a:a' },
      { LISTEN_PID: '1', LISTEN_FDS: '1', LISTEN_FDNAMES: '../x' },
      { LISTEN_PID: '1', LISTEN_FDS: '1' },
    ];
    for (const env of bad) expect(() => listenFds(env, 1), JSON.stringify(env)).toThrow();
  });

  it('clears the variables so children do not adopt the sockets', () => {
    const env: NodeJS.ProcessEnv = {
      LISTEN_PID: '1',
      LISTEN_FDS: '1',
      LISTEN_FDNAMES: 'a',
      X: '1',
    };
    clearListenEnv(env);
    expect(env).toEqual({ X: '1' });
  });
});

describe('service credentials', () => {
  function credDir(files: Record<string, { data: string | Buffer; mode?: number }>) {
    const dir = join(tmpDir(), 'creds');
    mkdirSync(dir, { mode: 0o700 });
    for (const [name, f] of Object.entries(files)) {
      writeFileSync(join(dir, name), f.data, { mode: f.mode ?? 0o400 });
      chmodSync(join(dir, name), f.mode ?? 0o400);
    }
    return dir;
  }

  it('reads a private credential', () => {
    const dir = credDir({ kek: { data: Buffer.alloc(32, 7) } });
    expect(readCredential('kek', { env: { CREDENTIALS_DIRECTORY: dir } })).toEqual(
      Buffer.alloc(32, 7),
    );
  });

  it('refuses missing directories, other-readable files, bad names and big files', () => {
    const dir = credDir({
      open: { data: 'x', mode: 0o444 },
      big: { data: Buffer.alloc(100) },
    });
    const env = { CREDENTIALS_DIRECTORY: dir };
    expect(() => readCredential('kek', { env: {} })).toThrow(CredentialError);
    expect(() => readCredential('kek', { env: { CREDENTIALS_DIRECTORY: 'rel' } })).toThrow(
      CredentialError,
    );
    expect(() => readCredential('missing', { env })).toThrow(/unreadable/);
    expect(readCredential('missing', { env, optional: true })).toBeNull();
    expect(() => readCredential('open', { env })).toThrow(/other users/);
    expect(() => readCredential('../kek', { env })).toThrow(/bad credential name/);
    expect(() => readCredential('big', { env, maxBytes: 10 })).toThrow(/too large/);
  });

  it("accepts both of systemd's layouts and nothing looser", () => {
    const svc = 990;
    expect(credentialPrivate({ mode: 0o100400, uid: svc, gid: svc })).toBe(true);
    expect(credentialPrivate({ mode: 0o100600, uid: svc, gid: svc })).toBe(true);
    expect(credentialPrivate({ mode: 0o100440, uid: 0, gid: 0 })).toBe(true);
    expect(credentialPrivate({ mode: 0o100440, uid: svc, gid: svc })).toBe(false);
    expect(credentialPrivate({ mode: 0o100440, uid: 0, gid: svc })).toBe(false);
    expect(credentialPrivate({ mode: 0o100440, uid: svc, gid: 0 })).toBe(false);
    expect(credentialPrivate({ mode: 0o100444, uid: 0, gid: 0 })).toBe(false);
    expect(credentialPrivate({ mode: 0o100404, uid: svc, gid: svc })).toBe(false);
    expect(credentialPrivate({ mode: 0o100460, uid: 0, gid: 0 })).toBe(false);
    expect(credentialPrivate({ mode: 0o100401, uid: 0, gid: 0 })).toBe(false);
  });
});

describe('root-provisioned config files', () => {
  it('accepts a file only its owner can write; refuses group/other-writable ones', () => {
    const dir = tmpDir();
    const ok = join(dir, 'ok.json');
    writeFileSync(ok, '{}', { mode: 0o644 });
    chmodSync(ok, 0o644);
    expect(readProvisionedFile(ok)).toBe('{}');
    const loose = join(dir, 'loose.json');
    writeFileSync(loose, '{}');
    chmodSync(loose, 0o664);
    expect(() => readProvisionedFile(loose)).toThrow(/writable by group or others/);
    expect(() => readProvisionedFile('relative.json')).toThrow(/absolute/);
  });

  it('signer config: strict keys, absolute paths, no approver keys', () => {
    expect(parseServiceConfig('{"storePath":"/var/lib/keyflap/signer/keys.enc.json"}')).toEqual({
      storePath: '/var/lib/keyflap/signer/keys.enc.json',
    });
    expect(() => parseServiceConfig('{"storePath":"keys.json"}')).toThrow(/absolute/);
    expect(() => parseServiceConfig('{"storePath":"/k","trustedApproverKeys":{"x":"y"}}')).toThrow(
      /unknown key "trustedApproverKeys"/,
    );
    expect(() =>
      parseServiceConfig('{"storePath":"/k","sources":{"protonPass":{"bin":"pass-cli","env":{}}}}'),
    ).toThrow(/absolute/);
    expect(() => parseServiceConfig('[]')).toThrow();
    expect(() => parseServiceConfig('{"storePath":"/k","sources":{"bitwarden":{}}}')).toThrow(
      /unknown key "sources.bitwarden"/,
    );
  });

  it('signer config: 1Password, with its token only from the systemd credential', () => {
    const op = { bin: '/opt/keyflap/bin/op', env: { HOME: '/var/lib/keyflap/signer' }, vault: 'A' };
    const cfg = parseServiceConfig(
      JSON.stringify({ storePath: '/k', sources: { onePassword: op } }),
    );
    expect(cfg.sources?.onePassword).toEqual(op);
    expect(() =>
      parseServiceConfig(
        JSON.stringify({
          storePath: '/k',
          sources: { onePassword: { ...op, env: { OP_SERVICE_ACCOUNT_TOKEN: 'ops_x' } } },
        }),
      ),
    ).toThrow(/must not set OP_/);
    expect(() =>
      parseServiceConfig(
        JSON.stringify({ storePath: '/k', sources: { onePassword: { ...op, bin: 'op' } } }),
      ),
    ).toThrow(/absolute/);

    const logs: string[] = [];
    const log = (e: string) => logs.push(e);
    const withToken = withServiceSecrets(
      cfg.sources,
      (name) => (name === OP_TOKEN_CREDENTIAL ? Buffer.from('ops_token\n') : null),
      log,
    );
    expect(withToken?.onePassword?.env).toEqual({
      HOME: '/var/lib/keyflap/signer',
      OP_SERVICE_ACCOUNT_TOKEN: 'ops_token',
    });
    const without = withServiceSecrets(cfg.sources, () => null, log);
    expect(without?.onePassword?.env).toEqual({ HOME: '/var/lib/keyflap/signer' });
    expect(logs).toEqual(['source_token_missing']);
    expect(buildSources(withToken, { mode: 'same-user' }).map((s) => s.kind)).toEqual([
      '1password',
    ]);
  });
});

describe('admin wire protocol (root-only sockets)', () => {
  let server: Server | undefined;
  afterEach(async () => {
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    server = undefined;
  });

  async function start(ops: AdminOps, seen: [string, boolean][] = []) {
    const path = join(tmpDir(), 'run', 'admin.sock');
    server = await startAdminServer({
      listen: { path },
      ops,
      onRequest: (op, ok) => seen.push([op, ok]),
    });
    return path;
  }

  it('dispatches named ops; only AdminError messages reach the caller', async () => {
    const seen: [string, boolean][] = [];
    const ops = new AdminOps()
      .register('echo', (p) => ({ got: p.v }))
      .register('refuse', () => {
        throw new AdminError('no such agent');
      })
      .register('crash', () => {
        throw new Error('/secret/path details');
      });
    const path = await start(ops, seen);
    expect(await adminCall(path, 'echo', { v: 1 })).toEqual({ got: 1 });
    await expect(adminCall(path, 'refuse')).rejects.toMatchObject({
      code: 'refused',
      message: 'no such agent',
    });
    await expect(adminCall(path, 'crash')).rejects.toMatchObject({ message: 'internal error' });
    await expect(adminCall(path, 'nope')).rejects.toThrow(/unknown admin command/);
    expect(seen).toEqual([
      ['echo', true],
      ['refuse', false],
      ['crash', false],
      ['nope', false],
    ]);
    expect(() => ops.register('echo', () => null)).toThrow(/twice/);
    expect(() => ops.register('Bad Name', () => null)).toThrow(/bad admin op/);
  });

  it('the socket is 0600 in a 0700 dir, and a denied connect says so', async () => {
    const path = await start(new AdminOps());
    const { statSync } = await import('node:fs');
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(join(path, '..')).mode & 0o777).toBe(0o700);
    chmodSync(path, 0o000);
    if (process.getuid?.() !== 0) {
      await expect(adminCall(path, 'status')).rejects.toMatchObject({ code: 'permission' });
    }
    await expect(adminCall(join(tmpDir(), 'none.sock'), 'status')).rejects.toBeInstanceOf(
      AdminCallError,
    );
  });

  it('rejects malformed requests', async () => {
    const path = await start(new AdminOps().register('x', () => 1));
    const raw = (line: string) =>
      new Promise<string>((resolve) => {
        const s = connect(path, () => s.write(line));
        let out = '';
        s.on('data', (d) => {
          out += d;
        });
        s.on('close', () => resolve(out));
      });
    for (const line of ['nope\n', '[]\n', '{"op":"x","params":[1]}\n', '{"op":"X Y"}\n']) {
      expect(JSON.parse(await raw(line)), line).toEqual({ ok: false, error: 'malformed request' });
    }
    expect(JSON.parse(await raw('{"op":"x"}\n'))).toEqual({ ok: true, result: 1 });
  });
});
