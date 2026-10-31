import { type ChildProcess, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import type { ApproverFront } from '@aab/approver/front';
import { adminCall } from '@aab/signer/admin-wire';
import { servicePlatform } from '@aab/signer/platform';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { runClaudeCodeHook } from '../src/hook-claude-code.ts';
import { runApproverFront } from '../src/service/approver-main.ts';
import { runServiceCommand } from '../src/service/cli.ts';
import type { CoreServiceConfig } from '../src/service/config.ts';
import { type CoreService, runCoreService } from '../src/service/core-main.ts';
import { SERVICE_PATHS, type ServicePaths } from '../src/service/paths.ts';
import { tmpDir } from './helpers.ts';

const SIGNER_MAIN = fileURLToPath(import.meta.resolve('@aab/signer/client')).replace(
  /client\.ts$/,
  'main.ts',
);

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

function credDir(path: string, files: Record<string, Buffer | string>): string {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  for (const [name, data] of Object.entries(files)) {
    writeFileSync(join(path, name), data, { mode: 0o400 });
  }
  return path;
}

const servicePlatforms = describe.runIf(servicePlatform() !== null);

servicePlatforms('service mode: core service + signer service + admin socket', () => {
  const dir = tmpDir();
  const channelKey = randomBytes(32);
  const hostToken = randomBytes(32).toString('base64url');
  const paths: ServicePaths = {
    ...SERVICE_PATHS,
    coreData: join(dir, 'core'),
    signerData: join(dir, 'signer'),
    hookDir: join(dir, 'hook'),
    hostToken: join(dir, 'hook', 'host-token'),
    intentSocket: join(dir, 'run', 'intent.sock'),
    adminSocket: join(dir, 'run', 'admin.sock'),
    signerSocket: join(dir, 'srun', 'signer.sock'),
    signerAdminSocket: join(dir, 'srun', 'admin.sock'),
    approverApiSocket: join(dir, 'arun', 'api.sock'),
  };
  let signer: ChildProcess;
  let service: CoreService;
  let front: ApproverFront;
  let frontPort: number;
  let origin: string;
  const signerLost = vi.fn();
  const stderr: string[] = [];
  const savedCreds = process.env.CREDENTIALS_DIRECTORY;

  beforeAll(async () => {
    const signerCfg = join(dir, 'signer.json');
    writeFileSync(
      signerCfg,
      JSON.stringify({
        storePath: join(dir, 'signer', 'keys.enc.json'),
        socketPath: paths.signerSocket,
        adminSocketPath: paths.signerAdminSocket,
      }),
    );
    chmodSync(signerCfg, 0o644);
    mkdirSync(join(dir, 'signer'), { mode: 0o700 });
    const signerCreds = credDir(join(dir, 'creds-signer'), {
      'channel-key': channelKey,
      kek: randomBytes(32),
    });
    signer = spawn(
      process.execPath,
      ['--disable-warning=ExperimentalWarning', SIGNER_MAIN, '--service', '--config', signerCfg],
      {
        env: { PATH: process.env.PATH ?? '', CREDENTIALS_DIRECTORY: signerCreds },
        stdio: ['ignore', 'ignore', 'pipe'],
      },
    );
    await new Promise<void>((resolve, reject) => {
      let err = '';
      signer.stderr?.on('data', (d: Buffer) => {
        err += d;
        if (err.includes('"ready"')) resolve();
      });
      signer.once('exit', (c) => reject(new Error(`signer exited ${c}: ${err}`)));
    });

    mkdirSync(paths.hookDir, { mode: 0o700 });
    writeFileSync(paths.hostToken, `${hostToken}\n`, { mode: 0o600 });

    const port = await freePort();
    origin = `http://approver.localhost:${port}`;
    const cfg: CoreServiceConfig = {
      dataDir: paths.coreData,
      signerSocket: paths.signerSocket,
      intentSocket: paths.intentSocket,
      adminSocket: paths.adminSocket,
      mcp: { host: '127.0.0.1', port: 0 },
      approver: {
        origin,
        listen: { host: '127.0.0.1', port },
        tls: false,
        front: { socket: paths.approverApiSocket },
      },
      highRisk: [],
      passwordSource: null,
      browser: { mode: 'headless', persist: true },
    };
    process.env.CREDENTIALS_DIRECTORY = credDir(join(dir, 'creds-core'), {
      'channel-key': channelKey,
      'host-token': `${hostToken}\n`,
    });
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
    mkdirSync(join(dir, 'arun'), { mode: 0o700 });
    service = await runCoreService(cfg, { onSignerLost: signerLost });
    front = await runApproverFront({
      origin,
      listen: { host: '127.0.0.1', port },
      tls: false,
      upstream: paths.approverApiSocket,
    });
    frontPort = port;
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    process.env.CREDENTIALS_DIRECTORY = savedCreds;
    if (savedCreds === undefined) delete process.env.CREDENTIALS_DIRECTORY;
    await front?.close();
    await service?.stop();
    signer?.kill('SIGKILL');
  });

  const out = () => {
    const chunks: string[] = [];
    return { write: (t: string) => void chunks.push(t), text: () => chunks.join('') };
  };

  it('status: the core reaches its signer and reports service mode', async () => {
    const o = out();
    await runServiceCommand({ kind: 'status', dataDir: '/unused', json: false }, o.write, paths);
    expect(o.text()).toMatch(/Mode: +service/);
    expect(o.text()).toMatch(/Signer: +ok/);
    expect(o.text()).toMatch(/Phones: +0 paired/);
    expect(o.text()).toMatch(/Audit log: +\d+ entries, hash chain intact/);
    expect(service.daemon.signer.process).toBeNull();
  });

  it('agent add over the admin socket prints the token once and the --service hook', async () => {
    const o = out();
    await runServiceCommand(
      { kind: 'agent-add', dataDir: '/unused', name: 'Claude Code', mcpPort: 8765 },
      o.write,
      paths,
    );
    const text = o.text();
    const token = /aab_agent_[A-Za-z0-9_-]{43}/.exec(text)?.[0];
    const id = /\(id ([0-9a-f-]{36})\)/.exec(text)?.[1];
    expect(token && id).toBeTruthy();
    expect(text).toContain(`/usr/local/bin/keyflap hook claude-code --agent ${id} --service`);
    expect(text).toContain(`${paths.hookDir}/**`);
    expect(text).not.toContain('--unprotected');
    expect(service.daemon.resolveAgent(token as string)?.agentId).toBe(id);

    const recorded = await runClaudeCodeHook({
      dataDir: '/nonexistent',
      hostTokenPath: paths.hostToken,
      socketPath: paths.intentSocket,
      agentId: id as string,
      stdin: Readable.from([JSON.stringify({ prompt: 'sign me in' })]),
      log: () => {},
    });
    expect(recorded).toBe('recorded');

    const l = out();
    await runServiceCommand({ kind: 'agent-list', dataDir: '/unused', json: true }, l.write, paths);
    expect(JSON.parse(l.text())).toMatchObject([{ id, name: 'Claude Code', revokedAt: null }]);
    const r = out();
    await runServiceCommand(
      { kind: 'agent-revoke', dataDir: '/unused', id: id as string },
      r.write,
      paths,
    );
    expect(service.daemon.resolveAgent(token as string)).toBeNull();
  });

  it('passwords go into the live signer, no restart, no offline signer', async () => {
    const added = await adminCall<{ id: string; domain: string }>(
      paths.adminSocket,
      'password.add',
      {
        site: 'https://login.example.com/',
        username: 'alice',
        password: 'correct horse battery staple',
      },
    );
    expect(added.domain).toBe('example.com');
    const l = out();
    await runServiceCommand(
      { kind: 'password-list', dataDir: '/unused', json: true },
      l.write,
      paths,
    );
    expect(JSON.parse(l.text())).toMatchObject([
      { id: added.id, domain: 'example.com', username: 'alice' },
    ]);
    expect(l.text()).not.toContain('correct horse');
    await expect(
      adminCall(paths.adminSocket, 'password.add', { site: 'x.example', password: 'abc' }),
    ).rejects.toThrow(/bad_password/);
    const r = out();
    await runServiceCommand(
      { kind: 'password-remove', dataDir: '/unused', id: added.id },
      r.write,
      paths,
    );
    expect(r.text()).toContain(`Removed password ${added.id}`);
    const rows = service.daemon.broker.audit.all();
    expect(rows.some((row) => row.event_type === 'admin.request')).toBe(true);
    expect(JSON.stringify(rows)).not.toContain('correct horse');
  });

  it('password import goes through the admin socket into the live signer', async () => {
    const file = join(dir, 'Passwords.csv');
    writeFileSync(
      file,
      'Title,URL,Username,Password,Notes,OTPAuth\n' +
        'Imp,https://imported.example/,ivy,imported-pw-5678,,otpauth://totp/I:ivy?secret=JBSWY3DPEHPK3PXP\n' +
        'Other,https://other.example/,olly,other-pw-5678,,\n',
      { mode: 0o600 },
    );
    const o = out();
    await runServiceCommand(
      {
        kind: 'password-import',
        dataDir: '/unused',
        file,
        sites: ['imported.example'],
        all: false,
        expect: null,
      },
      o.write,
      paths,
    );
    expect(o.text()).toMatch(
      /Imported 1 login .*\n {2}pw_\S+ {2}imported\.example \(ivy\) \+ TOTP/,
    );
    expect(o.text()).toContain('Usable now.');
    expect(o.text()).not.toContain('imported-pw');
    const l = out();
    await runServiceCommand(
      { kind: 'password-list', dataDir: '/unused', json: true },
      l.write,
      paths,
    );
    const listed = JSON.parse(l.text()) as { domain: string; totp: boolean }[];
    expect(listed).toContainEqual(
      expect.objectContaining({ domain: 'imported.example', totp: true }),
    );
    expect(listed.some((p) => p.domain === 'other.example')).toBe(false);
    expect(JSON.stringify(service.daemon.broker.audit.all())).not.toContain('imported-pw');
  });

  it('approver pair hands the one-time link to the admin only, never to the log', async () => {
    const o = out();
    await runServiceCommand(
      { kind: 'approver-pair', dataDir: '/unused', phone: null },
      o.write,
      paths,
    );
    const url = new RegExp(`${origin.replace(/[.]/g, '\\.')}/pair#[A-Za-z0-9_-]{43}`).exec(
      o.text(),
    )?.[0];
    expect(url).toBeTruthy();
    const code = (url as string).split('#')[1] as string;
    expect(stderr.join('')).not.toContain(code);
    const file = join(paths.coreData, 'approver', 'pairing-url');
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readFileSync(file, 'utf8').trim()).toBe(url);

    const a = out();
    await runServiceCommand(
      { kind: 'approver-list', dataDir: '/unused', json: true },
      a.write,
      paths,
    );
    expect(JSON.parse(a.text())).toEqual([]);
  });

  it('the approver page comes from the front; the core answers only the API, on its socket', async () => {
    const get = (o: { port?: number; socketPath?: string }, path: string) =>
      new Promise<{ status: number; type: string }>((resolve, reject) => {
        const r = request(
          { host: '127.0.0.1', ...o, path, headers: { host: new URL(origin).host } },
          (res) => {
            res.resume();
            resolve({ status: res.statusCode ?? 0, type: res.headers['content-type'] ?? '' });
          },
        );
        r.on('error', reject);
        r.end();
      });
    expect(await get({ port: frontPort }, '/')).toEqual({
      status: 200,
      type: 'text/html; charset=utf-8',
    });
    expect((await get({ port: frontPort }, '/api/state')).status).toBe(401);
    expect((await get({ socketPath: paths.approverApiSocket }, '/app.js')).status).toBe(404);
    expect((await get({ socketPath: paths.approverApiSocket }, '/api/state')).status).toBe(401);
  });

  it('policy and audit commands run in the core, over the admin socket', async () => {
    const set = out();
    await runServiceCommand(
      {
        kind: 'policy-set',
        dataDir: '/unused',
        site: 'example.com',
        agent: null,
        mode: 'deny',
        allowForMs: null,
        sessionTtlMs: undefined,
      },
      set.write,
      paths,
    );
    expect(set.text()).toContain('example.com (all agents): deny');
    const list = out();
    await runServiceCommand(
      { kind: 'policy-list', dataDir: '/unused', agent: null, json: true },
      list.write,
      paths,
    );
    expect(JSON.parse(list.text())).toMatchObject([{ site: 'example.com', mode: 'deny' }]);
    const rm = out();
    await runServiceCommand(
      { kind: 'policy-remove', dataDir: '/unused', site: 'example.com', agent: null },
      rm.write,
      paths,
    );
    await expect(
      runServiceCommand(
        { kind: 'policy-remove', dataDir: '/unused', site: 'example.com', agent: null },
        () => {},
        paths,
      ),
    ).rejects.toThrow(/no rule for example.com/);
    const v = out();
    await runServiceCommand({ kind: 'audit-verify', dataDir: '/unused' }, v.write, paths);
    expect(v.text()).toMatch(/hash chain intact/);
    const tail = out();
    await runServiceCommand(
      { kind: 'audit-tail', dataDir: '/unused', limit: 3, json: true },
      tail.write,
      paths,
    );
    expect(JSON.parse(tail.text())).toHaveLength(3);
  });

  it('sessions list / clear / keep / unkeep run in the core and apply at once', async () => {
    const d = service.daemon;
    const agent = d.registry.add('sessions-agent');
    const session = await d.sessions.get(agent);
    await session.context.addCookies([
      { name: 'a', value: '1', domain: 'example.com', path: '/' },
      { name: 'b', value: '2', domain: 'other.example', path: '/' },
    ]);
    session.markDirty();
    await d.sessions.save(agent.id, 'full');
    const list = out();
    await runServiceCommand(
      { kind: 'sessions-list', dataDir: '/unused', agent: agent.id, json: true },
      list.write,
      paths,
    );
    expect(
      JSON.parse(list.text())
        .sessions.map((r: { site: string }) => r.site)
        .sort(),
    ).toEqual(['example.com', 'other.example']);
    expect(list.text()).not.toMatch(/"value"|"name"/);

    const clear = out();
    await runServiceCommand(
      {
        kind: 'sessions-clear',
        dataDir: '/unused',
        agent: agent.id,
        all: false,
        site: 'example.com',
      },
      clear.write,
      paths,
    );
    expect(clear.text()).toContain('Cleared example.com for 1 agent(s): 1 cookies');
    expect((await session.context.cookies()).map((c) => c.name)).toEqual(['b']);
    expect(d.persistence?.repo.index(agent.id).map((r) => r.site)).toEqual(['other.example']);
    const events = d.broker.audit.all().map((r) => [r.event_type, JSON.parse(r.payload_json)]);
    expect(events).toContainEqual([
      'session.clear_requested',
      { agentId: agent.id, site: 'example.com', via: 'admin' },
    ]);
    expect(events).toContainEqual([
      'session.cleared',
      { agentId: agent.id, site: 'example.com', cookies: 1, pages: 0, via: 'admin' },
    ]);

    const keep = out();
    await runServiceCommand(
      {
        kind: 'sessions-keep',
        dataDir: '/unused',
        site: 'https://www.paypal.com',
        agent: agent.id,
      },
      keep.write,
      paths,
    );
    expect(keep.text()).toContain('Keeping paypal.com');
    expect(d.optins.has(agent.id, 'paypal.com')).toBe(true);
    const unkeep = out();
    await runServiceCommand(
      { kind: 'sessions-unkeep', dataDir: '/unused', site: 'paypal.com', agent: agent.id },
      unkeep.write,
      paths,
    );
    expect(unkeep.text()).toContain('No longer keeping paypal.com');
    expect(d.optins.has(agent.id, 'paypal.com')).toBe(false);

    const all = out();
    await runServiceCommand(
      { kind: 'sessions-clear', dataDir: '/unused', agent: agent.id, all: false, site: null },
      all.write,
      paths,
    );
    expect(d.sessions.peek(agent.id)).toBeUndefined();
    expect(d.persistence?.repo.index(agent.id)).toEqual([]);
    await expect(
      runServiceCommand(
        { kind: 'sessions-clear', dataDir: '/unused', agent: 'nope', all: false, site: null },
        () => {},
        paths,
      ),
    ).rejects.toThrow(/no active agent/);
  });

  describe('invariant 10: an admin request is refused when its audit row cannot be written', () => {
    const FIXED_REFUSAL = 'refused: the audit log could not record this request';
    const breakAdminRows = () =>
      service.daemon.db.exec(
        `CREATE TRIGGER admin_rows_unwritable BEFORE INSERT ON audit
           WHEN NEW.event_type = 'admin.request'
           BEGIN SELECT RAISE(ABORT, 'disk full at /var/lib/keyflap/core/broker.sqlite'); END`,
      );
    const mendAdminRows = () =>
      service.daemon.db.exec('DROP TRIGGER IF EXISTS admin_rows_unwritable');
    const linkFile = join(paths.coreData, 'approver', 'pairing-url');
    const listed = async () => ({
      agents: (await adminCall<{ agents: unknown[] }>(paths.adminSocket, 'agent.list')).agents
        .length,
      passwords: (await adminCall<{ passwords: unknown[] }>(paths.adminSocket, 'password.list'))
        .passwords.length,
      pairingLink: existsSync(linkFile) ? readFileSync(linkFile, 'utf8') : null,
    });

    it('refuses with a fixed message and leaves agents, passwords and the pairing link alone', async () => {
      const before = await listed();
      const rowsBefore = service.daemon.broker.audit.all().length;
      breakAdminRows();
      try {
        const refused = (op: string, params: Record<string, unknown> = {}) =>
          expect(adminCall(paths.adminSocket, op, params)).rejects.toMatchObject({
            code: 'refused',
            message: FIXED_REFUSAL,
          });
        await refused('agent.add', { name: 'unrecorded-agent' });
        await refused('password.add', {
          site: 'unrecorded.example',
          username: 'ivy',
          password: 'unrecorded-pw-0001',
        });
        await refused('approver.pair');
        await refused('status');
        await refused('no.such.op');
      } finally {
        mendAdminRows();
      }
      expect(service.daemon.broker.audit.all()).toHaveLength(rowsBefore);
      expect(service.daemon.broker.audit.verify()).toBeNull();
      expect(await listed()).toEqual(before);
    });

    it('with the audit log writable the row is written before the request runs and names only the op', async () => {
      const rowsBefore = service.daemon.broker.audit.all().length;
      const added = await adminCall<{ id: string }>(paths.adminSocket, 'agent.add', {
        name: 'recorded-agent',
        extra: 'recorded-param-0002',
      });
      const rows = service.daemon.broker.audit.all().slice(rowsBefore);
      expect(rows.map((r) => [r.event_type, JSON.parse(r.payload_json)])).toEqual([
        ['admin.request', { op: 'agent.add' }],
        ['agent.added', { agentId: added.id, name: 'recorded-agent', via: 'admin' }],
        ['admin.result', { op: 'agent.add', ok: true }],
      ]);
      expect(JSON.stringify(rows)).not.toContain('recorded-param-0002');
      expect(service.daemon.broker.audit.verify()).toBeNull();
      await adminCall(paths.adminSocket, 'agent.revoke', { id: added.id });
    });

    it('records whether the request worked, after it ran, so a failed one is told apart from a done one', async () => {
      const rowsBefore = service.daemon.broker.audit.all().length;
      await expect(adminCall(paths.adminSocket, 'no.such.op')).rejects.toThrow();
      const rows = service.daemon.broker.audit.all().slice(rowsBefore);
      expect(rows.map((r) => [r.event_type, JSON.parse(r.payload_json)])).toEqual([
        ['admin.request', { op: 'no.such.op' }],
        ['admin.result', { op: 'no.such.op', ok: false }],
      ]);
    });
  });

  it('dev-mode-only commands are refused in service mode', async () => {
    await expect(
      runServiceCommand(
        {
          kind: 'daemon',
          dataDir: '/x',
          mcpPort: 1,
          headed: false,
          unprotected: true,
          phone: null,
          highRisk: [],
          passwordSource: null,
          ephemeralBrowser: false,
        },
        () => {},
        paths,
      ),
    ).rejects.toThrow(/system service/);
  });

  it('a lost signer connection stops the core (systemd restarts it)', async () => {
    signer.kill('SIGKILL');
    await vi.waitFor(() => expect(signerLost).toHaveBeenCalledTimes(1), { timeout: 15_000 });
    await expect(adminCall(paths.adminSocket, 'status')).rejects.toMatchObject({
      code: 'unreachable',
    });
  });
});
