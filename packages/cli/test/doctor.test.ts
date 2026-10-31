import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  type DevDoctorContext,
  formatReport,
  hookCodeCheck,
  nodeIsSupported,
  runChecks,
  type ServiceDoctorContext,
} from '../src/doctor.ts';
import { readAgentToken } from '../src/mcp-headers.ts';
import { SERVICE_PATHS, servicePaths } from '../src/service/paths.ts';
import { mcpEntry, mergeMcp, mergeSettings, stringify } from '../src/setup/claude-config.ts';
import { emptyState, type SetupState } from '../src/setup/state.ts';
import { runCli, tmpDir } from './helpers.ts';
import { AGENT_ID, AGENT_TOKEN, FakeSystem } from './setup-fakes.ts';

const D = '/home/u/.keyflap';

function healthyDev(): { sys: FakeSystem; ctx: DevDoctorContext } {
  const sys = new FakeSystem();
  sys.dir(D, 0o700).dir(`${D}/run`).dir(`${D}/approver`).dir(`${D}/agents`);
  sys.socket(`${D}/run/intent.sock`).socket(`${D}/run/signer.sock`);
  sys.file(`${D}/host-token`, 'HOSTTOKEN-SECRET', 0o600);
  sys.file(`${D}/agents/${AGENT_ID}.token`, AGENT_TOKEN, 0o600);
  sys.file(`${D}/approver/devices.json`, JSON.stringify({ devices: [{ id: 'dev_1' }] }), 0o600);
  sys.http_ = (url, o) =>
    url === 'http://127.0.0.1:8765/mcp' && o.method === 'POST'
      ? { status: 401 }
      : url === 'https://b.tail1.ts.net:8766/'
        ? { status: 200 }
        : { status: null, error: 'ECONNREFUSED' };
  sys.dir('/home/u/proj/.claude', 0o755);
  const cfg = {
    mcpUrl: 'http://127.0.0.1:8765/mcp',
    headersCommand: `/n /m.ts mcp-headers --agent ${AGENT_ID}`,
    hookCommand: `/n /m.ts hook claude-code --agent ${AGENT_ID}`,
    denyDir: D,
    home: '/home/u',
  };
  sys.file('/home/u/proj/.mcp.json', stringify(mergeMcp(undefined, mcpEntry(cfg)).doc));
  sys.file(
    '/home/u/proj/.claude/settings.local.json',
    stringify(mergeSettings(undefined, cfg).doc),
  );
  const state: SetupState = {
    ...emptyState(8765),
    headed: true,
    approver: {
      kind: 'phone',
      origin: 'https://b.tail1.ts.net:8766',
      listen: { host: '127.0.0.1', port: 8766 },
      tlsCert: null,
      tlsKey: null,
      via: 'tailscale',
    },
  };
  const ctx: DevDoctorContext = {
    mode: 'dev',
    sys,
    project: '/home/u/proj',
    home: '/home/u',
    owner: { uid: 1000, gid: 1000 },
    dataDir: D,
    state,
    daemonCommand:
      'keyflap daemon --unprotected --approver phone --approver-origin https://b.tail1.ts.net:8766',
    chromium: async () => ({ ok: true }),
    nodeVersion: '22.23.4',
    local: {
      agents: () => [{ id: AGENT_ID, name: 'claude-code', revoked: false }],
      audit: () => ({ intact: true, entries: 12, brokenAt: null }),
      passwords: () => 1,
    },
  };
  return { sys, ctx };
}

const status = (r: Awaited<ReturnType<typeof runChecks>>, id: string) =>
  r.checks.find((c) => c.id === id)?.status;

describe('keyflap doctor: Node version', () => {
  it('accepts only the patched release of each supported line (CVE-2026-111497)', () => {
    for (const v of ['22.23.4', 'v22.23.4', '22.24.0', '24.22.1', '24.23.0', '26.12.1', '27.0.0']) {
      expect(nodeIsSupported(v), v).toBe(true);
    }
    for (const v of ['22.23.3', '22.18.0', '20.19.0', '23.11.0', '24.22.0', '25.9.0', '26.12.0']) {
      expect(nodeIsSupported(v), v).toBe(false);
    }
  });
});

describe('keyflap doctor (dev mode)', () => {
  it('a healthy setup passes every check', async () => {
    const { ctx } = healthyDev();
    const r = await runChecks(ctx);
    expect(r.checks.filter((c) => c.status !== 'ok')).toEqual([]);
    expect(r.ok).toBe(true);
    expect(formatReport(r)).toContain('All checks passed.');
  });

  it('daemon down: fails with the exact command to start it', async () => {
    const { sys, ctx } = healthyDev();
    sys.live.clear();
    const r = await runChecks(ctx);
    const d = r.checks.find((c) => c.id === 'daemon');
    expect(d).toMatchObject({ status: 'fail', fix: ctx.daemonCommand });
    expect(status(r, 'mcp')).toBe('skip');
    expect(r.ok).toBe(false);
  });

  it('warns loudly when the model can read the data dir', async () => {
    const { sys, ctx } = healthyDev();
    sys.file(
      '/home/u/proj/.claude/settings.local.json',
      stringify({
        hooks: JSON.parse(sys.text('/home/u/proj/.claude/settings.local.json') as string).hooks,
      }),
    );
    const r = await runChecks(ctx);
    const c = r.checks.find((x) => x.id === 'claude-deny');
    expect(c?.status).toBe('fail');
    expect(c?.detail).toContain('THE MODEL CAN READ ~/.keyflap');
    expect(formatReport(r)).toContain('fix:');
  });

  it('no phone paired, no agent, broken audit chain, headless: each reported', async () => {
    const { sys, ctx } = healthyDev();
    sys.file(`${D}/approver/devices.json`, JSON.stringify({ devices: [] }));
    ctx.local.agents = () => [];
    ctx.local.audit = () => ({ intact: false, entries: 9, brokenAt: 4 });
    (ctx.state as SetupState).headed = false;
    const r = await runChecks(ctx);
    expect(status(r, 'phone')).toBe('fail');
    expect(status(r, 'agents')).toBe('fail');
    expect(status(r, 'claude-hook')).toBe('fail');
    expect(status(r, 'audit')).toBe('fail');
    expect(status(r, 'headed')).toBe('warn');
  });

  it('a bad approver certificate is a failure', async () => {
    const { sys, ctx } = healthyDev();
    sys.http_ = (url) =>
      url.endsWith('/mcp')
        ? { status: 401 }
        : { status: null, error: 'ERR_TLS_CERT_ALTNAME_INVALID', tlsError: true };
    const c = (await runChecks(ctx)).checks.find((x) => x.id === 'approver-origin');
    expect(c).toMatchObject({ status: 'fail' });
    expect(c?.detail).toContain('certificate not valid');
  });

  it('never reads a token file and never prints one', async () => {
    const { sys, ctx } = healthyDev();
    const r = await runChecks(ctx);
    expect(sys.reads).not.toContain(`${D}/host-token`);
    expect(sys.reads).not.toContain(`${D}/agents/${AGENT_ID}.token`);
    const text = `${formatReport(r)}${JSON.stringify(r)}`;
    expect(text).not.toContain(AGENT_TOKEN);
    expect(text).not.toContain('HOSTTOKEN-SECRET');
  });
});

describe('keyflap doctor (service mode)', () => {
  function healthyService(platform: 'linux' | 'darwin' = 'linux'): {
    sys: FakeSystem;
    ctx: ServiceDoctorContext;
    calls: string[];
  } {
    const sys = new FakeSystem();
    sys.uid = 0;
    sys.platform = platform;
    const P = servicePaths(platform);
    sys.dir(P.hookDir, 0o700, 1000);
    sys
      .socket(P.intentSocket, { uid: 1000 })
      .socket(P.adminSocket, { uid: 0 })
      .socket(P.signerAdminSocket, { uid: 0 });
    sys.dir(dirname(P.coreConfig), 0o755, 0);
    sys.file(P.approverConfig, JSON.stringify({ origin: 'https://b.tail1.ts.net:8766' }), 0o644, 0);
    sys.file(
      P.signerConfig,
      JSON.stringify({
        approverAddress: { origin: 'https://b.tail1.ts.net:8766', target: 'http://127.0.0.1:8766' },
      }),
      0o644,
      0,
    );
    sys.file(
      P.coreConfig,
      JSON.stringify({
        browser:
          platform === 'linux' ? { mode: 'xvfb' } : { mode: 'headless', channel: 'chromium' },
        passwordSource: null,
      }),
      0o644,
      0,
    );
    sys.file('/etc/passwd', 'u:x:1000:1000::/home/u:/bin/bash\n');
    sys.exec_ =
      platform === 'linux'
        ? () => ({ code: 0, stdout: 'active\n', stderr: '' })
        : (cmd) =>
            cmd === '/usr/bin/id'
              ? { code: 0, stdout: 'u:*:1000:1000::0:0:U:/home/u:/bin/zsh\n', stderr: '' }
              : { code: 0, stdout: 'system/x = {\n\tstate = running\n\tpid = 7\n}\n', stderr: '' };
    sys.http_ = (url) => (url.endsWith('/mcp') ? { status: 401 } : { status: 200 });
    sys.dir('/home/u/proj/.claude', 0o755);
    const cfg = {
      mcpUrl: 'http://127.0.0.1:8765/mcp',
      headersCommand: `/usr/local/bin/keyflap mcp-headers --agent ${AGENT_ID} --service`,
      hookCommand: `/usr/local/bin/keyflap hook claude-code --agent ${AGENT_ID} --service`,
      denyDir: P.hookDir,
      home: '/home/u',
    };
    sys.file(
      '/home/u/proj/.mcp.json',
      stringify(mergeMcp(undefined, mcpEntry(cfg)).doc),
      0o644,
      1000,
    );
    sys.file(
      '/home/u/proj/.claude/settings.local.json',
      stringify(mergeSettings(undefined, cfg).doc),
      0o644,
      1000,
    );
    sys.file(`${P.hookDir}/agent-${AGENT_ID}.token`, AGENT_TOKEN, 0o600, 1000);
    const calls: string[] = [];
    const ctx: ServiceDoctorContext = {
      mode: 'service',
      sys,
      project: '/home/u/proj',
      home: '/home/u',
      owner: { uid: 1000, gid: 1000 },
      paths: P,
      chromium: async () => ({ ok: true }),
      nodeVersion: '22.23.4',
      admin: async <T>(socket: string, op: string) => {
        calls.push(`${socket} ${op}`);
        const r: Record<string, unknown> = {
          status:
            socket === P.signerAdminSocket
              ? { approvers: 1, address: { kind: 'ok', checkedAt: 1 } }
              : { mcpUrl: 'http://127.0.0.1:8765/mcp', signer: 'ok' },
          'agent.list': { agents: [{ id: AGENT_ID, name: 'claude-code', revokedAt: null }] },
          'audit.verify': { text: 'Audit hash chain intact (5 entries).\n', intact: true },
          'password.list': { passwords: [{}] },
        };
        return r[op] as T;
      },
    };
    return { sys, ctx, calls };
  }

  it('a healthy install passes (as root)', async () => {
    const { ctx } = healthyService();
    const r = await runChecks(ctx);
    expect(r.checks.filter((c) => c.status !== 'ok')).toEqual([]);
  });

  it('an inactive unit fails; without root the admin checks are skipped, not failed', async () => {
    const { sys, ctx } = healthyService();
    sys.exec_ = (_c, args) => ({
      code: 3,
      stdout: args[1] === 'keyflap-core.service' ? 'failed\n' : 'active\n',
      stderr: '',
    });
    sys.uid = 1000;
    const r = await runChecks(ctx);
    expect(r.checks.find((c) => c.id === 'units')).toMatchObject({
      status: 'fail',
      detail: 'keyflap-core failed',
    });
    expect(status(r, 'root')).toBe('warn');
    expect(status(r, 'agents')).toBe('skip');
    expect(status(r, 'audit')).toBe('skip');
  });

  it('a socket with the wrong owner or mode fails', async () => {
    const { sys, ctx } = healthyService();
    sys.socket(SERVICE_PATHS.intentSocket, { uid: 1000, mode: 0o666 });
    const r = await runChecks(ctx);
    expect(status(r, 'sockets')).toBe('fail');
  });

  it('on macOS: launchd labels, launchctl print, and log files in every fix', async () => {
    const { sys, ctx } = healthyService('darwin');
    const r = await runChecks(ctx);
    expect(r.checks.find((c) => c.id === 'mode')?.detail).toBe('service mode (launchd)');
    expect(r.checks.find((c) => c.id === 'units')).toMatchObject({
      status: 'ok',
      detail: 'com.keyflap.signer, com.keyflap.core, com.keyflap.approver active',
    });
    expect(status(r, 'sockets')).toBe('ok');
    expect(r.checks.filter((c) => c.status !== 'ok')).toEqual([]);
    expect(r.checks.find((c) => c.id === 'headed')?.detail).toMatch(/new headless mode.*phone/);
    expect(sys.execs.map((e) => e.cmd)).not.toContain('systemctl');
    const text = JSON.stringify(r);
    expect(text).not.toMatch(/systemctl|journalctl|keyflap-core/);

    sys.exec_ = (cmd, args) =>
      cmd === '/usr/bin/id'
        ? { code: 0, stdout: 'u:*:1000:1000::0:0:U:/home/u:/bin/zsh\n', stderr: '' }
        : args[1] === 'system/com.keyflap.core'
          ? { code: 113, stdout: '', stderr: 'Could not find service\n' }
          : { code: 0, stdout: 'system/x = {\n\tstate = running\n}\n', stderr: '' };
    sys.socket(servicePaths('darwin').adminSocket, { uid: 1000 });
    const down = await runChecks(ctx);
    expect(down.checks.find((c) => c.id === 'units')).toMatchObject({
      status: 'fail',
      detail: 'com.keyflap.core not loaded',
      fix: 'sudo launchctl print system/com.keyflap.core; sudo launchctl print system/com.keyflap.signer; sudo launchctl print system/com.keyflap.approver; sudo tail -n 50 /Library/Keyflap/log/core/core.log',
    });
    expect(down.checks.find((c) => c.id === 'chromium')).toMatchObject({
      status: 'skip',
      detail: 'com.keyflap.core is not running',
    });
    expect(down.checks.find((c) => c.id === 'sockets')?.fix).toContain(
      'sudo launchctl bootout system/com.keyflap.core',
    );
  });

  it('on macOS every fix says sudo keyflap, as on Linux', async () => {
    const { sys, ctx } = healthyService('darwin');
    ctx.admin = async <T>(socket: string, op: string) => {
      const r: Record<string, unknown> = {
        status:
          socket === ctx.paths.signerAdminSocket
            ? { approvers: 0 }
            : { mcpUrl: 'http://127.0.0.1:8765/mcp', signer: 'ok' },
        'agent.list': { agents: [] },
        'audit.verify': { text: 'Audit hash chain BROKEN at seq 2.\n', intact: false },
        'password.list': { passwords: [] },
      };
      return r[op] as T;
    };
    const asRoot = await runChecks(ctx);
    expect(asRoot.checks.find((c) => c.id === 'phone')?.fix).toBe(
      'sudo keyflap setup (or sudo keyflap approver pair)',
    );
    sys.uid = 1000;
    const asUser = await runChecks(ctx);
    expect(asUser.checks.find((c) => c.id === 'root')?.fix).toBe('sudo keyflap doctor');
    for (const r of [asRoot, asUser]) {
      const fixes = r.checks.flatMap((c) => [c.fix ?? '', c.detail]).join('\n');
      expect(fixes).toContain('sudo keyflap');
      expect(fixes).not.toContain('/usr/local/bin/keyflap');
    }
  });

  describe('the approval address (invariant 5)', () => {
    const withAddress = (platform: 'linux' | 'darwin', address: unknown) => {
      const h = healthyService(platform);
      const inner = h.ctx.admin;
      h.ctx.admin = async <T>(socket: string, op: string, params?: Record<string, unknown>) => {
        if (socket === h.ctx.paths.signerAdminSocket && op === 'status') {
          return { approvers: 1, address } as T;
        }
        return inner<T>(socket, op, params);
      };
      return h;
    };
    const check = async (h: ReturnType<typeof healthyService>) =>
      (await runChecks(h.ctx)).checks.find((c) => c.id === 'approver-address');

    it('ok: says what is watched', async () => {
      expect(await check(withAddress('linux', { kind: 'ok', checkedAt: 5 }))).toEqual({
        id: 'approver-address',
        status: 'ok',
        detail:
          'approval address ok (https://b.tail1.ts.net:8766 -> http://127.0.0.1:8766, watched)',
      });
    });

    it('wrong: fails with what was seen and the two steps, serve then pair', async () => {
      const c = await check(
        withAddress('linux', {
          kind: 'latched',
          at: Date.UTC(2026, 9, 30, 8),
          seen: 'b.tail1.ts.net:8766 proxies to http://127.0.0.1:9999',
        }),
      );
      expect(c).toEqual({
        id: 'approver-address',
        status: 'fail',
        detail:
          'approval address off: it was changed at 2026-10-30T08:00:00.000Z (b.tail1.ts.net:8766 proxies to http://127.0.0.1:9999), so phones were signed out to be safe',
        fix: 'sudo tailscale serve --bg --https=8766 http://127.0.0.1:8766, then sudo keyflap approver pair',
      });
    });

    it('tripped, and right again now: fails with one step, pair again', async () => {
      const c = await check(
        withAddress('linux', {
          kind: 'latched',
          at: Date.UTC(2026, 9, 30, 8),
          seen: 'b.tail1.ts.net:8766 proxies to http://127.0.0.1:9999',
          latest: { checkedAt: Date.UTC(2026, 9, 30, 9), verdict: { kind: 'ok' } },
        }),
      );
      expect(c).toEqual({
        id: 'approver-address',
        status: 'fail',
        detail:
          'approval address off: it was changed at 2026-10-30T08:00:00.000Z (b.tail1.ts.net:8766 proxies to http://127.0.0.1:9999), so phones were signed out to be safe. It is right again now',
        fix: 'pair your phone again to turn approvals back on: sudo keyflap approver pair',
      });
    });

    it('a short pause while Tailscale restarts is a warning that needs nothing done', async () => {
      const now = Date.now();
      const c = await check(
        withAddress('darwin', {
          kind: 'paused',
          since: now,
          detail: "Tailscale's token cannot be read",
          graceUntil: now + 60_000,
        }),
      );
      expect(c).toEqual({
        id: 'approver-address',
        status: 'warn',
        detail: 'approval address waiting for Tailscale: Tailscale is not answering yet',
        fix: 'wait a moment: approvals resume by themselves once Tailscale answers',
      });
    });

    it('unreadable: fails with the detail, and the fix that matches it', async () => {
      const paused = (detail: string) => ({ kind: 'paused', since: 1, detail });
      const app = '/Applications/Tailscale.app/Contents/MacOS/Tailscale';
      const refused = `tailscale is not trusted: ${app} is not in a system bin directory or /opt/keyflap/tools/tailscale/`;
      const h = withAddress('darwin', paused(refused));
      h.sys.file(app, '', 0o755, 0);
      expect(await check(h)).toMatchObject({
        status: 'fail',
        detail: `approval address unreadable: ${refused}`,
        fix: "re-run packages/install/macos/install.sh with the same options: it lets the signer read Tailscale's setting. It needs the standalone Tailscale app (tailscale.com/download) or tailscaled; the App Store app can't be read",
      });
      expect(
        await check(withAddress('darwin', paused("Tailscale's token cannot be read"))),
      ).toMatchObject({
        status: 'fail',
        detail: "approval address unreadable: Tailscale's token cannot be read",
        fix: expect.stringMatching(/^re-run packages\/install\/macos\/install\.sh /),
      });
      expect(
        await check(
          withAddress(
            'darwin',
            paused('tailscale is not trusted: /Library/Tailscale/ipnport is owned by uid 501'),
          ),
        ),
      ).toMatchObject({
        status: 'fail',
        fix: expect.stringMatching(/^re-run packages\/install\/macos\/install\.sh /),
      });
      expect(await check(withAddress('darwin', paused('Tailscale is not running')))).toMatchObject({
        status: 'fail',
        detail: 'approval address unreadable: Tailscale is not running',
        fix: 'start Tailscale (open the Tailscale app and connect), then sudo keyflap doctor',
      });
      expect(
        await check(
          withAddress('linux', paused('tailscale is not trusted: /usr/bin/tailscale is mode 0777')),
        ),
      ).toMatchObject({
        status: 'fail',
        fix: 'install Tailscale at a root-only path (/usr/bin/tailscale), then re-run packages/install/linux/install.sh with --tailscale-bin /usr/bin/tailscale',
      });
      expect(
        await check(withAddress('linux', paused('no tailscale CLI configured'))),
      ).toMatchObject({
        status: 'fail',
        fix: 'install Tailscale at a root-only path (/usr/bin/tailscale), then re-run packages/install/linux/install.sh with --tailscale-bin /usr/bin/tailscale',
      });
      expect(await check(withAddress('linux', paused('tailscale cannot be run')))).toMatchObject({
        status: 'fail',
        fix: 'install Tailscale at a root-only path (/usr/bin/tailscale), then re-run packages/install/linux/install.sh with --tailscale-bin /usr/bin/tailscale',
      });
      expect(await check(withAddress('linux', paused('tailscale exited 1')))).toMatchObject({
        status: 'fail',
        fix: 'start Tailscale (tailscale up), then sudo keyflap doctor',
      });
    });

    it('not watched: a warning that says why, never silently ok', async () => {
      expect(await check(withAddress('linux', { kind: 'unwatched' }))).toMatchObject({
        status: 'warn',
        detail: "Keyflap can't watch this address: it isn't a Tailscale name",
      });
    });

    it('on a Mac without a root-only tailscale, the steps name the app CLI; anything but a wrong proxy resets serve first', async () => {
      const app = '/Applications/Tailscale.app/Contents/MacOS/Tailscale';
      const h = withAddress('darwin', {
        kind: 'latched',
        at: 0,
        seen: 'b.tail1.ts.net:8766 also handles /x',
      });
      h.sys.file(app, '', 0o755, 0);
      expect((await check(h))?.fix).toBe(
        `${app} serve reset (it clears every serve setting on this computer), then ${app} serve --bg --https=8766 http://127.0.0.1:8766, then sudo keyflap approver pair`,
      );
      h.sys.http_ = (url) =>
        url.endsWith('/mcp') ? { status: 401 } : { status: null, error: 'x' };
      const origin = (await runChecks(h.ctx)).checks.find((c) => c.id === 'approver-origin');
      expect(origin?.fix).toBe(
        '/Applications/Tailscale.app/Contents/MacOS/Tailscale serve --bg --https=8766 http://127.0.0.1:8766',
      );
    });

    it('without root it is skipped like the other admin checks', async () => {
      const h = healthyService();
      h.sys.uid = 1000;
      expect(await check(h)).toMatchObject({ status: 'skip' });
    });
  });
});

describe('keyflap mcp-headers', () => {
  it('reads only a private, well-formed token file of ours', () => {
    const dir = tmpDir();
    const f = join(dir, 't');
    writeFileSync(f, `${AGENT_TOKEN}\n`, { mode: 0o600 });
    expect(readAgentToken(f)).toBe(AGENT_TOKEN);
    chmodSync(f, 0o644);
    expect(() => readAgentToken(f)).toThrow(/accessible to others/);
    chmodSync(f, 0o600);
    expect(() => readAgentToken(f, 4242)).toThrow(/another user/);
    writeFileSync(f, 'not-a-token', { mode: 0o600 });
    expect(() => readAgentToken(f)).toThrow(/malformed/);
  });

  it('prints only the header JSON; on failure nothing on stdout and exit 1', async () => {
    const dir = tmpDir();
    mkdirSync(join(dir, 'agents'), { mode: 0o700 });
    writeFileSync(join(dir, 'agents', `${AGENT_ID}.token`), `${AGENT_TOKEN}\n`, { mode: 0o600 });
    const ok = await runCli(['mcp-headers', '--agent', AGENT_ID, '--data-dir', dir]);
    expect(ok.code).toBe(0);
    expect(JSON.parse(ok.stdout)).toEqual({ Authorization: `Bearer ${AGENT_TOKEN}` });
    expect(ok.stderr).toBe('');
    const missing = await runCli([
      'mcp-headers',
      '--agent',
      '11111111-1111-4111-8111-111111111111',
      '--data-dir',
      dir,
    ]);
    expect(missing.code).toBe(1);
    expect(missing.stdout).toBe('');
    expect(missing.stderr).toMatch(/cannot read the agent token/);
    const bad = await runCli(['mcp-headers', '--agent', '../../etc/passwd', '--data-dir', dir]);
    expect(bad.code).toBe(1);
    expect(bad.stdout).toBe('');
  });
});

describe('keyflap doctor (dev mode): hook code in an agent project (security review L10)', () => {
  const state = (project: string | null): SetupState => ({
    ...emptyState(8765),
    claudeCode: [{ agentId: 'a', scope: project ? 'project' : 'user', project }],
  });
  it('warns when a Claude Code project contains the checkout or lies inside it', () => {
    const base = { home: '/home/u', state: state(null) };
    expect(hookCodeCheck({ ...base, project: '/home/u/src' }, '/home/u/src/keyflap')?.status).toBe(
      'warn',
    );
    expect(
      hookCodeCheck({ ...base, project: '/home/u/src/keyflap/packages' }, '/home/u/src/keyflap')
        ?.fix,
    ).toContain('~/src/keyflap');
    expect(
      hookCodeCheck(
        { home: '/home/u', project: '/tmp', state: state('/home/u/src') },
        '/home/u/src/keyflap',
      )?.status,
    ).toBe('warn');
  });
  it('is quiet for projects elsewhere (a sibling with a common prefix too)', () => {
    expect(
      hookCodeCheck(
        { home: '/home/u', project: '/home/u/src/keyflap-site', state: state('/home/u/work') },
        '/home/u/src/keyflap',
      ),
    ).toBeNull();
  });
});
