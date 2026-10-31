import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TestProject } from 'vitest/node';
import {
  AGENT_USER,
  CHROMIUM_REVISION,
  type Container,
  detectRuntime,
  ensureImage,
  hostBrowsersDir,
  hostNodeDir,
  NODE,
  PROBE_DIR,
  REPO,
  startContainer,
} from './container.ts';
import { FAKE_TAILSCALE, plantFakeTailscale } from './fake-tailscale.ts';
import { PHONE_LOG, pairProbePhone, waitFor } from './pair.ts';
import { setupDarwin } from './setup-darwin.ts';

export interface DarwinRelease {
  name: string;
  dir: string;
  sums: string;
  installedVersion: string;
  install: string;
  linuxOnly: { status: number | null; stderr: string; untouched: boolean };
  fromHome: { dir: string; status: number | null; stderr: string; untouched: boolean };
  upgrade: {
    stdout: string;
    before: InstallSnapshot;
    after: InstallSnapshot;
    agents: string;
    approvers: string;
    agentToken: { kept: boolean; mode: string; owner: string };
    plantedGone: boolean;
    versionGone: boolean;
  };
  reinstall: {
    uninstall: string;
    uninstallStatus: number | null;
    gone: string;
    kept: string;
    reinstall: string;
    kekKept: boolean;
    agents: string;
    approvers: string;
    tokenKept: boolean;
  };
}

export interface IsolationEnv {
  skip: string | null;
  runtime?: string;
  os?: 'linux' | 'darwin';
  phoneLog?: string;
  probeUid?: number;
  otherUser?: string;
  stage?: string;
  darwin?: DarwinRelease;
  container?: string;
  agentId?: string;
  agentToken?: string;
  mcpUrl?: string;
  rpUrl?: string;
  pids?: { core: number; signer: number; chromium: number; xvfb: number };
  yamaPtraceScope?: string;
  release?: {
    name: string;
    sums: string;
    installedVersion: string;
    install: string;
    noXvfb: { status: number | null; stderr: string; untouched: boolean };
    fromHome: { status: number | null; stderr: string; untouched: boolean };
    upgrade: {
      stdout: string;
      before: InstallSnapshot;
      after: InstallSnapshot;
      agents: string;
      approvers: string;
      agentToken: { kept: boolean; mode: string; owner: string };
      plantedGone: boolean;
    };
  };
}

export interface InstallSnapshot {
  kek: string;
  channelKey: string;
  corePid: number;
  signerPid: number;
}

const RELEASE_VERSION = '0.0.0-isolation';

declare module 'vitest' {
  export interface ProvidedContext {
    isolation: IsolationEnv;
  }
}

function pidOf(c: Container, args: string[]): number {
  const r = c.exec(['pgrep', '-o', ...args], { check: true });
  return Number(r.stdout.trim());
}

export default async function setup(project: TestProject) {
  const skip = (reason: string) => {
    if (process.env.KEYFLAP_ISOLATION_REQUIRED === '1')
      throw new Error(`isolation tests: ${reason}`);
    project.provide('isolation', { skip: reason });
  };
  if (process.platform === 'darwin') {
    return setupDarwin((env) => project.provide('isolation', env), skip);
  }
  if (process.platform !== 'linux') return skip('needs Linux or macOS');
  const rt = detectRuntime();
  if (!rt) return skip('needs podman or docker');

  const image = ensureImage(rt);
  const work = mkdtempSync(join(tmpdir(), 'keyflap-isolation-'));
  const bundle = join(work, 'bundle');
  const release = join(work, 'release');
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
  const buildBundle = join(REPO, 'packages/install/linux/build-bundle.sh');
  execFileSync(
    'bash',
    [buildBundle, '--release', release, '--arch', arch, '--version', RELEASE_VERSION],
    { stdio: ['ignore', 'ignore', 'inherit'], timeout: 10 * 60_000 },
  );
  execFileSync('bash', [buildBundle, bundle], { stdio: ['ignore', 'ignore', 'inherit'] });
  const c = startContainer(rt, image, {
    bundle,
    release,
    node: hostNodeDir(),
    browsers: hostBrowsersDir(),
  });
  const teardown = () => {
    if (process.env.KEYFLAP_ISOLATION_KEEP !== '1') c.remove();
    rmSync(work, { recursive: true, force: true });
  };
  try {
    waitFor(
      c,
      'systemd',
      ['systemctl', 'is-system-running'],
      (o) => /running|degraded/.test(o),
      60_000,
    );
    c.exec(['mount', '--make-rshared', '/'], { check: true });

    const name = `keyflap-${RELEASE_VERSION}-linux-${arch}`;
    c.exec(['install', '-d', '-m', '0700', '/root/release'], { check: true });
    c.exec(['cp', `/mnt/release/${name}.tar.xz`, '/mnt/release/SHA256SUMS', '/root/release/'], {
      check: true,
    });
    const sums = c.exec(['sh', '-c', 'cd /root/release && sha256sum -c SHA256SUMS'], {
      check: true,
    }).stdout;
    c.exec(['tar', '-xJf', `/root/release/${name}.tar.xz`, '-C', '/root/release'], {
      check: true,
    });
    const releaseInstall = [
      `/root/release/${name}/install.sh`,
      '--user',
      AGENT_USER,
      '--approver-origin',
      'http://approver.localhost:8766',
      '--high-risk',
      'rp.localhost',
      '--browsers-dir',
      '/root/browsers',
    ];
    c.exec(['install', '-d', '-m', '0700', '/root/browsers'], { check: true });
    c.exec(
      [
        'cp',
        '-r',
        `/mnt/browsers/chromium-${CHROMIUM_REVISION}`,
        `/mnt/browsers/chromium_headless_shell-${CHROMIUM_REVISION}`,
        '/root/browsers/',
      ],
      { check: true, timeoutMs: 5 * 60_000 },
    );

    c.exec(['cp', '-r', `/root/release/${name}`, `/home/${AGENT_USER}/rel`], { check: true });
    c.exec(['chown', '-R', `${AGENT_USER}:`, `/home/${AGENT_USER}/rel`], { check: true });
    const fromHome = c.exec([`/home/${AGENT_USER}/rel/install.sh`, ...releaseInstall.slice(1)], {
      timeoutMs: 60_000,
    });
    const fromHomeUntouched =
      c.exec(['sh', '-c', 'test ! -e /opt/keyflap && test ! -e /etc/keyflap && ! id keyflap-core'])
        .status === 0;
    c.exec(['rm', '-rf', `/home/${AGENT_USER}/rel`], { check: true });

    c.exec(['mv', '/usr/bin/Xvfb', '/usr/bin/Xvfb.off'], { check: true });
    const noXvfb = c.exec(releaseInstall, { timeoutMs: 60_000 });
    const untouched =
      c.exec(['sh', '-c', 'test ! -e /opt/keyflap && test ! -e /etc/keyflap && ! id keyflap-core'])
        .status === 0;
    c.exec(['mv', '/usr/bin/Xvfb.off', '/usr/bin/Xvfb'], { check: true });

    const install = c.exec(releaseInstall, { timeoutMs: 10 * 60_000 });
    if (install.status !== 0) {
      throw new Error(`release install.sh failed:\n${install.stdout}\n${install.stderr}`);
    }
    const waitReady = () =>
      waitFor(
        c,
        'keyflap-core',
        ['keyflap', 'status', '--json'],
        (o) => o.includes('"signer": "ok"'),
        90_000,
      );
    waitReady();
    const installedVersion = c.exec(['cat', '/opt/keyflap/app/VERSION'], { check: true }).stdout;

    c.exec(
      [
        'systemd-run',
        '--unit=test-rp',
        '--property=WorkingDirectory=/',
        NODE,
        `${PROBE_DIR}/rp.ts`,
      ],
      { check: true },
    );
    pairProbePhone(c, PHONE_LOG);

    const added = c.exec(['keyflap', 'agent', 'add', 'isolation-agent'], { check: true }).stdout;
    const agentId = /\(id ([0-9a-f-]{36})\)/.exec(added)?.[1];
    const agentToken = /(aab_agent_[A-Za-z0-9_-]{43})/.exec(added)?.[1];
    if (!agentId || !agentToken) throw new Error('agent add printed no id/token');
    c.exec(['keyflap', 'sessions', 'keep', 'rp.localhost', '--agent', agentId], { check: true });

    const hookDir = '/var/lib/keyflap/hook';
    const tokenFile = `${hookDir}/agent-${agentId}.token`;
    c.as(AGENT_USER, ['sh', '-c', `umask 077; cat >${tokenFile}`], { input: `${agentToken}\n` });
    c.as(AGENT_USER, [
      'ln',
      '-s',
      '/etc/keyflap/credentials/kek.cred',
      `${hookDir}/agent-00000000-0000-4000-8000-000000000001.token`,
    ]);
    c.as(AGENT_USER, [
      'sh',
      '-c',
      `echo not-a-token >${hookDir}/agent-00000000-0000-4000-8000-000000000002.token`,
    ]);

    c.exec(['cp', '-r', '/src/packages/install/linux', '/root/installer'], { check: true });
    c.exec(['cp', '-r', '/mnt/bundle', '/root/bundle'], { check: true, timeoutMs: 5 * 60_000 });
    c.exec(['cp', '-rL', '/mnt/node', '/root/node'], { check: true, timeoutMs: 5 * 60_000 });
    const sha = (path: string) =>
      c.exec(['sha256sum', path], { check: true }).stdout.split(' ')[0] ?? '';
    const mainPid = (unit: string) =>
      Number(
        c
          .exec(['systemctl', 'show', '-p', 'MainPID', '--value', unit], { check: true })
          .stdout.trim(),
      );
    const before = {
      kek: sha('/etc/keyflap/credentials/kek.cred'),
      channelKey: sha('/etc/keyflap/credentials/channel-key.cred'),
      corePid: mainPid('keyflap-core.service'),
      signerPid: mainPid('keyflap-signer.service'),
    };
    plantFakeTailscale(c);
    const upgrade = c.exec(
      [
        'bash',
        '/root/installer/install.sh',
        '--bundle',
        '/root/bundle',
        '--user',
        AGENT_USER,
        '--approver-origin',
        'http://approver.localhost:8766',
        '--high-risk',
        'rp.localhost',
        '--node-dir',
        '/root/node',
        '--tailscale-bin',
        FAKE_TAILSCALE,
      ],
      { timeoutMs: 10 * 60_000 },
    );
    if (upgrade.status !== 0) {
      throw new Error(`upgrade install.sh failed:\n${upgrade.stdout}\n${upgrade.stderr}`);
    }
    waitReady();
    const after = {
      kek: sha('/etc/keyflap/credentials/kek.cred'),
      channelKey: sha('/etc/keyflap/credentials/channel-key.cred'),
      corePid: mainPid('keyflap-core.service'),
      signerPid: mainPid('keyflap-signer.service'),
    };
    const releaseFacts: IsolationEnv['release'] = {
      name,
      sums,
      installedVersion: installedVersion.trim(),
      install: install.stdout,
      noXvfb: { status: noXvfb.status, stderr: noXvfb.stderr, untouched },
      fromHome: { status: fromHome.status, stderr: fromHome.stderr, untouched: fromHomeUntouched },
      upgrade: {
        stdout: upgrade.stdout,
        before,
        after,
        agents: c.exec(['keyflap', 'agent', 'list'], { check: true }).stdout,
        approvers: c.exec(['keyflap', 'approver', 'list'], { check: true }).stdout,
        agentToken: {
          kept: c.exec(['cat', tokenFile]).stdout === `${agentToken}\n`,
          mode: c.exec(['stat', '-c', '%a', tokenFile]).stdout.trim(),
          owner: c.exec(['stat', '-c', '%U', tokenFile]).stdout.trim(),
        },
        plantedGone:
          c.exec(['sh', '-c', `ls ${hookDir} | grep -c 00000000-0000-4000-8000`]).stdout.trim() ===
          '0',
      },
    };

    const status = JSON.parse(c.exec(['keyflap', 'status', '--json'], { check: true }).stdout) as {
      service: { core: { mcpUrl: string } };
    };

    const sysPid = (unit: string) =>
      Number(
        c
          .exec(['systemctl', 'show', '-p', 'MainPID', '--value', unit], { check: true })
          .stdout.trim(),
      );
    const env: IsolationEnv = {
      skip: null,
      runtime: rt,
      os: 'linux',
      phoneLog: PHONE_LOG,
      container: c.name,
      agentId,
      agentToken,
      mcpUrl: status.service.core.mcpUrl,
      rpUrl: 'http://rp.localhost:3000/',
      pids: {
        core: sysPid('keyflap-core.service'),
        signer: sysPid('keyflap-signer.service'),
        chromium: pidOf(c, [
          '-u',
          'keyflap-core',
          '-f',
          'chrome-linux64/chrome .*--remote-debugging-pipe',
        ]),
        xvfb: pidOf(c, ['-u', 'keyflap-core', 'Xvfb']),
      },
      yamaPtraceScope: c.exec(['cat', '/proc/sys/kernel/yama/ptrace_scope']).stdout.trim(),
      release: releaseFacts,
    };
    project.provide('isolation', env);
  } catch (err) {
    const logs = c.exec(['journalctl', '--no-pager', '-n', '80', '-o', 'cat']).stdout;
    teardown();
    throw new Error(`${(err as Error).message}\n--- journal ---\n${logs}`);
  }
  return teardown;
}
