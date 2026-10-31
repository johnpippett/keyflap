import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';

export type Runtime = 'podman' | 'docker';

export const IMAGE_DIR = join(import.meta.dirname, '..', 'container');
export const REPO = join(import.meta.dirname, '..', '..', '..');
export const NODE = '/opt/keyflap/node/bin/node';
export const PROBE_DIR = '/src/packages/isolation/test/probe';
export const AGENT_USER = 'agentuser';

export function detectRuntime(): Runtime | null {
  const wanted = process.env.KEYFLAP_ISOLATION_RUNTIME;
  const candidates: Runtime[] =
    wanted === 'podman' || wanted === 'docker' ? [wanted] : ['podman', 'docker'];
  for (const rt of candidates) {
    const r = spawnSync(rt, ['info'], { stdio: 'ignore', timeout: 30_000 });
    if (r.status === 0) return rt;
  }
  return null;
}

export function imageTag(): string {
  const h = createHash('sha256')
    .update(readFileSync(join(IMAGE_DIR, 'Containerfile')))
    .digest('hex')
    .slice(0, 12);
  return `localhost/keyflap-isolation:${h}`;
}

export function ensureImage(rt: Runtime): string {
  const tag = imageTag();
  const exists = spawnSync(rt, ['image', 'inspect', tag], { stdio: 'ignore' }).status === 0;
  if (!exists) {
    execFileSync(
      rt,
      ['build', '-q', '-t', tag, '-f', join(IMAGE_DIR, 'Containerfile'), IMAGE_DIR],
      {
        stdio: ['ignore', 'ignore', 'inherit'],
        timeout: 15 * 60_000,
      },
    );
  }
  return tag;
}

export function hostNodeDir(): string {
  if (!process.version.startsWith('v22.')) throw new Error('run the isolation tests with Node 22');
  return dirname(dirname(realpathSync(process.execPath)));
}

export const CHROMIUM_REVISION = '1248';

export function hostBrowsersDir(): string {
  const dir =
    process.env.PLAYWRIGHT_BROWSERS_PATH ||
    join(process.env.HOME ?? '/root', '.cache', 'ms-playwright');
  if (
    !existsSync(join(dir, `chromium-${CHROMIUM_REVISION}`)) ||
    !existsSync(join(dir, `chromium_headless_shell-${CHROMIUM_REVISION}`))
  ) {
    throw new Error(
      `no Playwright Chromium ${CHROMIUM_REVISION} in ${dir}: run pnpm --filter @aab/shim exec playwright install chromium`,
    );
  }
  return dir;
}

export interface Container {
  rt: Runtime;
  name: string;
  exec(cmd: string[], opts?: { input?: string; timeoutMs?: number; check?: boolean }): ExecResult;
  as(user: string, cmd: string[], opts?: { input?: string; timeoutMs?: number }): ExecResult;
  remove(): void;
}

export interface ExecResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

export function startContainer(
  rt: Runtime,
  image: string,
  mounts: { bundle: string; release: string; node: string; browsers: string },
): Container {
  const name = `keyflap-isolation-${process.pid}-${Date.now().toString(36)}`;
  const flags =
    rt === 'podman'
      ? ['--systemd=always', '--cap-add', 'SYS_ADMIN']
      : [
          '--privileged',
          '--cgroupns=private',
          '--tmpfs',
          '/run',
          '--tmpfs',
          '/run/lock',
          '--tmpfs',
          '/tmp',
        ];
  execFileSync(
    rt,
    [
      'run',
      '-d',
      '--name',
      name,
      ...flags,
      '-v',
      `${mounts.bundle}:/mnt/bundle:ro`,
      '-v',
      `${mounts.release}:/mnt/release:ro`,
      '-v',
      `${REPO}:/src:ro`,
      '-v',
      `${mounts.node}:/mnt/node:ro`,
      '-v',
      `${mounts.browsers}:/mnt/browsers:ro`,
      image,
      '/sbin/init',
    ],
    { stdio: ['ignore', 'ignore', 'inherit'] },
  );
  return attachContainer(rt, name);
}

export function attachContainer(rt: Runtime, name: string): Container {
  const exec: Container['exec'] = (cmd, opts = {}) => {
    const r = spawnSync(rt, ['exec', ...(opts.input !== undefined ? ['-i'] : []), name, ...cmd], {
      input: opts.input,
      encoding: 'utf8',
      timeout: opts.timeoutMs ?? 120_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    const res = { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
    if (opts.check && res.status !== 0) {
      throw new Error(`${cmd.join(' ')} failed (${res.status}): ${res.stderr || res.stdout}`);
    }
    return res;
  };
  return {
    rt,
    name,
    exec,
    as: (user, cmd, opts) => exec(['runuser', '-u', user, '--', ...cmd], opts),
    remove() {
      spawnSync(rt, ['rm', '-f', name], { stdio: 'ignore', timeout: 60_000 });
    },
  };
}
