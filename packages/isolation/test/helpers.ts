import { inject } from 'vitest';
import { attachContainer, type Runtime } from './container.ts';
import type { IsolationEnv } from './global-setup.ts';
import { darwinHost, type Host, L, type Os, servicePids } from './platform.ts';
import type { Attempt, Outcome } from './probe/attempt.ts';

export const env: IsolationEnv = inject('isolation');
export const skipReason = env.skip;
export const where = skipReason ?? env.runtime;
export const whereOn = (os: Os) =>
  L.os === os ? where : `${os === 'darwin' ? 'macOS' : 'Linux'} only`;

export function host(): Host {
  if (L.os === 'darwin') return darwinHost();
  return attachContainer(env.runtime as Runtime, env.container as string);
}

export function probe(attempts: Attempt[], user = L.agentUser): Outcome[] {
  const r = host().as(user, [L.node, `${L.probeDir}/attempt.ts`, JSON.stringify(attempts)], {
    timeoutMs: 120_000,
  });
  if (r.status !== 0) throw new Error(`probe failed: ${r.stderr}`);
  return JSON.parse(r.stdout) as Outcome[];
}

export function outcomes(attempts: Record<string, Attempt>, user?: string): Record<string, string> {
  const labels = Object.keys(attempts);
  const res = probe(Object.values(attempts), user);
  return Object.fromEntries(labels.map((l, i) => [l, res[i]?.ok ? 'ok' : (res[i]?.code ?? '?')]));
}

export function ptrace(pids: number[]): Record<string, string> {
  const r = host().as(L.agentUser, ['python3', `${L.probeDir}/ptrace.py`, ...pids.map(String)]);
  if (r.status !== 0) throw new Error(`ptrace probe failed: ${r.stderr}`);
  return JSON.parse(r.stdout) as Record<string, string>;
}

export interface ProcessView {
  vmmap: string;
  sample: string;
  lsof: string;
  signal: string;
  environment: string;
  taskForPid: string;
}

export function inspectProcesses(
  pids: number[],
  user = L.agentUser,
): { control: ProcessView; targets: Record<string, ProcessView> } {
  const r = host().as(user, [L.node, `${L.probeDir}/darwin-process.ts`, ...pids.map(String)], {
    timeoutMs: 180_000,
  });
  if (r.status !== 0) throw new Error(`process probe failed: ${r.stderr}`);
  return JSON.parse(r.stdout) as { control: ProcessView; targets: Record<string, ProcessView> };
}

export interface Pids {
  core: number;
  signer: number;
  approver: number;
  chromium: number;
  xvfb: number;
}

export function pids(): Pids {
  const h = host();
  const pidOf = (args: string[]) =>
    Number(h.exec(['pgrep', '-o', ...args], { check: true }).stdout.trim());
  const services = servicePids(h);
  if (L.os === 'darwin') {
    return {
      ...services,
      chromium: pidOf([
        '-u',
        L.users.core,
        '-f',
        'Google Chrome for Testing.*remote-debugging-pipe',
      ]),
      xvfb: 0,
    };
  }
  return {
    ...services,
    chromium: pidOf([
      '-u',
      'keyflap-core',
      '-f',
      'chrome-linux64/chrome .*--remote-debugging-pipe',
    ]),
    xvfb: pidOf(['-u', 'keyflap-core', 'Xvfb']),
  };
}

export function phoneDecisions(): { event: string; shown?: string }[] {
  return host()
    .exec(['cat', env.phoneLog as string], { check: true })
    .stdout.trim()
    .split('\n')
    .map((l) => JSON.parse(l) as { event: string; shown?: string });
}
