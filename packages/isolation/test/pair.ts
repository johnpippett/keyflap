import { execFileSync } from 'node:child_process';
import { NODE, PROBE_DIR } from './container.ts';
import type { Host } from './platform.ts';

export const KEYFLAP = '/usr/local/bin/keyflap';
export const PHONE_UNIT = 'test-phone';
export const PHONE_LOG = '/root/phone.log';

export function waitFor(
  c: Host,
  what: string,
  cmd: string[],
  ok: (out: string) => boolean,
  ms: number,
): string {
  const deadline = Date.now() + ms;
  let last = '';
  while (Date.now() < deadline) {
    const r = c.exec(cmd, { timeoutMs: 30_000 });
    last = r.stdout + r.stderr;
    if (r.status === 0 && ok(r.stdout)) return r.stdout;
    execFileSync('sleep', ['0.5']);
  }
  throw new Error(`timed out waiting for ${what}: ${last.slice(-2000)}`);
}

const pairedLines = (log: string) => (log.match(/"paired"/g) ?? []).length;

export function pairProbePhone(c: Host, log = PHONE_LOG): string {
  c.exec(['systemctl', 'stop', `${PHONE_UNIT}.service`]);
  c.exec(['systemctl', 'reset-failed', `${PHONE_UNIT}.service`]);
  const pair = c.exec([KEYFLAP, 'approver', 'pair'], { check: true }).stdout;
  const url = /(http:\/\/approver\.localhost:8766\/pair#[A-Za-z0-9_-]+)/.exec(pair)?.[1];
  if (!url) throw new Error(`no pairing URL in: ${pair}`);
  const before = pairedLines(c.exec(['cat', log]).stdout);
  c.exec(
    [
      'systemd-run',
      `--unit=${PHONE_UNIT}`,
      '--collect',
      '--setenv=PLAYWRIGHT_BROWSERS_PATH=/opt/keyflap/browsers',
      NODE,
      `${PROBE_DIR}/phone.ts`,
      url,
      log,
    ],
    { check: true },
  );
  waitFor(c, 'phone pairing', ['cat', log], (o) => pairedLines(o) > before, 60_000);
  return url;
}
