import { execFile } from 'node:child_process';

const PS_BIN = '/bin/ps';

export function staleBrowserPids(
  psLines: string,
  opts: { browsersPath: string; selfPid: number },
): number[] {
  const prefix = opts.browsersPath.endsWith('/') ? opts.browsersPath : `${opts.browsersPath}/`;
  const pids: number[] = [];
  for (const raw of psLines.split('\n')) {
    const m = /^\s*(\d+)\s+(.*)$/.exec(raw);
    if (!m) continue;
    const pid = Number(m[1]);
    const command = m[2] as string;
    if (pid === opts.selfPid || !command.startsWith(prefix)) continue;
    pids.push(pid);
  }
  return pids;
}

export async function killStaleBrowsers(opts: {
  browsersPath: string;
  uid: number;
  selfPid?: number;
  log?: (line: string) => void;
}): Promise<number[]> {
  const psLines = await new Promise<string>((resolve) => {
    execFile(
      PS_BIN,
      ['-o', 'pid=,command=', '-u', String(opts.uid)],
      { timeout: 5_000, maxBuffer: 4 * 1024 * 1024 },
      (_err, stdout) => resolve(stdout ?? ''),
    );
  });
  const pids = staleBrowserPids(psLines, {
    browsersPath: opts.browsersPath,
    selfPid: opts.selfPid ?? process.pid,
  });
  const killed: number[] = [];
  for (const pid of pids) {
    try {
      process.kill(pid, 'SIGKILL');
      killed.push(pid);
    } catch {}
  }
  if (killed.length > 0) {
    opts.log?.(
      `keyflap-core: killed ${killed.length} stale browser process(es) left from an earlier run`,
    );
  }
  return killed;
}
