import { spawn } from 'node:child_process';

export type Task = { name: string; command: string; args: string[] };
export type TaskResult = { name: string; ok: boolean; output: string; seconds: number };

export function packageScriptTask(script: string, npmExecPath: string | undefined): Task {
  const args = ['--silent', 'run', script];
  return npmExecPath
    ? { name: script, command: process.execPath, args: [npmExecPath, ...args] }
    : { name: script, command: 'pnpm', args };
}

export function runTask(task: Task): Promise<TaskResult> {
  const started = performance.now();
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const child = spawn(task.command, task.args, { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (c: Buffer) => chunks.push(c));
    child.stderr.on('data', (c: Buffer) => chunks.push(c));
    const finish = (ok: boolean, extra = '') =>
      resolve({
        name: task.name,
        ok,
        output: Buffer.concat(chunks).toString('utf8') + extra,
        seconds: (performance.now() - started) / 1000,
      });
    child.on('error', (err) => finish(false, `${err.message}\n`));
    child.on('close', (code, signal) => finish(code === 0 && signal === null));
  });
}

export async function runAllInParallel(
  tasks: Task[],
  report: (result: TaskResult) => void,
): Promise<boolean> {
  const results = await Promise.all(
    tasks.map((t) =>
      runTask(t).then((r) => {
        report(r);
        return r;
      }),
    ),
  );
  return results.every((r) => r.ok);
}
