import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { packageScriptTask, runAllInParallel, type TaskResult } from './parallel.ts';

const node = (name: string, code: string) => ({
  name,
  command: process.execPath,
  args: ['-e', code],
});

describe('running checks in parallel', () => {
  it('passes only when every task passes, and reports each one with its output', async () => {
    const seen: TaskResult[] = [];
    const ok = await runAllInParallel(
      [
        node('passes', 'process.stdout.write("fine")'),
        node('fails', 'process.stderr.write("broken"); process.exit(3)'),
      ],
      (r) => seen.push(r),
    );
    expect(ok).toBe(false);
    const byName = Object.fromEntries(seen.map((r) => [r.name, r]));
    expect(byName.passes).toMatchObject({ ok: true, output: 'fine' });
    expect(byName.fails).toMatchObject({ ok: false, output: 'broken' });
  });

  it('a task killed by a signal or that cannot start is a failure', async () => {
    const seen: TaskResult[] = [];
    const ok = await runAllInParallel(
      [
        node('killed', 'process.kill(process.pid, "SIGTERM")'),
        { name: 'missing', command: '/nonexistent/command', args: [] },
      ],
      (r) => seen.push(r),
    );
    expect(ok).toBe(false);
    expect(seen.map((r) => r.ok)).toEqual([false, false]);
  });

  it('runs the tasks at the same time: each one starts before any of the others ends', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'run-parallel-overlap-'));
    const waitForAllThree = `
      const fs = require('node:fs');
      const start = Date.now();
      fs.writeFileSync(process.argv[1] + '/' + process.pid, '');
      const until = start + 20000;
      const timer = setInterval(() => {
        if (fs.readdirSync(process.argv[1]).length >= 3) {
          clearInterval(timer);
          process.stdout.write(JSON.stringify({ start, end: Date.now() }));
        } else if (Date.now() > until) {
          process.exit(1);
        }
      }, 10);`;
    try {
      const seen: TaskResult[] = [];
      const ok = await runAllInParallel(
        [1, 2, 3].map((i) => ({
          name: `task${i}`,
          command: process.execPath,
          args: ['-e', waitForAllThree, dir],
        })),
        (r) => seen.push(r),
      );
      expect(ok).toBe(true);
      const spans = seen.map((r) => JSON.parse(r.output) as { start: number; end: number });
      expect(spans).toHaveLength(3);
      for (const a of spans) {
        for (const b of spans) expect(a.start).toBeLessThanOrEqual(b.end);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);
});

describe('which pnpm runs each package script', () => {
  it('the pnpm that started us (npm_execpath), under this Node, when there is one', () => {
    expect(packageScriptTask('lint', '/corepack/pnpm/10.28.0/bin/pnpm.cjs')).toEqual({
      name: 'lint',
      command: process.execPath,
      args: ['/corepack/pnpm/10.28.0/bin/pnpm.cjs', '--silent', 'run', 'lint'],
    });
  });

  it('pnpm from PATH otherwise', () => {
    for (const unset of [undefined, '']) {
      expect(packageScriptTask('lint', unset)).toEqual({
        name: 'lint',
        command: 'pnpm',
        args: ['--silent', 'run', 'lint'],
      });
    }
  });

  it('run-parallel.ts hands each script to the npm_execpath it was given', () => {
    const dir = mkdtempSync(join(tmpdir(), 'run-parallel-'));
    try {
      const fake = join(dir, 'fake-pnpm.cjs');
      writeFileSync(fake, 'process.stdout.write(JSON.stringify(process.argv.slice(2)));\n');
      const out = execFileSync(
        process.execPath,
        [join(import.meta.dirname, '..', 'run-parallel.ts'), 'one', 'two'],
        { env: { ...process.env, npm_execpath: fake, GITHUB_ACTIONS: 'true' }, encoding: 'utf8' },
      );
      expect(out).toContain('["--silent","run","one"]');
      expect(out).toContain('["--silent","run","two"]');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
