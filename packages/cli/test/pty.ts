import { type ChildProcess, spawn } from 'node:child_process';

const q = (a: string) => `'${a.replaceAll("'", `'\\''`)}'`;

const BSD_SCRIPT = 'exec /usr/bin/script -q /dev/null "$@" < <(exec /bin/cat 2>/dev/null)';

export class PtySession {
  output = '';
  private cursor = 0;
  private readonly child: ChildProcess;
  readonly exited: Promise<number | null>;
  private waiters: (() => void)[] = [];

  constructor(argv: string[], opts: { env: Record<string, string>; cwd: string }) {
    const [cmd, args] =
      process.platform === 'darwin'
        ? ['/bin/bash', ['-c', BSD_SCRIPT, 'bash', ...argv]]
        : ['/usr/bin/script', ['-qfec', argv.map(q).join(' '), '/dev/null']];
    this.child = spawn(cmd, args, {
      env: opts.env,
      cwd: opts.cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const onData = (c: Buffer) => {
      this.output += c.toString('utf8');
      for (const w of this.waiters.splice(0)) w();
    };
    this.child.stdout?.on('data', onData);
    this.child.stderr?.on('data', onData);
    this.exited = new Promise((r) => this.child.on('close', (code) => r(code)));
    void this.exited.then(() => {
      this.child.stdin?.destroy();
      for (const w of this.waiters.splice(0)) w();
    });
  }

  get pid(): number | undefined {
    return this.child.pid;
  }

  async expect(re: RegExp, timeoutMs = 30_000): Promise<RegExpExecArray> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const rest = this.output.slice(this.cursor);
      const m = re.exec(rest);
      if (m) {
        this.cursor += m.index + m[0].length;
        return m;
      }
      if (this.child.exitCode !== null || Date.now() > deadline) {
        throw new Error(
          `expected ${re} ${this.child.exitCode !== null ? `(process exited ${this.child.exitCode})` : '(timed out)'}; output since last match:\n${rest.slice(-3000)}`,
        );
      }
      await new Promise<void>((r) => {
        const t = setTimeout(r, Math.max(10, Math.min(500, deadline - Date.now())));
        this.waiters.push(() => {
          clearTimeout(t);
          r();
        });
      });
    }
  }

  send(text: string): void {
    this.child.stdin?.write(text);
  }

  async answer(prompt: RegExp, answer: string, timeoutMs?: number): Promise<void> {
    await this.expect(prompt, timeoutMs);
    await new Promise((r) => setTimeout(r, 50));
    this.send(`${answer}\r`);
  }

  signal(sig: NodeJS.Signals): void {
    this.child.kill(sig);
  }
}
