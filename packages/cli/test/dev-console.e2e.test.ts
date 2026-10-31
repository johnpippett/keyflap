import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createAgent } from '../src/agent.ts';
import { USAGE } from '../src/args.ts';
import { createKeyFile } from '../src/key-file.ts';
import { MAIN, runCli, tmpDir } from './helpers.ts';
import { PtySession } from './pty.ts';

const ENTER_ALT = '\u001b[?1049h';
const LEAVE_ALT = '\u001b[?1049l';
const ttyLines = (output: string) => output.replace(/\r+\n/g, '\n');

describe('keyflap with no command, as the user, in a real terminal', () => {
  let home: string;
  let s: PtySession | null = null;

  afterEach(async () => {
    if (s && (await Promise.race([s.exited, Promise.resolve('running')])) === 'running') {
      s.signal('SIGKILL');
    }
    s = null;
    rmSync(home, { recursive: true, force: true });
  });

  const fresh = () => {
    home = tmpDir();
    return join(home, '.keyflap');
  };

  const start = (args: string[] = []) =>
    new PtySession([process.execPath, MAIN, ...args], {
      env: { PATH: process.env.PATH ?? '', HOME: home, TERM: 'xterm-256color' },
      cwd: home,
    });

  it('opens the unprotected console for a dev data dir: warning first, then the overview', async () => {
    createAgent(fresh(), 'claude-code');
    s = start();
    await s.expect(/This is the unprotected\s+version of/);
    expect(s.output).toContain(ENTER_ALT);
    expect(s.output).toContain('████');
    await s.expect(/Press Enter to continue/);
    s.send('\r');
    await s.expect(/What do you want to manage\?/);
    expect(s.output).toContain('! UNPROTECTED');
    s.send('\u001b');
    expect(await s.exited).toBe(0);
    expect(s.output).toContain(LEAVE_ALT);
  });

  it('Esc on the warning leaves at once, without opening the overview', async () => {
    createAgent(fresh(), 'claude-code');
    s = start();
    await s.expect(/Press Enter to continue/);
    s.send('\u001b');
    expect(await s.exited).toBe(0);
    expect(s.output).not.toContain('What do you want to manage?');
    expect(s.output).toContain(LEAVE_ALT);
  });

  it.runIf(process.platform === 'darwin')(
    'opens it for a simple install (a key file)',
    async () => {
      const dir = fresh();
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      createKeyFile(dir);
      s = start();
      await s.expect(/This is the unprotected\s+version of/);
      s.send('\r');
      await s.expect(/What do you want to manage\?/);
      expect(s.output).toContain('! UNPROTECTED');
      s.send('\u001b');
      expect(await s.exited).toBe(0);
    },
  );

  it.skipIf(process.platform === 'darwin')(
    'says the simple install is for macOS when a key file is found on Linux',
    async () => {
      const dir = fresh();
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      createKeyFile(dir);
      s = start();
      expect(await s.exited).toBe(1);
      expect(s.output).toContain('the simple install is for macOS only');
      expect(s.output).not.toContain(ENTER_ALT);
    },
  );

  it('prints the usage when there is no install at all', async () => {
    fresh();
    mkdirSync(home, { recursive: true });
    s = start();
    expect(await s.exited).toBe(0);
    expect(ttyLines(s.output)).toBe(USAGE);
    expect(s.output).not.toContain(ENTER_ALT);
  });

  it('still prints the usage for --help, even with an install', async () => {
    createAgent(fresh(), 'claude-code');
    const r = await runCli(['--help'], { env: { HOME: home } });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe(USAGE);
  });

  it('prints the usage without a terminal, even with an install', async () => {
    createAgent(fresh(), 'claude-code');
    const r = await runCli([], { env: { HOME: home } });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe(USAGE);
  });
});
