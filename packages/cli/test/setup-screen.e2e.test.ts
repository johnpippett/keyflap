import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { PtySession } from './pty.ts';

const PREVIEW = join(import.meta.dirname, 'setup-preview.ts');
const ENTER_ALT = '\u001b[?1049h';
const LEAVE_ALT = '\u001b[?1049l';

describe('setup screens in a real terminal (the preview, against fakes)', () => {
  let s: PtySession | null = null;
  afterEach(async () => {
    if (s && (await Promise.race([s.exited, Promise.resolve('running')])) === 'running') {
      s.signal('SIGKILL');
    }
  });

  const start = (args: string[] = []) =>
    new PtySession([process.execPath, PREVIEW, ...args], {
      env: {
        PATH: process.env.PATH ?? '',
        HOME: process.env.HOME ?? '/tmp',
        TERM: 'xterm-256color',
      },
      cwd: import.meta.dirname,
    });

  it('runs every step full screen and leaves the final screen on the terminal', {
    timeout: 60_000,
  }, async () => {
    s = start();
    await s.expect(/Six short steps/);
    expect(s.output).toContain(ENTER_ALT);
    s.send('\r');
    await s.expect(/STEP 1 OF 6/);
    await s.expect(/Press Enter to continue/);
    s.send('\r');
    await s.expect(/STEP 2 OF 6/);
    await s.expect(/Press Enter to continue/);
    s.send('\r');
    await s.answer(/Pair a phone now\?/, '');
    await s.expect(/Waiting for your/);
    await s.expect(/Phone paired/, 15_000);
    s.send('\r');
    await s.answer(/Set up an agent for Claude Code\?/, '');
    await s.answer(/Agent name/, '');
    await s.answer(/Write the Claude Code config/, '');
    await s.expect(/All your projects/);
    s.send('\r');
    await s.answer(/Apply these changes\?/, 'y');
    await s.expect(/Claude Code is set up/);
    s.send('\r');
    await s.expect(/Add a credential\?/);
    s.send('\u001b[B\r');
    await s.expect(/Press Enter to finish/, 15_000);
    s.send('\r');
    expect(await s.exited).toBe(0);
    const after = s.output.slice(s.output.lastIndexOf(LEAVE_ALT));
    expect(after).toMatch(/All 15 checks passed/);
    expect(after).toMatch(/nothing on this machine changed/);
    expect(s.output).not.toContain('PREVIEW-not-a-real-pairing-code');
  });

  it('restores the terminal on Ctrl-C at a prompt', { timeout: 30_000 }, async () => {
    s = start(['--scenario', 'linux-fresh']);
    await s.expect(/Six short steps/);
    s.send('\u0003');
    expect(await s.exited).toBe(130);
    const tail = s.output.slice(s.output.lastIndexOf(ENTER_ALT));
    expect(tail).toContain(LEAVE_ALT);
    expect(tail).toContain('\u001b[?25h');
    expect(tail).toMatch(/Preview stopped/);
  });

  it('restores the terminal on Ctrl-C while a step waits', { timeout: 30_000 }, async () => {
    s = start(['--scenario', 'linux-fresh']);
    await s.expect(/Six short steps/);
    s.send('\r');
    await s.expect(/Checking the Keyflap services/);
    s.send('\u0003');
    await s.exited;
    expect(s.output.slice(s.output.lastIndexOf(ENTER_ALT))).toContain(LEAVE_ALT);
  });
});
