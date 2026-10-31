import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { stripStyle, termStyle } from '@aab/approver';
import { AgentRegistry, openDb } from '@aab/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { UNPROTECTED_BANNER, unprotectedBanner } from '../src/daemon.ts';
import { type DoctorReport, formatReport } from '../src/doctor.ts';
import { styleMarks } from '../src/format.ts';
import { runCli, tmpDir } from './helpers.ts';

// biome-ignore lint/suspicious/noControlCharactersInRegex: looking for escapes
const ESC = /\u001b/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: red foreground or background
const RED = /\u001b\[(?:[0-9;]*;)?(?:31|91|41|101)m/;
const colour = termStyle(3);
const plain = termStyle(0);

const report: DoctorReport = {
  mode: 'dev',
  ok: false,
  checks: [
    { id: 'node', status: 'ok', detail: 'Node 22.23.4' },
    { id: 'daemon', status: 'fail', detail: 'not running', fix: 'keyflap daemon --unprotected' },
    { id: 'phone', status: 'warn', detail: 'no phone paired', fix: 'keyflap daemon --pair' },
    { id: 'mcp', status: 'skip', detail: 'daemon not running' },
  ],
};

describe('keyflap doctor output', () => {
  it('coloured: blue ✓, the failure as an inverted flap, the ids still aligned, no red', () => {
    const t = formatReport(report, colour);
    expect(t).toContain(colour.header('doctor · dev mode'));
    expect(t).toContain(colour.ok('✓'));
    expect(t).toContain(colour.bad('✗'));
    expect(t).toContain(colour.bad('1 check failed.'));
    expect(t).not.toMatch(RED);
    const cols = stripStyle(t)
      .split('\n')
      .filter((l) => /^ {1,2}[✓✗!-]/.test(l) || /^ {2}\s?[✓✗!-] /.test(l))
      .map((l) => l.search(/[a-z]{3,}/));
    expect(new Set(cols).size).toBe(1);
  });
});

describe('keyflap setup marks and the daemon banner', () => {
  it('colours ✓ blue and ✗ as an inverted flap, keeping the column', () => {
    const t = styleMarks('  ✓ Node 22\n  ✗ Chromium missing\nnot ✓ here\n', colour);
    expect(t).toContain(`  ${colour.ok('✓')} Node 22`);
    expect(t).toContain(` ${colour.bad('✗')}Chromium missing`);
    expect(t).toContain('not ✓ here');
    expect(t).not.toMatch(RED);
  });

  it('the UNPROTECTED banner keeps its words; coloured, it is an inverted flap', () => {
    expect(unprotectedBanner(plain)).toBe(UNPROTECTED_BANNER);
    const c = unprotectedBanner(colour);
    expect(c).toContain(colour.bad(UNPROTECTED_BANNER.split('\n')[0] as string));
    expect(c).not.toMatch(RED);
  });
});

describe('keyflap status: colour switch', () => {
  let dir: string;
  beforeAll(() => {
    dir = tmpDir();
    const db = openDb(join(dir, 'broker.sqlite'));
    new AgentRegistry(db).add('style-bot');
    db.close();
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const status = (env: Record<string, string | undefined>) =>
    runCli(['status', '--data-dir', dir], { env: { NO_COLOR: undefined, ...env } });

  it('a pipe gives plain text', async () => {
    const s = await status({ FORCE_COLOR: undefined });
    expect(s.code).toBe(0);
    expect(s.stdout).not.toMatch(ESC);
    expect(s.stdout).toMatch(/Audit log:\s+\d+ entries, hash chain intact/);
  });

  it('colour when forced, in the brand blue, never red', async () => {
    const s = await status({ FORCE_COLOR: '3' });
    expect(s.stdout).toContain(colour.header('status'));
    expect(s.stdout).toContain(colour.ok('hash chain intact'));
    expect(s.stdout).not.toMatch(RED);
  });
});
