import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const WORKFLOWS = join(import.meta.dirname, '..', '..', '..', '.github', 'workflows');
const GITHUB_HOSTED = /^(ubuntu|macos|windows)-(latest|\d+(\.\d+)?)(-arm)?$/;

const workflows = readdirSync(WORKFLOWS)
  .filter((f) => f.endsWith('.yml'))
  .map((file) => ({ file, text: readFileSync(join(WORKFLOWS, file), 'utf8') }));

const code = (text: string) => text.split('\n').filter((l) => !l.trim().startsWith('#'));
const runsOn = workflows.flatMap(({ file, text }) =>
  code(text)
    .filter((l) => /^\s*runs-on:/.test(l))
    .map((line) => ({ file, value: line.replace(/^\s*runs-on:\s*/, '').trim() })),
);

describe('CI runs only on GitHub-hosted runners', () => {
  it('every job names a GitHub-hosted label, never an expression or a self-hosted runner', () => {
    expect(runsOn.length).toBeGreaterThan(0);
    for (const { file, value } of runsOn) {
      expect(GITHUB_HOSTED.test(value), `${file}: runs-on: ${value}`).toBe(true);
    }
  });

  it('no workflow mentions a self-hosted runner anywhere in its code', () => {
    for (const { file, text } of workflows) {
      expect(code(text).join('\n'), file).not.toMatch(/self-hosted/);
    }
  });

  it('the Linux job installs Chromium with its system libraries', () => {
    const ci = workflows.find((w) => w.file === 'ci.yml');
    expect(code(ci?.text ?? '').join('\n')).toMatch(
      /run: .*playwright install --with-deps chromium/,
    );
  });
});
