import { existsSync } from 'node:fs';
import { basename, isAbsolute, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { headersCommand, hookCommand } from '../src/agent.ts';
import { defaultDataDir } from '../src/args.ts';

const AGENT = '0b9d6c1e-2f4a-4c3b-9e8d-7a6b5c4d3e2f';
const MAIN = join(import.meta.dirname, '..', 'src', 'main.ts');

function shellWords(command: string): string[] {
  const words: string[] = [];
  let word: string | null = null;
  for (let i = 0; i < command.length; i++) {
    const c = command[i] as string;
    if (c === "'") {
      const end = command.indexOf("'", i + 1);
      word = (word ?? '') + command.slice(i + 1, end);
      i = end;
    } else if (c === '\\') {
      i++;
      word = (word ?? '') + (command[i] as string);
    } else if (c === ' ') {
      if (word !== null) words.push(word);
      word = null;
    } else word = (word ?? '') + c;
  }
  if (word !== null) words.push(word);
  return words;
}

const LAUNCHERS = ['pnpm', 'pnpx', 'npm', 'npx', 'yarn', 'corepack', 'bun', 'bunx'];

describe('Claude Code runs these commands, and their stdout reaches the model or the transport', () => {
  const dev = [
    ['hookCommand', hookCommand, ['hook', 'claude-code']],
    ['headersCommand', headersCommand, ['mcp-headers']],
  ] as const;

  it.each(dev)(
    '%s starts node on main.ts by absolute path, never a package manager',
    (_, build, sub) => {
      for (const dataDir of [defaultDataDir(), "/tmp/keyflap data/it's"]) {
        const words = shellWords(build(AGENT, dataDir));
        expect(words[0]).toBe(process.execPath);
        expect(isAbsolute(words[0] as string)).toBe(true);
        expect(words[1]).toBe(MAIN);
        expect(existsSync(MAIN)).toBe(true);
        expect(words.slice(2, 2 + sub.length)).toEqual(sub);
        expect(words.slice(2 + sub.length, 4 + sub.length)).toEqual(['--agent', AGENT]);
        expect(words.slice(4 + sub.length)).toEqual(
          dataDir === defaultDataDir() ? [] : ['--data-dir', dataDir],
        );
        for (const w of words) expect(LAUNCHERS, w).not.toContain(basename(w));
      }
    },
  );

  it('shellWords reads what shellQuote writes', () => {
    expect(shellWords(`/a/node '/a b/main.ts' --x 'it'\\''s'`)).toEqual([
      '/a/node',
      '/a b/main.ts',
      '--x',
      "it's",
    ]);
  });
});
