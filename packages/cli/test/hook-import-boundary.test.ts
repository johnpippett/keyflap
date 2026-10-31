import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { builtinModules } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const PACKAGES = fileURLToPath(new URL('../..', import.meta.url));
const CLI_SRC = join(PACKAGES, 'cli', 'src');

const isBuiltin = (s: string) =>
  s.startsWith('node:') ? builtinModules.includes(s.slice(5)) : builtinModules.includes(s);
const isRelative = (s: string) => s.startsWith('./') || s.startsWith('../');

function staticSpecifiers(code: string): string[] {
  return [
    ...code.matchAll(/^(?:import|export)\s[^'"`;]*?\sfrom\s*['"]([^'"]+)['"]/gm),
    ...code.matchAll(/^import\s*['"]([^'"]+)['"]/gm),
  ].map((m) => m[1] as string);
}

function dynamicSpecifiers(code: string): string[] {
  return [...code.matchAll(/\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g)].map(
    (m) => m[1] as string,
  );
}

function computedImports(code: string): string[] {
  return code.match(/\b(?:import|require)\s*\(\s*[^'"\s)]/g) ?? [];
}

function packageEntry(spec: string): string | null {
  const m = /^@aab\/([^/]+)(\/.*)?$/.exec(spec);
  if (!m) return null;
  const dir = join(PACKAGES, m[1] as string);
  const exports = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).exports as Record<
    string,
    string
  >;
  const target = exports[m[2] ? `.${m[2]}` : '.'];
  return target ? join(dir, target) : null;
}

function closure(
  entries: string[],
  allowed: (spec: string) => boolean,
  followDynamic: boolean,
): { files: string[]; problems: string[] } {
  const files = new Set<string>();
  const problems: string[] = [];
  const visit = (file: string) => {
    if (files.has(file)) return;
    files.add(file);
    const code = readFileSync(file, 'utf8');
    const specs = [...staticSpecifiers(code), ...(followDynamic ? dynamicSpecifiers(code) : [])];
    const here = relative(PACKAGES, file);
    for (const c of followDynamic ? computedImports(code) : [])
      problems.push(`${here}: computed ${c}`);
    for (const s of specs) {
      if (isBuiltin(s)) continue;
      if (isRelative(s)) visit(resolve(dirname(file), s));
      else if (allowed(s)) {
        const entry = packageEntry(s);
        if (entry === null) problems.push(`${here}: ${s} has no package export`);
        else visit(entry);
      } else problems.push(`${here}: ${s}`);
    }
  };
  for (const e of entries) visit(e);
  return { files: [...files].map((f) => relative(PACKAGES, f)).sort(), problems };
}

const cli = (...p: string[]) => join(CLI_SRC, ...p);

const HOOK_ENTRIES = [
  cli('hook-claude-code.ts'),
  cli('hook-codex.ts'),
  cli('hook-hermes.ts'),
  cli('mcp-headers.ts'),
  cli('service', 'paths.ts'),
];

const hookMayImport = (s: string) => s === '@aab/signer/platform';
const frontMayImport = (s: string) =>
  s === '@aab/approver/front' || s === '@aab/sources' || s.startsWith('@aab/signer/');

describe('the Claude Code hook and the headers helper start fast: node built-ins and nothing else', () => {
  it('the hook and helper modules reach only node built-ins, their own files and @aab/signer/platform', () => {
    const { files, problems } = closure(HOOK_ENTRIES, hookMayImport, true);
    expect(problems).toEqual([]);
    expect(files).toEqual(
      expect.arrayContaining([
        'cli/src/hook-claude-code.ts',
        'cli/src/hook-core.ts',
        'cli/src/mcp-headers.ts',
        'cli/src/service/paths.ts',
        'signer/src/platform.ts',
      ]),
    );
  });

  it('service/paths.ts imports nothing at all', () => {
    const code = readFileSync(cli('service', 'paths.ts'), 'utf8');
    expect([
      ...staticSpecifiers(code),
      ...dynamicSpecifiers(code),
      ...computedImports(code),
    ]).toEqual([]);
  });

  it('main.ts loads only args.ts and what it imports until a subcommand is known', () => {
    const { files, problems } = closure([cli('main.ts')], hookMayImport, false);
    expect(problems).toEqual([]);
    expect(files).toEqual(expect.arrayContaining(['cli/src/main.ts', 'cli/src/args.ts']));
  });

  it('the approver front entry reaches only node built-ins and workspace modules that use only those', () => {
    const { files, problems } = closure([cli('service', 'approver-main.ts')], frontMayImport, true);
    expect(problems).toEqual([]);
    expect(files).toEqual(
      expect.arrayContaining(['approver/src/front.ts', 'signer/src/systemd.ts']),
    );
  });

  it('the walk reports what it exists to report', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aabc-'));
    try {
      writeFileSync(join(dir, 'a.ts'), "import { x } from '@aab/core';\nimport './b.ts';\n");
      writeFileSync(
        join(dir, 'b.ts'),
        "import { y } from 'zod';\nimport { join } from 'node:path';\nawait import('tldts');\nawait import(name);\n",
      );
      const { files, problems } = closure([join(dir, 'a.ts')], hookMayImport, true);
      expect(files).toHaveLength(2);
      expect(problems.map((p) => p.replace(/^.*: /, ''))).toEqual([
        '@aab/core',
        'computed import(n',
        'zod',
        'tldts',
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the specifier scans read multi-line imports and ignore the word from inside strings', () => {
    expect(
      staticSpecifiers("import {\n  a,\n  b,\n} from 'zod';\nconst s = 'read from \\'x\\'';"),
    ).toEqual(['zod']);
    expect(
      staticSpecifiers("export { a } from './a.ts';\nimport type { T } from './t.ts';"),
    ).toEqual(['./a.ts', './t.ts']);
  });
});
