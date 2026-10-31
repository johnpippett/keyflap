import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const PACKAGES = fileURLToPath(new URL('../..', import.meta.url));
const NEVER_RUN_PASSWORD_TOOLS = ['core', 'mcp', 'shim'];

function sourceFiles(pkg: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(ts|js|mjs)$/.test(e.name)) out.push(p);
    }
  };
  walk(join(PACKAGES, pkg, 'src'));
  return out;
}

function specifiers(code: string): string[] {
  return [
    ...code.matchAll(/\bfrom\s*['"]([^'"]+)['"]/g),
    ...code.matchAll(/\bimport\s*['"]([^'"]+)['"]/g),
    ...code.matchAll(/\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g),
  ].map((m) => m[1] as string);
}

const computedImports = (code: string) => code.match(/\b(?:import|require)\s*\(\s*[^'"\s)]/g) ?? [];

const runsProcesses = (spec: string) => spec.replace(/^node:/, '') === 'child_process';
const readsPasswordSources = (spec: string) =>
  spec === '@aab/sources' || spec.startsWith('@aab/sources/') || /(^|\/)sources\/src\//.test(spec);

function offenders(pkg: string): string[] {
  const found: string[] = [];
  for (const f of sourceFiles(pkg)) {
    const code = readFileSync(f, 'utf8');
    const name = f.slice(PACKAGES.length);
    for (const s of specifiers(code)) {
      if (runsProcesses(s) || readsPasswordSources(s)) found.push(`${name}: ${s}`);
    }
    for (const c of computedImports(code)) found.push(`${name}: computed ${c}`);
  }
  return found;
}

describe('only the signer runs password-manager CLIs', () => {
  it.each(NEVER_RUN_PASSWORD_TOOLS)(
    '@aab/%s sources import neither node:child_process nor @aab/sources',
    (pkg) => {
      expect(sourceFiles(pkg).length).toBeGreaterThan(0);
      expect(offenders(pkg)).toEqual([]);
    },
  );

  it('the scan catches the imports it exists to catch', () => {
    const code = [
      "import { spawn } from 'node:child_process';",
      "import { execFile } from 'child_process';",
      "import { ProtonPassSource } from '@aab/sources';",
      "import { fake } from '@aab/sources/testing';",
      "import { x } from '../../sources/src/tool.ts';",
      "const m = await import('node:child_process');",
      "const r = require('child_process');",
      'const c = await import(name);',
      "import { createHash } from 'node:crypto';",
      "import { a } from './a.ts';",
    ].join('\n');
    expect(specifiers(code).filter((s) => runsProcesses(s) || readsPasswordSources(s))).toEqual([
      'node:child_process',
      'child_process',
      '@aab/sources',
      '@aab/sources/testing',
      '../../sources/src/tool.ts',
      'node:child_process',
      'child_process',
    ]);
    expect(computedImports(code)).toEqual(['import(n']);
  });
});
