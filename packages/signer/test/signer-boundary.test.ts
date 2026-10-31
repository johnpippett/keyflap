import { readdirSync, readFileSync } from 'node:fs';
import { builtinModules } from 'node:module';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const PACKAGES = fileURLToPath(new URL('../..', import.meta.url));

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

function manifest(pkg: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(PACKAGES, pkg, 'package.json'), 'utf8'));
}

function offending(code: string, allowed: (spec: string) => boolean): string[] {
  const specs = [
    ...code.matchAll(/\bfrom\s*['"]([^'"]+)['"]/g),
    ...code.matchAll(/\bimport\s*['"]([^'"]+)['"]/g),
    ...code.matchAll(/\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g),
  ].map((m) => m[1] as string);
  const bad = specs.filter((s) => !allowed(s));
  const computed = code.match(/\b(?:import|require)\s*\(\s*[^'"\s)]/g) ?? [];
  return [...bad, ...computed.map((c) => `computed: ${c}`)];
}

const isRelative = (s: string) => s.startsWith('./') || s.startsWith('../');
const isBuiltin = (s: string) =>
  s.startsWith('node:') ? builtinModules.includes(s.slice(5)) : builtinModules.includes(s);
const isSources = (s: string) => s === '@aab/sources' || s.startsWith('@aab/sources/');

const signerMayImport = (s: string) => isRelative(s) || isBuiltin(s) || isSources(s);
const sourcesMayImport = (s: string) => isRelative(s) || isBuiltin(s);

describe('signer boundary: zero npm dependencies, only node built-ins and @aab/sources', () => {
  it('the signer declares @aab/sources as its only dependency of any kind', () => {
    const m = manifest('signer');
    expect(Object.keys((m.dependencies as object) ?? {})).toEqual(['@aab/sources']);
    for (const k of ['devDependencies', 'optionalDependencies', 'peerDependencies']) {
      expect(m[k], k).toBeUndefined();
    }
  });

  it('@aab/sources declares no dependencies of any kind', () => {
    const m = manifest('sources');
    expect(m.dependencies ?? {}).toEqual({});
    for (const k of ['devDependencies', 'optionalDependencies', 'peerDependencies']) {
      expect(m[k], k).toBeUndefined();
    }
  });

  it('signer sources import only relative paths, node built-ins and @aab/sources', () => {
    const found: Record<string, string[]> = {};
    for (const f of sourceFiles('signer')) {
      const bad = offending(readFileSync(f, 'utf8'), signerMayImport);
      if (bad.length > 0) found[f.slice(PACKAGES.length)] = bad;
    }
    expect(found).toEqual({});
  });

  it('@aab/sources sources import only relative paths and node built-ins', () => {
    const found: Record<string, string[]> = {};
    for (const f of sourceFiles('sources')) {
      const bad = offending(readFileSync(f, 'utf8'), sourcesMayImport);
      if (bad.length > 0) found[f.slice(PACKAGES.length)] = bad;
    }
    expect(found).toEqual({});
  });

  it('the scan catches the imports it exists to catch', () => {
    const code = [
      "import { z } from 'zod';",
      "import 'left-pad';",
      "const x = await import('tldts');",
      "const y = require('@aab/core');",
      'const z = await import(name);',
      "import { createHash } from 'node:crypto';",
      "import { a } from './a.ts';",
      "import { s } from '@aab/sources';",
    ].join('\n');
    expect(offending(code, signerMayImport)).toEqual([
      'zod',
      'left-pad',
      'tldts',
      '@aab/core',
      'computed: import(n',
    ]);
    expect(offending("import { s } from '@aab/sources';", sourcesMayImport)).toEqual([
      '@aab/sources',
    ]);
  });
});
