import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

export interface SourceFile {
  path: string;
  text: string;
}

const CODE = /\.(?:ts|js|mjs)$/;

function walk(dir: string, found: string[]): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walk(full, found);
    else found.push(full);
  }
  return found;
}

export const readSource = (path: string): string => readFileSync(join(REPO_ROOT, path), 'utf8');

export function sourceFiles(dir: string, pattern: RegExp = CODE): SourceFile[] {
  return walk(join(REPO_ROOT, dir), [])
    .filter((full) => pattern.test(full))
    .sort()
    .map((full) => ({
      path: relative(REPO_ROOT, full).split('\\').join('/'),
      text: readFileSync(full, 'utf8'),
    }));
}

export function productionSources(): SourceFile[] {
  return readdirSync(join(REPO_ROOT, 'packages')).flatMap((name) =>
    existsSync(join(REPO_ROOT, 'packages', name, 'src')) ? sourceFiles(`packages/${name}/src`) : [],
  );
}

export function callArguments(source: string, callee: string): string[][] {
  const calls: string[][] = [];
  const open = new RegExp(`\\b${callee}\\(`, 'g');
  for (let hit = open.exec(source); hit; hit = open.exec(source)) {
    if (/\bfunction\s+$/.test(source.slice(0, hit.index))) continue;
    const args: string[] = [];
    let depth = 1;
    let quote = '';
    let current = '';
    for (let i = hit.index + hit[0].length; i < source.length && depth > 0; i++) {
      const ch = source.charAt(i);
      if (quote) {
        current += ch;
        if (ch === '\\') current += source.charAt(++i);
        else if (ch === quote) quote = '';
      } else if (ch === "'" || ch === '"' || ch === '`') {
        quote = ch;
        current += ch;
      } else if ('([{'.includes(ch)) {
        depth++;
        current += ch;
      } else if (')]}'.includes(ch)) {
        depth--;
        if (depth > 0) current += ch;
      } else if (ch === ',' && depth === 1) {
        args.push(current.trim());
        current = '';
      } else {
        current += ch;
      }
    }
    if (current.trim() !== '') args.push(current.trim());
    calls.push(args);
  }
  return calls;
}
