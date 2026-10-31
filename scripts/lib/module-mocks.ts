import { globSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const replacesModules = /\bvi\.(mock|doMock|unmock|doUnmock)\(/;
const relativeImport = /\b(?:from|import)\s*\(?\s*['"](\.{1,2}\/[^'"]+)['"]/g;

function replacesModulesOrImportsOneThatDoes(file: string, seen: Set<string>): boolean {
  if (seen.has(file)) return false;
  seen.add(file);
  let src: string;
  try {
    src = readFileSync(file, 'utf8');
  } catch {
    return false;
  }
  if (replacesModules.test(src)) return true;
  for (const m of src.matchAll(relativeImport)) {
    const target = join(dirname(file), m[1] ?? '');
    if (target.includes('/src/')) continue;
    if (replacesModulesOrImportsOneThatDoes(target, seen)) return true;
  }
  return false;
}

export function findModuleMockingFiles(
  root: string,
  include: string[],
  exclude: string[],
): string[] {
  return globSync(include, { cwd: root, exclude })
    .filter((f) => replacesModulesOrImportsOneThatDoes(join(root, f), new Set()))
    .sort();
}
