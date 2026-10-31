import { posix } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readSource } from './source-tree.ts';

const STATIC_IMPORT = /^(?:import|export)\b[^;]*?\bfrom\s*(['"])(.+?)\1/gm;
const SIDE_EFFECT_IMPORT = /^import\s*(['"])(.+?)\1/gm;
const DYNAMIC = /\b(?:import|require)\s*\(\s*(['"`])?([^'"`)]*)/g;

function importSpecifiers(source: string): string[] {
  const found = [
    ...[...source.matchAll(STATIC_IMPORT)].map((m) => m[2] as string),
    ...[...source.matchAll(SIDE_EFFECT_IMPORT)].map((m) => m[2] as string),
    ...[...source.matchAll(DYNAMIC)].map((m) => (m[1] ? (m[2] as string) : '<computed>')),
  ];
  return found.sort();
}

const SIGNER_PLATFORM = 'packages/signer/src/platform.ts';

function importClosure(entry: string): { files: string[]; foreign: string[] } {
  const files: string[] = [];
  const foreign: string[] = [];
  const visit = (file: string) => {
    if (files.includes(file)) return;
    files.push(file);
    for (const spec of importSpecifiers(readSource(file))) {
      if (spec.startsWith('node:')) continue;
      if (spec.startsWith('./')) visit(posix.join(posix.dirname(file), spec));
      else if (spec === '@aab/signer/platform') visit(SIGNER_PLATFORM);
      else foreign.push(`${file} imports ${spec}`);
    }
  };
  visit(entry);
  return { files: files.sort(), foreign };
}

describe('code that must not depend on anything but Node', () => {
  it('the service-mode front and the page files import only node: built-ins and the signer platform module', () => {
    for (const entry of ['packages/approver/src/front.ts', 'packages/approver/src/page-files.ts']) {
      expect(importClosure(entry).foreign, entry).toEqual([]);
    }
    expect(importClosure('packages/approver/src/front.ts').files).toEqual([
      'packages/approver/src/front.ts',
      'packages/approver/src/page-files.ts',
      SIGNER_PLATFORM,
    ]);
  });

  it('the QR encoder is handed the pairing link and imports nothing, so no dependency can read it', () => {
    expect(importSpecifiers(readSource('packages/approver/src/qr.ts'))).toEqual([]);
  });

  it('the import scanner sees multi-line, type, re-export, side-effect, dynamic and require imports', () => {
    const sample = [
      "import {\n  a,\n  b,\n} from 'one';",
      "import type { T } from './two.ts';",
      "export { c } from 'three';",
      "import 'four';",
      "const d = await import('five');",
      "const e = require('six');",
      'const f = await import(name);',
      'export function g() { return 1; }',
      "const h = 'from';",
    ].join('\n');
    expect(importSpecifiers(sample)).toEqual([
      './two.ts',
      '<computed>',
      'five',
      'four',
      'one',
      'six',
      'three',
    ]);
  });
});
