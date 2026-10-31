import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { findModuleMockingFiles } from './module-mocks.ts';

const mocks = `vi.${'mock'}('node:fs');\n`;

const fixtures: Record<string, string> = {
  'test/direct.test.ts': mocks,
  'test/side-effect.test.ts': "import './helpers/mocks-fs.ts';\n",
  'test/named.test.ts': "import { x } from './helpers/mocks-fs.ts';\n",
  'test/dynamic.test.ts': "await import('./helpers/mocks-fs.ts');\n",
  'test/reexport.test.ts': "import { y } from './helpers/barrel.ts';\n",
  'test/two-hops.test.ts': "import './helpers/side-effect-chain.ts';\n",
  'test/plain.test.ts': "import { z } from './helpers/plain.ts';\n",
  'test/cycle.test.ts': "import './helpers/cycle-a.ts';\n",
  'test/src-import.test.ts': "import { s } from '../src/mocks-in-src.ts';\n",
  'test/missing.test.ts': "import './helpers/does-not-exist.ts';\n",
  'test/helpers/mocks-fs.ts': mocks,
  'test/helpers/barrel.ts': "export * from './mocks-fs.ts';\n",
  'test/helpers/side-effect-chain.ts': "import './mocks-fs.ts';\n",
  'test/helpers/plain.ts': 'export const z = 1;\n',
  'test/helpers/cycle-a.ts': "import './cycle-b.ts';\n",
  'test/helpers/cycle-b.ts': "import './cycle-a.ts';\n",
  'src/mocks-in-src.ts': mocks,
};

describe('findModuleMockingFiles', () => {
  let root: string;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'module-mocks-'));
    for (const [file, src] of Object.entries(fixtures)) {
      mkdirSync(dirname(join(root, file)), { recursive: true });
      writeFileSync(join(root, file), src);
    }
  });

  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it('finds files that replace modules themselves or through any relative import', () => {
    expect(root).not.toBe(process.cwd());
    expect(findModuleMockingFiles(root, ['test/*.test.ts'], [])).toEqual([
      'test/direct.test.ts',
      'test/dynamic.test.ts',
      'test/named.test.ts',
      'test/reexport.test.ts',
      'test/side-effect.test.ts',
      'test/two-hops.test.ts',
    ]);
  });

  it('globs from the root it is given, not from the working directory', () => {
    expect(findModuleMockingFiles(root, ['test/direct.test.ts'], [])).toEqual([
      'test/direct.test.ts',
    ]);
    expect(findModuleMockingFiles(join(root, 'src'), ['test/direct.test.ts'], [])).toEqual([]);
  });

  it('applies the exclude patterns', () => {
    expect(
      findModuleMockingFiles(root, ['test/*.test.ts'], ['test/side-effect.test.ts']),
    ).not.toContain('test/side-effect.test.ts');
  });
});
