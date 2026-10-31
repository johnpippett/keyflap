import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const PLATFORM = new URL('../src/platform.ts', import.meta.url);

const loadsModules = (code: string) => /\b(?:import|require)\b|\bfrom\s*['"]/.test(code);

describe('platform.ts is loaded by the hook on every prompt, so it loads nothing', () => {
  it('has no import, require, dynamic import or re-export', () => {
    expect(loadsModules(readFileSync(PLATFORM, 'utf8'))).toBe(false);
  });

  it('the scan catches every way to load a module', () => {
    for (const code of [
      "import { join } from 'node:path';",
      "import type { Foo } from './foo.ts';",
      "import 'node:fs';",
      "const m = await import('node:fs');",
      "const fs = require('node:fs');",
      "export { join } from 'node:path';",
      "export * from './foo.ts';",
    ]) {
      expect(loadsModules(code), code).toBe(true);
    }
    expect(
      loadsModules('export const x = 1;\nexport function f() { return process.platform; }'),
    ).toBe(false);
  });
});
