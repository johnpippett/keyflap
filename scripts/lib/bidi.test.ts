import { describe, expect, it } from 'vitest';
import { codePointLabel, findBidi } from './bidi.ts';

const ch = (codePoint: number) => String.fromCodePoint(codePoint);

describe('bidi scanner', () => {
  it('finds every direction mark, embedding, isolate and line separator', () => {
    const flagged = [
      0x061c, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066,
      0x2067, 0x2068, 0x2069,
    ];
    for (const cp of flagged) {
      expect(findBidi(`const a = '${ch(cp)}';`), codePointLabel(cp)).toEqual([
        { line: 1, codePoint: cp },
      ]);
    }
  });

  it('leaves neighbouring code points and ordinary text alone', () => {
    const calm = [0x200b, 0x200c, 0x200d, 0x202f, 0x2065, 0x206a, 0x00e9, 0x4e2d];
    for (const cp of calm)
      expect(findBidi(`const a = '${ch(cp)}';`), codePointLabel(cp)).toEqual([]);
  });

  it('reports the line, counting newlines only', () => {
    const src = `a();\nb();\nc('${ch(0x202e)}');\nd('${ch(0x2028)}');\n`;
    expect(findBidi(src)).toEqual([
      { line: 3, codePoint: 0x202e },
      { line: 4, codePoint: 0x2028 },
    ]);
  });

  it('accepts the escaped spelling', () => {
    expect(findBidi(`const a = '${'\\'}u202e';`)).toEqual([]);
  });

  it('labels a code point like the Unicode tables', () => {
    expect(codePointLabel(0x202e)).toBe('U+202E');
    expect(codePointLabel(0x61)).toBe('U+0061');
  });
});
