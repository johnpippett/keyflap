import { describe, expect, it } from 'vitest';
import { isDirective, scanComments, stripComments } from './comments.ts';

const OPEN = '$' + '{';
const texts = (src: string) => scanComments(src).map((c) => c.text);

describe('comment scanner', () => {
  it('finds line and block comments', () => {
    expect(texts('a(); // one\n/* two\nlines */ b();')).toEqual(['// one', '/* two\nlines */']);
  });

  it('ignores comment markers inside strings, templates and regex literals', () => {
    const src = [
      "const a = 'http://x';",
      'const b = "/* no */";',
      ['const c = `//', OPEN, '1 /* yes */}//`;'].join(''),
      'const d = /\\/\\/[/]+/g;',
      'const e = x / y / z;',
    ].join('\n');
    expect(texts(src)).toEqual(['/* yes */']);
  });

  it('handles nested templates and a hashbang', () => {
    const src = ['#!/usr/bin/env node\nconst a = `', OPEN, '`', OPEN, '1}`}`; // end'].join('');
    expect(texts(src)).toEqual(['// end']);
  });

  it('treats a division after a closing paren as division, not a regex', () => {
    expect(texts('const a = (b + c) / 2; // note\nconst d = e / 3;')).toEqual(['// note']);
  });
});

describe('directives', () => {
  it('keeps lint and type directives and nothing else', () => {
    const keep = [
      '// biome-ignore lint/suspicious/noExplicitAny: reason',
      '// @ts-expect-error reason',
      '// @ts-ignore reason',
      '/// <reference types="node" />',
      '/*! legal */',
    ];
    for (const k of keep) expect(isDirective({ start: 0, end: k.length, text: k }), k).toBe(true);
    const drop = ['// explains the code', '/** docs */', '// do not remove'];
    for (const d of drop) expect(isDirective({ start: 0, end: d.length, text: d }), d).toBe(false);
  });
});

describe('stripComments', () => {
  it('drops whole-line comments with their line and trailing ones with their padding', () => {
    const src = 'a();\n  // gone\nb(); // gone too\n/* x */ c();\n';
    expect(stripComments(src, scanComments(src))).toBe('a();\nb();\n c();\n');
  });

  it('removes nothing when there is nothing to remove', () => {
    const src = "const a = 'x'; const b = 1 / 2;\n";
    expect(stripComments(src, scanComments(src))).toBe(src);
  });
});
