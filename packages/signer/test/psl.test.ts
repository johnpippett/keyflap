import { existsSync, readFileSync, statSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  loadPublicSuffixList,
  parsePublicSuffixList,
  registrableDomain,
  rpIdAllowedForHost,
} from '../src/psl.ts';

const DAT = new URL('../src/psl/public_suffix_list.dat', import.meta.url);

describe('public suffix list snapshot', () => {
  it('parses: both sections, a version, thousands of rules', () => {
    const text = readFileSync(DAT, 'utf8');
    const rules = parsePublicSuffixList(text);
    expect(rules.version).toMatch(/^\d{4}-\d{2}-\d{2}_/);
    expect(rules.normal.size).toBeGreaterThan(8000);
    expect(rules.wildcard.size).toBeGreaterThan(10);
    expect(rules.exception.size).toBeGreaterThan(3);
    expect(rules.normal.has('co.uk')).toBe(true);
    expect(rules.normal.has('github.io')).toBe(true);
    expect(loadPublicSuffixList().version).toBe(rules.version);
  });

  it('has a documented update script', () => {
    const script = new URL('../scripts/update-psl.sh', import.meta.url);
    expect(existsSync(script)).toBe(true);
    expect(statSync(script).mode & 0o100).toBe(0o100);
    expect(readFileSync(script, 'utf8')).toContain('https://publicsuffix.org/list/');
  });

  it('refuses a truncated or foreign file', () => {
    const text = readFileSync(DAT, 'utf8');
    expect(() => parsePublicSuffixList(text.slice(0, text.length / 2))).toThrow();
    expect(() => parsePublicSuffixList('com\nco.uk\n')).toThrow();
    const bad = text.replace('\nco.uk\n', '\nco..uk\n');
    expect(() => parsePublicSuffixList(bad)).toThrow();
  });

  it('registrable domains', () => {
    const cases: [string, string | null][] = [
      ['www.bbc.co.uk', 'bbc.co.uk'],
      ['co.uk', null],
      ['uk', null],
      ['a.b.example.com', 'example.com'],
      ['com', null],
      ['victim.github.io', 'victim.github.io'],
      ['github.io', null],
      ['foo.ck', null],
      ['a.foo.ck', 'a.foo.ck'],
      ['www.ck', 'www.ck'],
      ['a.www.ck', 'www.ck'],
      ['x.kawasaki.jp', null],
      ['city.kawasaki.jp', 'city.kawasaki.jp'],
      ['xn--55qx5d.cn', null],
      ['a.xn--55qx5d.cn', 'a.xn--55qx5d.cn'],
      ['rp.localhost', 'rp.localhost'],
      ['localhost', null],
      ['', null],
      ['WWW.EXAMPLE.COM', null],
      ['example.com.', null],
      ['127.0.0.1', null],
      ['a..example.com', null],
      ['exa mple.com', null],
    ];
    for (const [host, want] of cases) expect(registrableDomain(host), host).toBe(want);
  });

  it('rpId rule mirrors the core (never a public suffix)', () => {
    expect(rpIdAllowedForHost('bbc.co.uk', 'www.bbc.co.uk')).toBe(true);
    expect(rpIdAllowedForHost('www.bbc.co.uk', 'www.bbc.co.uk')).toBe(true);
    expect(rpIdAllowedForHost('co.uk', 'www.bbc.co.uk')).toBe(false);
    expect(rpIdAllowedForHost('barclays.co.uk', 'www.bbc.co.uk')).toBe(false);
    expect(rpIdAllowedForHost('github.io', 'victim.github.io')).toBe(false);
    expect(rpIdAllowedForHost('localhost', 'localhost')).toBe(true);
    expect(rpIdAllowedForHost('localhost', 'rp.localhost')).toBe(false);
    expect(rpIdAllowedForHost('rp.localhost', 'rp.localhost')).toBe(true);
    expect(rpIdAllowedForHost('example.com', 'notexample.com')).toBe(false);
  });
});
