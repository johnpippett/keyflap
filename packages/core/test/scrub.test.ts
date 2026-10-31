import { describe, expect, it } from 'vitest';
import { parseTotpInput, siteDomain } from '../src/passwords.ts';
import { REDACTED, scrubDeep, scrubString, secretForms, truncateScrubbed } from '../src/scrub.ts';

describe('invariant 8: output scrubbing of filled secrets', () => {
  const pw = 'p@ss word/+%&?é"\\';

  it('scrubs the raw value and its JSON, URL and form encodings', () => {
    const forms = secretForms(pw);
    expect(forms).toEqual(
      expect.arrayContaining([
        pw,
        JSON.stringify(pw).slice(1, -1),
        encodeURIComponent(pw),
        new URLSearchParams({ v: pw }).toString().slice(2),
      ]),
    );
    for (const f of forms) {
      expect(scrubString(`before ${f} after`, [pw])).toBe(`before ${REDACTED} after`);
    }
  });

  it('matches percent-encodings case-insensitively', () => {
    const lower = encodeURIComponent(pw).replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase());
    expect(scrubString(`/x?p=${lower}`, [pw])).toBe(`/x?p=${REDACTED}`);
  });

  it('walks nested results, keys included, and leaves other values alone', () => {
    const out = scrubDeep(
      { url: `https://a.example/?p=${encodeURIComponent(pw)}`, n: 3, list: [pw, 'ok'], [pw]: true },
      [pw],
    );
    expect(out).toEqual({
      url: `https://a.example/?p=${REDACTED}`,
      n: 3,
      list: [REDACTED, 'ok'],
      [REDACTED]: true,
    });
  });

  it('scrubs codes and never-short values; no secrets means the value is returned as is', () => {
    expect(scrubString('Code 123456 sent', ['123456'])).toBe(`Code ${REDACTED} sent`);
    expect(secretForms('abc')).toEqual([]);
    const v = { a: 'x' };
    expect(scrubDeep(v, [])).toBe(v);
  });
});

describe('invariant 8: scrubbing, review regressions', () => {
  it("scrubs the browser URL parser's spelling of a raw value (query, path, fragment)", () => {
    const pw = "it's a secret";
    for (const href of [
      new URL(`https://a.example/x?p=${pw}`).href,
      new URL(`https://a.example/${pw}`).href,
      new URL(`https://a.example/#${pw}`).href,
    ]) {
      expect(href).not.toContain(pw);
      const out = scrubString(href, [pw]);
      expect(out, href).toContain(REDACTED);
      expect(out).not.toMatch(/secret/);
    }
  });

  it('scrubs whitespace-collapsed and trimmed copies (aria snapshots normalize whitespace)', () => {
    const pw = 'tw0  spaces ';
    expect(scrubString('- paragraph: tw0 spaces .', [pw])).toBe(`- paragraph: ${REDACTED} .`);
  });

  it('falls back to redacting any token that percent-decodes to a secret', () => {
    const pw = 'odd~Value(1)';
    const odd = '%6Fdd%7EValue%281%29';
    expect(scrubString(`/url: https://a.example/?p=${odd}&q=1 rest`, [pw])).toBe(
      `/url: ${REDACTED} rest`,
    );
  });

  it('redacts the longer of two overlapping secrets whole, whatever the order', () => {
    for (const order of [
      ['hunter22', 'hunter22!x'],
      ['hunter22!x', 'hunter22'],
    ]) {
      expect(scrubString('a hunter22!x b', order)).toBe(`a ${REDACTED} b`);
    }
  });

  it('truncation never leaves the start of a secret at the cut', () => {
    const pw = 'abcdefgh-secret';
    const text = `${'x'.repeat(10)}${pw}`;
    for (let max = 11; max < text.length; max++) {
      const cut = truncateScrubbed(text, max, [pw]);
      expect(cut.length).toBeLessThanOrEqual(max);
      expect(cut.endsWith('a') && max > 10 ? cut.length : 0, `max ${max}`).toBe(0);
      expect(cut).toBe('x'.repeat(10));
    }
    expect(truncateScrubbed('short', 100, [pw])).toBe('short');
  });
});

describe('password item inputs', () => {
  it('siteDomain: registrable domain of a host or URL; none for IPs and public suffixes', () => {
    expect(siteDomain('example.com')).toBe('example.com');
    expect(siteDomain('https://login.example.co.uk/x?y')).toBe('example.co.uk');
    expect(siteDomain('Accounts.Example.COM')).toBe('example.com');
    expect(siteDomain('http://rp.localhost:3000/')).toBe('rp.localhost');
    expect(siteDomain('https://127.0.0.1/')).toBeNull();
    expect(siteDomain('[::1]')).toBeNull();
    expect(siteDomain('co.uk')).toBeNull();
    expect(siteDomain('github.io')).toBeNull();
    expect(siteDomain('')).toBeNull();
  });

  it('parseTotpInput: bare secrets and otpauth://totp URIs', () => {
    expect(parseTotpInput(' JBSWY3DPEHPK3PXP ')).toEqual({ secret: 'JBSWY3DPEHPK3PXP' });
    expect(
      parseTotpInput(
        'otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP&issuer=Ex&algorithm=sha256&digits=8&period=60',
      ),
    ).toEqual({ secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA256', digits: 8, period: 60 });
    expect(() => parseTotpInput('otpauth://hotp/x?secret=AAAA&counter=1')).toThrow(/totp/);
    expect(() => parseTotpInput('otpauth://totp/x')).toThrow(/no secret/);
  });
});
