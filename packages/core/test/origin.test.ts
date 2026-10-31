import { describe, expect, it } from 'vitest';
import {
  canonicalHost,
  normalizeHost,
  registrableDomain,
  rpIdAllowedForHost,
  verifiedOriginFromFrame,
} from '../src/origin.ts';

const frameAt = (url: string, isMainFrame = true) => {
  let securityOrigin: string | null = null;
  try {
    securityOrigin = new URL(url).origin;
  } catch {}
  return { url, isMainFrame, securityOrigin };
};

describe('invariant 2: verified origin comes only from the trusted frame URL', () => {
  it.each([
    ['https://example.com/login?x=1#y', 'https://example.com'],
    ['https://login.example.com:8443/a', 'https://login.example.com:8443'],
    ['http://localhost:3000/', 'http://localhost:3000'],
    ['http://rp.localhost:3000/x', 'http://rp.localhost:3000'],
  ])('%s → %s', (url, origin) => {
    expect(verifiedOriginFromFrame(frameAt(url))).toMatchObject({ ok: true, origin });
  });

  it.each([
    ['https://example.com/', false, 'not_top_level_frame'],
    ['http://example.com/', true, 'insecure_origin'],
    ['about:blank', true, 'insecure_origin'],
    ['data:text/html,hi', true, 'insecure_origin'],
    ['blob:https://example.com/uuid', true, 'insecure_origin'],
    ['file:///etc/passwd', true, 'insecure_origin'],
    ['https://127.0.0.1/', true, 'ip_origin'],
    ['https://[::1]/', true, 'ip_origin'],
    ['not a url', true, 'bad_frame_url'],
    ['https://example.com./login', true, 'non_canonical_host'],
    ['https://example.com../', true, 'non_canonical_host'],
    ['https://a..example.com/', true, 'non_canonical_host'],
    ['https://-a.example.com/', true, 'non_canonical_host'],
  ])('denies %s (main frame: %s)', (url, isMainFrame, reason) => {
    expect(verifiedOriginFromFrame(frameAt(url, isMainFrame))).toEqual({ ok: false, reason });
  });
});

describe('invariant 2: the document origin must equal the frame URL origin (review H1)', () => {
  const url = 'https://example.com/uploads/x.html';
  it.each([
    ['opaque (CSP sandbox, as Chromium reports it)', '://'],
    ['opaque (serialized)', 'null'],
    ['unknown (not read)', null],
    ['empty', ''],
    ['another origin', 'https://evil.com'],
    ['another port', 'https://example.com:8443'],
    ['another scheme', 'http://example.com'],
    ['a subdomain', 'https://www.example.com'],
  ])('denies a document whose origin is %s', (_what, securityOrigin) => {
    expect(verifiedOriginFromFrame({ url, isMainFrame: true, securityOrigin })).toEqual({
      ok: false,
      reason: 'document_origin_mismatch',
    });
  });

  it('allows the matching origin, and takes it from the URL', () => {
    expect(
      verifiedOriginFromFrame({ url, isMainFrame: true, securityOrigin: 'https://example.com' }),
    ).toEqual({ ok: true, origin: 'https://example.com', host: 'example.com' });
  });
});

describe('policy section 9: one canonical host form (review L2)', () => {
  it.each([
    ['example.com', 'example.com'],
    ['login.example.co.uk', 'login.example.co.uk'],
    ['xn--bcher-kva.de', 'xn--bcher-kva.de'],
    ['rp.localhost', 'rp.localhost'],
  ])('canonical: %s', (h, out) => {
    expect(canonicalHost(h)).toBe(out);
  });

  it.each([
    'example.com.',
    'Example.com',
    'a..b.com',
    '.example.com',
    '127.0.0.1',
    '',
    'bücher.de',
  ])('not canonical: %j', (h) => {
    expect(canonicalHost(h)).toBeNull();
    expect(registrableDomain(h)).toBeNull();
  });

  it.each([
    ['Example.COM.', 'example.com'],
    ['.example.com', 'example.com'],
    ['bücher.de', 'xn--bcher-kva.de'],
    [' login.Example.com ', 'login.example.com'],
  ])('normalizes user input %j → %s', (input, out) => {
    expect(normalizeHost(input)).toBe(out);
  });

  it.each(['example.com..', 'a..b.com', 'example.com/x', 'u@example.com', 'example.com:443', ''])(
    'refuses user input %j',
    (input) => {
      expect(normalizeHost(input)).toBeNull();
    },
  );
});

describe('invariant 3: rpId must be a registrable-domain suffix of the verified origin', () => {
  it.each([
    ['example.com', 'example.com'],
    ['example.com', 'login.example.com'],
    ['login.example.com', 'a.login.example.com'],
    ['example.co.uk', 'login.example.co.uk'],
    ['foo.github.io', 'foo.github.io'],
    ['rp.localhost', 'a.rp.localhost'],
    ['localhost', 'localhost'],
  ])('allows rpId %s on host %s', (rpId, host) => {
    expect(rpIdAllowedForHost(rpId, host)).toBe(true);
  });

  it.each([
    ['example.com', 'evil.com', 'unrelated site'],
    ['example.com', 'evilexample.com', 'suffix without a dot boundary'],
    ['example.com', 'example.com.evil.net', 'prefix match'],
    ['login.example.com', 'example.com', 'rpId more specific than origin'],
    ['com', 'example.com', 'public suffix'],
    ['co.uk', 'example.co.uk', 'multi-label public suffix'],
    ['github.io', 'foo.github.io', 'private-section public suffix'],
    ['localhost', 'rp.localhost', 'localhost treated as a TLD'],
    ['com', 'com', 'public suffix equal to the host'],
    ['co.uk', 'co.uk', 'multi-label public suffix equal to the host'],
    ['github.io', 'github.io', 'private-section public suffix equal to the host'],
    ['127.0.0.1', '127.0.0.1', 'IP address'],
    ['Example.com', 'example.com', 'not canonical lowercase'],
    ['example.com.', 'example.com', 'trailing dot'],
    ['', 'example.com', 'empty'],
  ])('denies rpId %s on host %s (%s)', (rpId, host) => {
    expect(rpIdAllowedForHost(rpId, host)).toBe(false);
  });
});
