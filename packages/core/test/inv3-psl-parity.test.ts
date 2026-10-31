import { describe, expect, it } from 'vitest';
import {
  registrableDomain as signerRegistrableDomain,
  rpIdAllowedForHost as signerRpIdAllowed,
} from '../../signer/src/psl.ts';
import {
  registrableDomain as coreRegistrableDomain,
  rpIdAllowedForHost as coreRpIdAllowed,
} from '../src/origin.ts';

const HOSTS = [
  'example.com',
  'www.example.com',
  'a.b.c.example.com',
  'com',
  'bbc.co.uk',
  'www.bbc.co.uk',
  'co.uk',
  'uk',
  'shop.example.com.au',
  'com.au',
  'foo.ck',
  'a.foo.ck',
  'ck',
  'www.ck',
  'a.www.ck',
  'x.kawasaki.jp',
  'a.x.kawasaki.jp',
  'kawasaki.jp',
  'city.kawasaki.jp',
  'a.city.kawasaki.jp',
  'github.io',
  'victim.github.io',
  'a.victim.github.io',
  'blogspot.com',
  'victim.blogspot.com',
  'herokuapp.com',
  'victim.herokuapp.com',
  's3.amazonaws.com',
  'bucket.s3.amazonaws.com',
  'vercel.app',
  'victim.vercel.app',
  'xn--55qx5d.cn',
  'a.xn--55qx5d.cn',
  'xn--fiqs8s',
  'example.xn--fiqs8s',
  'a.example.xn--fiqs8s',
  'localhost',
  'rp.localhost',
  'a.rp.localhost',
  'intranet',
  'a',
  '',
  'WWW.EXAMPLE.COM',
  'example.com.',
  '.example.com',
  '127.0.0.1',
  '[::1]',
  'a..example.com',
  'exa mple.com',
  '-bad.example.com',
  'bad-.example.com',
  `${'a'.repeat(64)}.example.com`,
  `${'a'.repeat(63)}.example.com`,
  `${'a.'.repeat(130)}com`,
  'münchen.de',
  'xn--mnchen-3ya.de',
];

const unrelated = [
  'example.org',
  'notexample.com',
  'xample.com',
  'evil.example.com',
  'evil.github.io',
];

function rpIdCandidates(host: string): string[] {
  const labels = host.split('.');
  const suffixes = labels.map((_, i) => labels.slice(i).join('.'));
  return [
    ...new Set([host, ...suffixes, `evil.${host}`, `x${host}`, ...unrelated, 'com', 'co.uk', '']),
  ];
}

describe('invariant 3: the signer applies the same public suffix rules as the core', () => {
  it.each(HOSTS)('registrable domain of %j', (host) => {
    expect(signerRegistrableDomain(host), host).toBe(coreRegistrableDomain(host));
  });

  it.each(HOSTS)('rpId candidates for host %j', (host) => {
    for (const rpId of rpIdCandidates(host)) {
      expect(signerRpIdAllowed(rpId, host), `${rpId} for ${host}`).toBe(
        coreRpIdAllowed(rpId, host),
      );
    }
  });

  it('the table is not vacuous: both sides accept and refuse', () => {
    const decisions = HOSTS.flatMap((host) =>
      rpIdCandidates(host).map((rpId) => coreRpIdAllowed(rpId, host)),
    );
    expect(decisions.filter(Boolean).length).toBeGreaterThan(30);
    expect(decisions.filter((d) => !d).length).toBeGreaterThan(200);
    expect(coreRegistrableDomain('www.bbc.co.uk')).toBe('bbc.co.uk');
    expect(coreRegistrableDomain('a.victim.github.io')).toBe('victim.github.io');
    expect(coreRegistrableDomain('co.uk')).toBeNull();
  });
});
