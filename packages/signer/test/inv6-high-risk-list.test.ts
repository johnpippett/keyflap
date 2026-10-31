import { describe, expect, it } from 'vitest';
import { isHighRisk } from '../src/risk.ts';

const SOCIAL_HOSTS = [
  'facebook.com',
  'www.facebook.com',
  'm.facebook.com',
  'meta.com',
  'about.meta.com',
  'x.com',
  'mobile.x.com',
  'twitter.com',
  'api.twitter.com',
];

const STILL_GATED: readonly (readonly [string, string])[] = [
  ['Google', 'google.com'],
  ['Google sign-in subdomain', 'accounts.google.com'],
  ['Gmail', 'gmail.com'],
  ['Gmail on Google', 'mail.google.com'],
  ['Microsoft', 'microsoft.com'],
  ['Microsoft sign-in', 'login.microsoftonline.com'],
  ['Outlook', 'outlook.com'],
  ['Apple', 'apple.com'],
  ['Apple ID', 'appleid.apple.com'],
  ['iCloud', 'icloud.com'],
  ['GitHub', 'github.com'],
  ['GitHub subdomain', 'gist.github.com'],
  ['GitLab', 'gitlab.com'],
  ['Amazon', 'amazon.com'],
  ['Amazon storefront', 'www.amazon.com'],
  ['Amazon UK', 'amazon.co.uk'],
  ['bank', 'chase.com'],
  ['bank subdomain', 'secure.chase.com'],
  ['UK bank', 'online.santander.co.uk'],
  ['payments', 'paypal.com'],
  ['brokerage', 'schwab.com'],
  ['crypto', 'coinbase.com'],
  ['government', 'www.irs.gov'],
  ['military', 'army.mil'],
  ['identity provider', 'okta.com'],
  ['identity provider (ID.me)', 'id.me'],
  ['password manager', '1password.com'],
  ['password manager subdomain', 'my.1password.com'],
  ['password manager (Bitwarden)', 'vault.bitwarden.com'],
  ['mail host ending in x.com', 'gmx.com'],
];

describe('invariant 6: the built-in high-risk list gates high-stakes sites, not socials', () => {
  describe('Facebook, Meta, X and Twitter are not high-risk by default', () => {
    it.each(SOCIAL_HOSTS)('%s', (host) => {
      expect(isHighRisk(host)).toBe(false);
    });

    it('stay gated for an owner who adds them to their own list', () => {
      expect(isHighRisk('www.facebook.com', ['facebook.com'])).toBe(true);
      expect(isHighRisk('x.com', ['x.com'])).toBe(true);
      expect(isHighRisk('api.twitter.com', ['twitter.com'])).toBe(true);
      expect(isHighRisk('about.meta.com', ['meta.com'])).toBe(true);
    });

    it('do not loosen a lookalike or a parent: only the exact names left the list', () => {
      expect(isHighRisk('notfacebook.com')).toBe(false);
      expect(isHighRisk('facebook.com.evil.example')).toBe(false);
      expect(isHighRisk('com')).toBe(true);
    });
  });

  describe('every other high-stakes category stays high-risk', () => {
    it.each(STILL_GATED)('%s: %s', (_kind, host) => {
      expect(isHighRisk(host)).toBe(true);
    });
  });
});
