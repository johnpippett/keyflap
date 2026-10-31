import { EventEmitter } from 'node:events';
import type { Page } from 'playwright';
import { describe, expect, it } from 'vitest';
import {
  ChallengeWatch,
  classifyDocumentResponse,
  classifyUrl,
  detectHumanCheck,
  hostMatches,
} from '../src/challenge.ts';

describe('challenge hosts', () => {
  it('match on label boundaries only', () => {
    expect(hostMatches('challenges.cloudflare.com', 'challenges.cloudflare.com')).toBe(true);
    expect(hostMatches('x.captcha.awswaf.com', 'captcha.awswaf.com')).toBe(true);
    expect(hostMatches('NEWASSETS.HCAPTCHA.COM', 'hcaptcha.com')).toBe(true);
    expect(hostMatches('notcaptcha.awswaf.com', 'captcha.awswaf.com')).toBe(false);
    expect(hostMatches('x.captcha.awswaf.com.evil.localhost', 'captcha.awswaf.com')).toBe(false);
    expect(hostMatches('evilhcaptcha.com', 'hcaptcha.com')).toBe(false);
  });

  it('lookalike hosts are not challenge hosts', () => {
    for (const url of [
      'https://x.captcha.awswaf.com.evil.localhost/frame',
      'https://challenges.cloudflare.com.evil.localhost/turnstile',
      'https://hcaptcha.com.evil.localhost/#frame=checkbox',
      'https://www.google.com.evil.localhost/recaptcha/api2/anchor',
      'https://evil.localhost/recaptcha/api2/bframe',
      'http://captcha.localhost.evil.localhost/challenge/widget',
    ]) {
      expect(classifyUrl(url, ['captcha.localhost']), url).toBeNull();
    }
  });

  it('interactive widgets vs background ones', () => {
    const cases: [string, string | null, boolean][] = [
      [
        'https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile/if/ov2',
        'cloudflare',
        true,
      ],
      [
        'https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html#frame=checkbox&id=1',
        'hcaptcha',
        true,
      ],
      [
        'https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html#frame=challenge&id=1',
        'hcaptcha',
        true,
      ],
      [
        'https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html#frame=checkbox-invisible',
        'hcaptcha',
        false,
      ],
      ['https://www.google.com/recaptcha/api2/anchor?ar=1&k=key&size=normal', 'recaptcha', true],
      [
        'https://www.google.com/recaptcha/api2/anchor?ar=1&k=key&size=invisible',
        'recaptcha',
        false,
      ],
      ['https://www.google.com/recaptcha/enterprise/anchor?k=key', 'recaptcha', true],
      ['https://www.recaptcha.net/recaptcha/api2/bframe?k=key', 'recaptcha', true],
      ['https://www.google.com/recaptcha/api.js', 'recaptcha', false],
      ['https://client-api.arkoselabs.com/fc/gc/', 'arkose', true],
      ['https://x.funcaptcha.com/fc/', 'arkose', true],
      ['https://geo.captcha-delivery.com/captcha/?initialCid=x', 'datadome', true],
      ['https://captcha.px-cdn.net/x/captcha.js', 'human', true],
      ['https://abc.captcha.awswaf.com/abc/captcha.js', 'aws-waf', true],
      ['https://abc.token.awswaf.com/abc/challenge.js', 'aws-waf', false],
    ];
    for (const [url, provider, interactive] of cases) {
      expect(classifyUrl(url), url).toEqual({ provider, interactive });
    }
  });

  it('only /recaptcha/ on the Google hosts, and only http(s)', () => {
    expect(classifyUrl('https://www.google.com/search?q=recaptcha')).toBeNull();
    expect(classifyUrl('https://www.google.com/maps/recaptcha/api2/anchor')).toBeNull();
    expect(classifyUrl('about:blank')).toBeNull();
    expect(classifyUrl('data:text/html,<p>challenges.cloudflare.com</p>')).toBeNull();
    expect(classifyUrl('not a url')).toBeNull();
  });

  it('test-only extra hosts count as interactive widgets', () => {
    expect(
      classifyUrl('http://captcha.localhost:3000/challenge/widget', ['captcha.localhost']),
    ).toEqual({
      provider: 'test',
      interactive: true,
    });
    expect(classifyUrl('http://captcha.localhost:3000/challenge/widget')).toBeNull();
  });
});

describe('challenge headers', () => {
  it('AWS WAF and Cloudflare', () => {
    expect(classifyDocumentResponse({ 'x-amzn-waf-action': 'captcha' })).toBe('aws-waf');
    expect(classifyDocumentResponse({ 'x-amzn-waf-action': 'Challenge' })).toBe('aws-waf');
    expect(classifyDocumentResponse({ 'cf-mitigated': 'challenge' })).toBe('cloudflare');
  });
  it('anything else is no signal', () => {
    expect(classifyDocumentResponse({})).toBeNull();
    expect(classifyDocumentResponse({ 'x-amzn-waf-action': 'allow' })).toBeNull();
    expect(classifyDocumentResponse({ 'cf-mitigated': 'block' })).toBeNull();
    expect(classifyDocumentResponse({ 'content-type': 'text/html; challenge' })).toBeNull();
  });
});

interface FakeFrame {
  url(): string;
  isDetached(): boolean;
  frameElement(): Promise<{
    isVisible(): Promise<boolean>;
    boundingBox(): Promise<{ x: number; y: number; width: number; height: number } | null>;
    dispose(): Promise<void>;
  }>;
}

function fakePage(url: string) {
  const ee = new EventEmitter();
  let current = url;
  const main = { url: () => current, isDetached: () => false } as unknown as FakeFrame;
  const frames: FakeFrame[] = [main];
  const page = {
    on: (e: string, l: (...a: unknown[]) => void) => ee.on(e, l),
    off: (e: string, l: (...a: unknown[]) => void) => ee.off(e, l),
    isClosed: () => false,
    mainFrame: () => main,
    frames: () => frames,
  };
  return {
    page: page as unknown as Page,
    navigate(to: string, headers: Record<string, string> = {}, status = 200) {
      ee.emit('response', {
        request: () => ({ isNavigationRequest: () => true }),
        frame: () => main,
        url: () => to,
        status: () => status,
        headers: () => headers,
      });
      current = to;
      ee.emit('framenavigated', main);
    },
    request(u: string) {
      ee.emit('request', { url: () => u });
    },
    subresource(u: string, headers: Record<string, string>) {
      ee.emit('response', {
        request: () => ({ isNavigationRequest: () => false }),
        frame: () => main,
        url: () => u,
        status: () => 200,
        headers: () => headers,
      });
    },
    addFrame(u: string, box: { width: number; height: number } | null, visible = true) {
      frames.push({
        url: () => u,
        isDetached: () => false,
        frameElement: async () => ({
          isVisible: async () => visible,
          boundingBox: async () => (box ? { x: 0, y: 0, ...box } : null),
          dispose: async () => {},
        }),
      });
    },
  };
}

describe('detectHumanCheck', () => {
  it('a challenge header on the current main document is positive', async () => {
    const f = fakePage('https://site.example/');
    const w = new ChallengeWatch(f.page);
    f.navigate('https://site.example/login', { 'x-amzn-waf-action': 'captcha' }, 405);
    expect(await detectHumanCheck(f.page, w)).toEqual({ provider: 'aws-waf' });
    f.navigate('https://site.example/account');
    expect(await detectHumanCheck(f.page, w)).toBeNull();
  });

  it('a challenge header on a subresource is not a signal', async () => {
    const f = fakePage('https://site.example/');
    const w = new ChallengeWatch(f.page);
    f.subresource('https://site.example/api', { 'cf-mitigated': 'challenge' });
    expect(await detectHumanCheck(f.page, w)).toBeNull();
  });

  it('a script host alone is not a challenge', async () => {
    const f = fakePage('https://site.example/login');
    const w = new ChallengeWatch(f.page);
    f.request('https://challenges.cloudflare.com/turnstile/v0/api.js');
    f.request('https://www.google.com/recaptcha/api.js');
    expect(w.requestedHosts().sort()).toEqual(['challenges.cloudflare.com', 'www.google.com']);
    expect(await detectHumanCheck(f.page, w)).toBeNull();
    f.navigate('https://site.example/next');
    expect(w.requestedHosts()).toEqual([]);
  });

  it('a visible interactive widget of at least 60×60 is positive', async () => {
    const f = fakePage('https://site.example/login');
    f.addFrame('https://challenges.cloudflare.com/x/turnstile', { width: 300, height: 65 });
    expect(await detectHumanCheck(f.page, new ChallengeWatch(f.page))).toEqual({
      provider: 'cloudflare',
    });
  });

  it('invisible, hidden or tiny widgets are not', async () => {
    const f = fakePage('https://site.example/login');
    f.addFrame('https://www.google.com/recaptcha/api2/anchor?size=invisible', {
      width: 256,
      height: 60,
    });
    f.addFrame('https://challenges.cloudflare.com/x/turnstile', { width: 300, height: 65 }, false);
    f.addFrame('https://newassets.hcaptcha.com/x#frame=checkbox', { width: 59, height: 300 });
    f.addFrame('https://newassets.hcaptcha.com/x#frame=challenge', null);
    f.addFrame('https://evil.localhost/recaptcha/api2/bframe', { width: 400, height: 580 });
    expect(await detectHumanCheck(f.page, new ChallengeWatch(f.page))).toBeNull();
  });

  it('a frame whose element cannot be read counts as no', async () => {
    const f = fakePage('https://site.example/login');
    const p = f.page as unknown as { frames: () => FakeFrame[] };
    p.frames().push({
      url: () => 'https://challenges.cloudflare.com/x',
      isDetached: () => false,
      frameElement: () => Promise.reject(new Error('detached')),
    });
    expect(await detectHumanCheck(f.page, null)).toBeNull();
  });
});
