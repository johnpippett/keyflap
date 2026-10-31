import { describe, expect, it } from 'vitest';
import { sourceFiles } from './source-tree.ts';

const RESERVED = /(?:^|\.)(?:example|test|invalid|localhost)$|(?:^|\.)example\.(?:com|net|org)$/;

function localOrReserved(authority: string): boolean {
  const host = authority
    .replace(/^.*@/, '')
    .replace(/:[^:\]]*$/, '')
    .replace(/\.$/, '');
  return (
    host.startsWith('$') ||
    !host.includes('.') ||
    host === '[::1]' ||
    /^127(?:\.\d+){3}$/.test(host) ||
    RESERVED.test(host)
  );
}

const URL_HOST = String.raw`(['"\x60])https?:\/\/([^/'"\x60\s?#]+)`;
const anyUrl = (text: string): string[] =>
  [...text.matchAll(/https?:\/\/([^/'"\x60\s?#]+)/g)].map((m) => m[1] as string);
const SINK = String.raw`\b(?:goto|fetch|WebSocket|browser_open)\b[^;\n]{0,80}?`;
const sinkUrls = (text: string): string[] =>
  [...text.matchAll(new RegExp(SINK + URL_HOST, 'g'))].map((m) => m[2] as string);

const SCRIPTS = /\.(?:mjs|js|ts|sh)$/;
const SAMPLES_FILE = 'packages/approver/test/local-hosts-only.test.ts';
const tests = sourceFiles('packages').filter(
  (f) => f.path.includes('/test/') && f.path !== SAMPLES_FILE,
);
const scripts = [
  ...sourceFiles('.claude/skills', SCRIPTS).filter((f) => f.path.includes('/scripts/')),
  ...sourceFiles('packages/test-rp/src'),
];

describe('automated tests only reach the local test relying party', () => {
  it('the host check takes local and reserved names and refuses real sites', () => {
    for (const ok of [
      'rp.localhost:3000',
      'localhost',
      '127.0.0.1:8765',
      '[::1]:9',
      'insecure.test',
      'login.example.com',
      'a.example',
      'x',
      `\${host}:\${port}`,
    ]) {
      expect(localOrReserved(ok), ok).toBe(true);
    }
    for (const bad of [
      'www.google.com',
      'github.com',
      'example.com.evil.net',
      'notexample.com',
      'evil.com',
      'user@bank.com',
    ]) {
      expect(localOrReserved(bad), bad).toBe(false);
    }
  });

  it('the sink scan reads the address a test navigates to or fetches, not fixture strings', () => {
    expect(sinkUrls("await page.goto('https://www.paypal.com/login');")).toEqual([
      'www.paypal.com',
    ]);
    expect(sinkUrls(`const r = await fetch(\`http://rp.localhost:\${port}/x\`);`)).toEqual([
      `rp.localhost:\${port}`,
    ]);
    expect(sinkUrls("h.mcp.ok('browser_open', { url: 'https://github.com/' });")).toEqual([
      'github.com',
    ]);
    expect(sinkUrls("f.request('https://challenges.cloudflare.com/api.js');")).toEqual([]);
    expect(sinkUrls(`await page.goto(\`\${rp.url}login\`);`)).toEqual([]);
  });

  it('no test navigates to or fetches a real site', () => {
    const reached = tests.flatMap((f) => sinkUrls(f.text).map((host) => ({ path: f.path, host })));
    expect(reached.length).toBeGreaterThan(0);
    expect(reached.filter((r) => !localOrReserved(r.host))).toEqual([]);
  });

  it('the skill scripts and the test relying party name no real site at all', () => {
    expect(scripts.length).toBeGreaterThan(0);
    const named = scripts.flatMap((f) => anyUrl(f.text).map((host) => ({ path: f.path, host })));
    expect(named.length).toBeGreaterThan(0);
    expect(named.filter((r) => !localOrReserved(r.host))).toEqual([]);
  });
});
