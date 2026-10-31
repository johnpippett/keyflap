import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PAGE_DIR = fileURLToPath(new URL('./page/', import.meta.url));

export const STATIC: Readonly<Record<string, { file: string; type: string }>> = {
  '/': { file: 'app.html', type: 'text/html; charset=utf-8' },
  '/pair': { file: 'app.html', type: 'text/html; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
  '/approval-check.js': { file: 'approval-check.js', type: 'text/javascript; charset=utf-8' },
  '/app.css': { file: 'app.css', type: 'text/css; charset=utf-8' },
  '/sw.js': { file: 'sw.js', type: 'text/javascript; charset=utf-8' },
  '/manifest.webmanifest': { file: 'manifest.webmanifest', type: 'application/manifest+json' },
  '/handoff': { file: 'handoff.html', type: 'text/html; charset=utf-8' },
  '/handoff.js': { file: 'handoff.js', type: 'text/javascript; charset=utf-8' },
  '/handoff-zoom.js': { file: 'handoff-zoom.js', type: 'text/javascript; charset=utf-8' },
  '/handoff.css': { file: 'handoff.css', type: 'text/css; charset=utf-8' },
  '/brand/barlow-condensed-700.woff2': {
    file: 'brand/barlow-condensed-700.woff2',
    type: 'font/woff2',
  },
  '/brand/barlow-400.woff2': { file: 'brand/barlow-400.woff2', type: 'font/woff2' },
  '/brand/barlow-600.woff2': { file: 'brand/barlow-600.woff2', type: 'font/woff2' },
  '/brand/mark.svg': { file: 'brand/mark.svg', type: 'image/svg+xml' },
  '/brand/icon.svg': { file: 'brand/icon.svg', type: 'image/svg+xml' },
  '/brand/icon-192.png': { file: 'brand/icon-192.png', type: 'image/png' },
  '/brand/icon-512.png': { file: 'brand/icon-512.png', type: 'image/png' },
  '/brand/icon-maskable-512.png': { file: 'brand/icon-maskable-512.png', type: 'image/png' },
  '/brand/apple-touch-icon.png': { file: 'brand/apple-touch-icon.png', type: 'image/png' },
  '/apple-touch-icon.png': { file: 'brand/apple-touch-icon.png', type: 'image/png' },
};

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "manifest-src 'self'",
  "worker-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

const VERSIONED_LINKS = ['app.html', 'handoff.html', 'manifest.webmanifest'];

export function loadPageFiles(dir: string = PAGE_DIR): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  for (const { file } of Object.values(STATIC)) {
    if (!files.has(file)) files.set(file, readFileSync(join(dir, file)));
  }
  for (const file of VERSIONED_LINKS) {
    files.set(file, Buffer.from(versionBrandLinks((files.get(file) as Buffer).toString(), files)));
  }
  return files;
}

export function versionBrandLinks(text: string, files: ReadonlyMap<string, Buffer>): string {
  return text.replace(/(["'])(\/brand\/[a-z0-9.-]+)\1/g, (link, quote: string, path: string) => {
    const s = STATIC[path];
    const body = s && files.get(s.file);
    if (!body) return link;
    const v = createHash('sha256').update(body).digest('hex').slice(0, 12);
    return `${quote}${path}?v=${v}${quote}`;
  });
}

export function securityHeaders(origin: string): Record<string, string> {
  return {
    'content-security-policy': CSP,
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'cache-control': 'no-store',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
    'permissions-policy': 'publickey-credentials-get=(self), publickey-credentials-create=(self)',
    ...(origin.startsWith('https:') ? { 'strict-transport-security': 'max-age=31536000' } : {}),
  };
}

export const isLoopback = (h: string) => h === '127.0.0.1' || h === '::1' || h === 'localhost';
export const isLocalhostName = (h: string) => h === 'localhost' || h.endsWith('.localhost');

export function approverOriginUrl(origin: string): URL {
  const url = new URL(origin);
  if (url.origin !== origin) throw new Error('approver origin must be a bare origin');
  const local = url.protocol === 'http:' && isLocalhostName(url.hostname);
  if (url.protocol !== 'https:' && !local) {
    throw new Error('approver origin must be https: (http: only on *.localhost, for tests)');
  }
  return url;
}

export function allowedHostsFor(
  origin: string,
  listen: { host: string; port: number; tls: boolean },
  boundPort: number,
): Set<string> {
  const url = new URL(origin);
  const hosts = new Set([url.host]);
  if (!listen.tls && isLoopback(listen.host)) {
    hosts.add(`127.0.0.1:${boundPort}`);
    hosts.add(`localhost:${boundPort}`);
    hosts.add(`[::1]:${boundPort}`);
  }
  if (url.port === '' && listen.port === 0) hosts.add(`${url.hostname}:${boundPort}`);
  return hosts;
}
