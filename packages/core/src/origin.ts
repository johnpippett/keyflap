import { isIP } from 'node:net';
import { type TrustedFrame, trustedFrame } from '@aab/shim';
import type { Page } from 'playwright';
import { getDomain } from 'tldts';

export type OriginCheck =
  | { ok: true; origin: string; host: string }
  | { ok: false; reason: string };

export function isLocalhost(host: string): boolean {
  return host === 'localhost' || host.endsWith('.localhost');
}

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function canonicalHost(host: string): string | null {
  if (typeof host !== 'string' || host.length === 0 || host.length > 253) return null;
  if (isIP(host.replace(/^\[|\]$/g, '')) !== 0) return null;
  return host.split('.').every((l) => LABEL.test(l)) ? host : null;
}

export function normalizeHost(input: string): string | null {
  if (typeof input !== 'string') return null;
  const raw = input.trim().replace(/^\./, '').replace(/\.$/, '');
  if (raw.length === 0 || raw.length > 253 || /[/?#@:\\\s]/.test(raw)) return null;
  let host: string;
  try {
    host = new URL(`https://${raw}/`).hostname;
  } catch {
    return null;
  }
  return canonicalHost(host);
}

export function canonicalOrigin(href: string): { origin: string; host: string } | null {
  let u: URL;
  try {
    u = new URL(href);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  const host = normalizeHost(u.hostname);
  if (!host) return null;
  return { origin: `${u.protocol}//${host}${u.port ? `:${u.port}` : ''}`, host };
}

export function checkOriginUrl(href: string): OriginCheck {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return { ok: false, reason: 'bad_frame_url' };
  }
  const host = url.hostname;
  if (url.protocol === 'https:') {
  } else if (url.protocol === 'http:' && isLocalhost(host)) {
  } else {
    return { ok: false, reason: 'insecure_origin' };
  }
  if (!host || isIP(host.replace(/^\[|\]$/g, '')) !== 0) return { ok: false, reason: 'ip_origin' };
  if (canonicalHost(host) !== host) return { ok: false, reason: 'non_canonical_host' };
  return { ok: true, origin: url.origin, host };
}

export function verifiedOriginFromFrame(frame: TrustedFrame): OriginCheck {
  if (!frame.isMainFrame) return { ok: false, reason: 'not_top_level_frame' };
  const o = checkOriginUrl(frame.url);
  if (!o.ok) return o;
  if (typeof frame.securityOrigin !== 'string' || frame.securityOrigin !== o.origin) {
    return { ok: false, reason: 'document_origin_mismatch' };
  }
  return o;
}

export function verifiedOriginOfPage(page: Page): OriginCheck {
  try {
    if (page.isClosed()) return { ok: false, reason: 'page_closed' };
    return verifiedOriginFromFrame(trustedFrame(page.mainFrame()));
  } catch {
    return { ok: false, reason: 'internal_error' };
  }
}

function isValidDomain(s: string): boolean {
  return canonicalHost(s) === s;
}

export function registrableDomain(host: string): string | null {
  if (canonicalHost(host) !== host) return null;
  if (isLocalhost(host)) {
    return host === 'localhost' ? null : (getDomain(host) ?? null);
  }
  return getDomain(host, { allowPrivateDomains: true }) ?? null;
}

export function rpIdAllowedForHost(rpId: string, host: string): boolean {
  if (typeof rpId !== 'string' || !isValidDomain(rpId) || !isValidDomain(host)) return false;
  if (host === 'localhost') return rpId === 'localhost';
  const reg = registrableDomain(host);
  if (!reg) return false;
  if (rpId !== host && !host.endsWith(`.${rpId}`)) return false;
  return rpId === reg || rpId.endsWith(`.${reg}`);
}
