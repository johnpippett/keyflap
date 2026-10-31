import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

interface Rules {
  normal: Set<string>;
  wildcard: Set<string>;
  exception: Set<string>;
  version: string;
}

const PSL_FILE = new URL('./psl/public_suffix_list.dat', import.meta.url);
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MIN_RULES = 5000;

let cached: Rules | Error | undefined;

export function parsePublicSuffixList(text: string): Rules {
  for (const marker of [
    '// ===BEGIN ICANN DOMAINS===',
    '// ===END ICANN DOMAINS===',
    '// ===BEGIN PRIVATE DOMAINS===',
    '// ===END PRIVATE DOMAINS===',
  ]) {
    if (!text.includes(marker)) throw new Error(`public suffix list: missing ${marker}`);
  }
  const version = /^\/\/ VERSION: (\S+)$/m.exec(text)?.[1] ?? 'unknown';
  const rules: Rules = { normal: new Set(), wildcard: new Set(), exception: new Set(), version };
  for (const raw of text.split('\n')) {
    const line = raw.trim().split(/\s/)[0] ?? '';
    if (line === '' || line.startsWith('//')) continue;
    let set = rules.normal;
    let body = line;
    if (body.startsWith('!')) {
      set = rules.exception;
      body = body.slice(1);
    } else if (body.startsWith('*.')) {
      set = rules.wildcard;
      body = body.slice(2);
    }
    const ascii = domainToASCII(body);
    if (!ascii?.split('.').every((l) => LABEL.test(l))) {
      throw new Error(`public suffix list: bad rule ${JSON.stringify(line)}`);
    }
    set.add(ascii);
  }
  const n = rules.normal.size + rules.wildcard.size + rules.exception.size;
  if (n < MIN_RULES) throw new Error(`public suffix list: only ${n} rules`);
  return rules;
}

function rules(): Rules | null {
  if (cached === undefined) {
    try {
      cached = parsePublicSuffixList(readFileSync(PSL_FILE, 'utf8'));
    } catch (err) {
      cached = err instanceof Error ? err : new Error(String(err));
    }
  }
  return cached instanceof Error ? null : cached;
}

export function loadPublicSuffixList(): { version: string } {
  rules();
  if (cached instanceof Error) throw cached;
  return { version: (cached as Rules).version };
}

function hostLabels(host: unknown): string[] | null {
  if (typeof host !== 'string' || host.length === 0 || host.length > 253) return null;
  if (host !== host.toLowerCase() || isIP(host) !== 0) return null;
  const labels = host.split('.');
  return labels.every((l) => LABEL.test(l)) ? labels : null;
}

function suffixLength(labels: string[], r: Rules): number {
  const n = labels.length;
  for (let i = 0; i < n; i++) {
    if (r.exception.has(labels.slice(i).join('.'))) return n - i - 1;
  }
  let len = 1;
  for (let i = 0; i < n; i++) {
    const l = n - i;
    if (l <= len) break;
    if (r.normal.has(labels.slice(i).join('.'))) len = l;
    else if (i + 1 < n && r.wildcard.has(labels.slice(i + 1).join('.'))) len = l;
  }
  return len;
}

export function registrableDomain(host: string): string | null {
  const labels = hostLabels(host);
  const r = rules();
  if (!labels || !r) return null;
  const len = suffixLength(labels, r);
  return labels.length > len ? labels.slice(labels.length - len - 1).join('.') : null;
}

export function rpIdAllowedForHost(rpId: string, host: string): boolean {
  if (!hostLabels(rpId) || !hostLabels(host)) return false;
  if (host === 'localhost') return rpId === 'localhost';
  const reg = registrableDomain(host);
  if (!reg) return false;
  if (rpId !== host && !host.endsWith(`.${rpId}`)) return false;
  return rpId === reg || rpId.endsWith(`.${reg}`);
}
