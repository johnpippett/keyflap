export interface SourceItemInfo {
  ref: string;
  hosts: string[];
  username: string | null;
  hasTotp: boolean;
}

export interface SourceSecret {
  hosts: string[];
  password: string;
  totp: { secret: string; algorithm?: string; digits?: number; period?: number } | null;
}

export interface CredentialSource {
  readonly kind: string;
  list(): Promise<SourceItemInfo[]>;
  fetch(ref: string, reason: string): Promise<SourceSecret>;
}

export class SourceError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason);
    this.reason = reason;
  }
}

export function loginHosts(urls: readonly unknown[]): string[] {
  const out = new Set<string>();
  for (const u of urls) {
    if (typeof u !== 'string') continue;
    const s = u.trim();
    if (s.length === 0 || s.length > 2048) continue;
    const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(s);
    if (hasScheme && !/^https?:\/\//i.test(s)) continue;
    let host: string;
    try {
      host = new URL(hasScheme ? s : `https://${s}`).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (!host.includes('.') || host.startsWith('[') || /^[\d.]+$/.test(host)) continue;
    out.add(host.replace(/\.$/, ''));
  }
  return [...out];
}

export function parseTotpUri(input: string): SourceSecret['totp'] {
  const s = input.trim();
  if (s.length === 0) return null;
  if (!/^otpauth:/i.test(s)) return { secret: s };
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return null;
  }
  if (url.host.toLowerCase() !== 'totp') return null;
  const secret = url.searchParams.get('secret');
  if (!secret) return null;
  const out: NonNullable<SourceSecret['totp']> = { secret };
  const alg = url.searchParams.get('algorithm');
  if (alg) out.algorithm = alg.toUpperCase();
  const digits = url.searchParams.get('digits');
  if (digits) out.digits = Number(digits);
  const period = url.searchParams.get('period');
  if (period) out.period = Number(period);
  return out;
}
