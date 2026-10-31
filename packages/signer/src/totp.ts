import { createHmac } from 'node:crypto';

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface TotpParams {
  secret: string;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input: string): Buffer | null {
  const clean = input.replace(/[\s-]/g, '').toUpperCase().replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) return null;
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = ((value << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function normalizeTotp(raw: unknown): TotpParams | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.secret !== 'string' || r.secret.length > 1024) return null;
  const key = base32Decode(r.secret);
  if (!key || key.length < 10 || key.length > 128) return null;
  const algorithm = r.algorithm ?? 'SHA1';
  if (algorithm !== 'SHA1' && algorithm !== 'SHA256' && algorithm !== 'SHA512') return null;
  const digits = r.digits ?? 6;
  const period = r.period ?? 30;
  if (!Number.isInteger(digits) || (digits as number) < 6 || (digits as number) > 8) return null;
  if (!Number.isInteger(period) || (period as number) < 15 || (period as number) > 120) return null;
  return {
    secret: base32Encode(key),
    algorithm,
    digits: digits as number,
    period: period as number,
  };
}

export function hotp(key: Buffer, counter: number, digits: number, algorithm: TotpAlgorithm) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac(algorithm.toLowerCase(), key).update(msg).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return code.toString().padStart(digits, '0');
}

export function totpCode(p: TotpParams, nowMs: number): string {
  const key = base32Decode(p.secret);
  if (!key) throw new Error('bad totp secret');
  return hotp(key, Math.floor(nowMs / 1000 / p.period), p.digits, p.algorithm);
}
