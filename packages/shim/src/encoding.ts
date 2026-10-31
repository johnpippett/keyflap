import { createHash } from 'node:crypto';

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_AT = 0x40;

export const AAGUID_NONE = new Uint8Array(16);

export const COSE_ALG_ES256 = -7;

export type CborValue =
  | number
  | string
  | Uint8Array
  | CborValue[]
  | Map<number | string, CborValue>;

function head(major: number, n: number): Uint8Array {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
  if (n < 0x100000000) {
    const b = new Uint8Array(5);
    b[0] = (major << 5) | 26;
    new DataView(b.buffer).setUint32(1, n);
    return b;
  }
  throw new Error('cbor: integer too large');
}

export function cborEncode(v: CborValue): Uint8Array {
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('cbor: only integers supported');
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (typeof v === 'string') {
    const bytes = new TextEncoder().encode(v);
    return concat(head(3, bytes.length), bytes);
  }
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(cborEncode));
  const entries = [...v.entries()].map(([k, val]) => [cborEncode(k), cborEncode(val)] as const);
  entries.sort(([a], [b]) => a.length - b.length || compareBytes(a, b));
  return concat(head(5, entries.length), ...entries.flat());
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

export function buildClientDataJSON(
  type: 'webauthn.get' | 'webauthn.create',
  challengeB64url: string,
  verifiedOrigin: string,
): Uint8Array {
  const json = `{"type":${JSON.stringify(type)},"challenge":${JSON.stringify(challengeB64url)},"origin":${JSON.stringify(verifiedOrigin)},"crossOrigin":false}`;
  return new TextEncoder().encode(json);
}

export function coseEs256PublicKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  if (x.length !== 32 || y.length !== 32) throw new Error('bad P-256 coordinates');
  return cborEncode(
    new Map<number, CborValue>([
      [1, 2],
      [3, COSE_ALG_ES256],
      [-1, 1],
      [-2, x],
      [-3, y],
    ]),
  );
}

export function spkiP256(x: Uint8Array, y: Uint8Array): Uint8Array {
  const prefix = Uint8Array.from(
    Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
  );
  return concat(prefix, Uint8Array.of(0x04), x, y);
}

export function buildAuthenticatorData(opts: {
  rpId: string;
  flags: number;
  signCount?: number;
  attested?: { aaguid: Uint8Array; credentialId: Uint8Array; cosePublicKey: Uint8Array };
}): Uint8Array {
  const counter = new Uint8Array(4);
  new DataView(counter.buffer).setUint32(0, opts.signCount ?? 0);
  const parts = [sha256(opts.rpId), Uint8Array.of(opts.flags), counter];
  if (opts.attested) {
    const { aaguid, credentialId, cosePublicKey } = opts.attested;
    if (aaguid.length !== 16) throw new Error('bad aaguid');
    if (credentialId.length > 1023) throw new Error('credential id too long');
    parts.push(
      aaguid,
      Uint8Array.of(credentialId.length >> 8, credentialId.length & 0xff),
      credentialId,
      cosePublicKey,
    );
  }
  return concat(...parts);
}

export function buildNoneAttestationObject(authData: Uint8Array): Uint8Array {
  return cborEncode(
    new Map<string, CborValue>([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authData],
    ]),
  );
}

export const b64url = {
  encode: (b: Uint8Array) => Buffer.from(b).toString('base64url'),
  decode: (s: string): Uint8Array => {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('invalid base64url');
    return new Uint8Array(Buffer.from(s, 'base64url'));
  },
};
