import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import {
  decodeAttestationObject,
  decodeCredentialPublicKey,
  parseAuthenticatorData,
} from '@simplewebauthn/server/helpers';
import { describe, expect, it } from 'vitest';
import {
  AAGUID_NONE,
  buildAuthenticatorData,
  buildClientDataJSON,
  buildNoneAttestationObject,
  cborEncode,
  coseEs256PublicKey,
  FLAG_AT,
  FLAG_UP,
  spkiP256,
} from '../src/encoding.ts';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('CBOR encoder (RFC 8949 appendix A vectors)', () => {
  it.each([
    [0, '00'],
    [23, '17'],
    [24, '1818'],
    [1000, '1903e8'],
    [1000000, '1a000f4240'],
    [-1, '20'],
    [-7, '26'],
    [-1000, '3903e7'],
    ['IETF', '6449455446'],
    [new Uint8Array([1, 2, 3, 4]), '4401020304'],
    [[1, [2, 3]], '820182020 3'.replace(' ', '')],
  ])('%j', (v, expected) => {
    expect(hex(cborEncode(v as never))).toBe(expected);
  });

  it('sorts map keys canonically (length, then bytes)', () => {
    const m = new Map<number | string, never>([
      ['aa', 1 as never],
      [-1, 2 as never],
      [1, 3 as never],
      ['b', 4 as never],
    ]);
    expect(hex(cborEncode(m))).toBe('a4' + '0103' + '2002' + '616204' + '62616101');
  });
});

describe('WebAuthn structures decode with an independent implementation', () => {
  const x = new Uint8Array(32).fill(1);
  const y = new Uint8Array(32).fill(2);

  it('COSE ES256 key', () => {
    const decoded = decodeCredentialPublicKey(
      coseEs256PublicKey(x, y) as Uint8Array<ArrayBuffer>,
    ) as unknown as Map<number, unknown>;
    expect(decoded.get(1)).toBe(2);
    expect(decoded.get(3)).toBe(-7);
    expect(decoded.get(-1)).toBe(1);
    expect(hex(decoded.get(-2) as Uint8Array)).toBe(hex(x));
    expect(hex(decoded.get(-3) as Uint8Array)).toBe(hex(y));
  });

  it('none attestation object with attested credential data', () => {
    const credentialId = new Uint8Array(32).fill(9);
    const authData = buildAuthenticatorData({
      rpId: 'example.com',
      flags: FLAG_UP | FLAG_AT,
      attested: { aaguid: AAGUID_NONE, credentialId, cosePublicKey: coseEs256PublicKey(x, y) },
    });
    const att = decodeAttestationObject(
      buildNoneAttestationObject(authData) as Uint8Array<ArrayBuffer>,
    );
    expect(att.get('fmt')).toBe('none');
    expect(att.get('attStmt').size).toBe(0);
    const parsed = parseAuthenticatorData(att.get('authData'));
    expect(hex(parsed.rpIdHash)).toBe(createHash('sha256').update('example.com').digest('hex'));
    expect(parsed.flags).toMatchObject({
      up: true,
      uv: false,
      at: true,
      be: false,
      bs: false,
      ed: false,
    });
    expect(parsed.counter).toBe(0);
    expect(hex(parsed.credentialID as Uint8Array)).toBe(hex(credentialId));
  });

  it('assertion authenticatorData is exactly 37 bytes', () => {
    expect(buildAuthenticatorData({ rpId: 'example.com', flags: FLAG_UP })).toHaveLength(37);
  });

  it('clientDataJSON is valid JSON carrying exactly the given origin', () => {
    const cd = JSON.parse(
      new TextDecoder().decode(buildClientDataJSON('webauthn.get', 'abc', 'https://a.example')),
    );
    expect(cd).toEqual({
      type: 'webauthn.get',
      challenge: 'abc',
      origin: 'https://a.example',
      crossOrigin: false,
    });
  });

  it('SPKI round-trips a real P-256 public key', () => {
    const real = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
      format: 'jwk',
    });
    const rx = new Uint8Array(Buffer.from(real.x as string, 'base64url'));
    const ry = new Uint8Array(Buffer.from(real.y as string, 'base64url'));
    const jwk = createPublicKey({
      key: Buffer.from(spkiP256(rx, ry)),
      format: 'der',
      type: 'spki',
    }).export({ format: 'jwk' });
    expect(jwk).toEqual({ kty: 'EC', crv: 'P-256', x: real.x, y: real.y });
  });
});
