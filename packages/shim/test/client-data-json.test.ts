import { describe, expect, it } from 'vitest';
import { buildClientDataJSON } from '../src/encoding.ts';

const utf8 = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe('clientDataJSON bytes follow WebAuthn 5.8.1.1, the order browsers emit', () => {
  it.each([
    ['webauthn.get', 'abc-DEF_123'],
    ['webauthn.create', 'abc-DEF_123'],
  ] as const)(
    '%s: type, challenge, origin, crossOrigin, nothing else, no whitespace',
    (type, challenge) => {
      expect(utf8(buildClientDataJSON(type, challenge, 'https://a.example'))).toBe(
        `{"type":"${type}","challenge":"abc-DEF_123","origin":"https://a.example","crossOrigin":false}`,
      );
    },
  );

  it('keeps a port in the origin and escapes with JSON.stringify rules', () => {
    expect(utf8(buildClientDataJSON('webauthn.get', 'c', 'http://rp.localhost:3000'))).toBe(
      '{"type":"webauthn.get","challenge":"c","origin":"http://rp.localhost:3000","crossOrigin":false}',
    );
    expect(utf8(buildClientDataJSON('webauthn.get', 'c', 'https://a"b.example'))).toBe(
      '{"type":"webauthn.get","challenge":"c","origin":"https://a\\"b.example","crossOrigin":false}',
    );
  });
});
