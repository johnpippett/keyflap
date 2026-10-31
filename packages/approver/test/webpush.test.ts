import { createECDH, createPublicKey, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { encryptPush, VapidKey, validPushEndpoint } from '../src/webpush.ts';

describe('web push', () => {
  it('encrypts exactly as RFC 8291 appendix A', () => {
    const ua = createECDH('prime256v1');
    ua.setPrivateKey(Buffer.from('q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94', 'base64url'));
    const out = encryptPush(
      {
        endpoint: 'https://push.example.net/x',
        keys: {
          p256dh: ua.getPublicKey().toString('base64url'),
          auth: 'BTBZMqHH6r4Tts7J_aSIgg',
        },
      },
      Buffer.from('When I grow up, I want to be a watermelon'),
      {
        ephemeralPrivateKey: Buffer.from(
          'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
          'base64url',
        ),
        salt: Buffer.from('DGv6ra1nlYgDCS1FRnbzlw', 'base64url'),
      },
    );
    expect(ua.getPublicKey().toString('base64url')).toBe(
      'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
    );
    expect(out.toString('base64url')).toBe(
      'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
    );
  });

  it('signs a VAPID JWT for the endpoint origin with its public key', () => {
    const vapid = VapidKey.generate();
    const now = Date.UTC(2026, 0, 1);
    const header = vapid.authorization(
      'https://fcm.googleapis.com/fcm/send/abc',
      'mailto:a@b',
      now,
    );
    const m = /^vapid t=([^,]+), k=(.+)$/.exec(header);
    expect(m).not.toBeNull();
    const [h, c, s] = String(m?.[1]).split('.') as [string, string, string];
    expect(JSON.parse(Buffer.from(h, 'base64url').toString())).toEqual({
      typ: 'JWT',
      alg: 'ES256',
    });
    expect(JSON.parse(Buffer.from(c, 'base64url').toString())).toEqual({
      aud: 'https://fcm.googleapis.com',
      exp: now / 1000 + 12 * 3600,
      sub: 'mailto:a@b',
    });
    const raw = Buffer.from(m?.[2] as string, 'base64url');
    expect(raw.length).toBe(65);
    const pub = createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: raw.subarray(1, 33).toString('base64url'),
        y: raw.subarray(33).toString('base64url'),
      },
      format: 'jwk',
    });
    expect(
      verify(
        'sha256',
        Buffer.from(`${h}.${c}`),
        { key: pub, dsaEncoding: 'ieee-p1363' },
        Buffer.from(s, 'base64url'),
      ),
    ).toBe(true);
  });

  it('accepts only https push endpoints on real hostnames', () => {
    expect(validPushEndpoint('https://fcm.googleapis.com/fcm/send/x')).toBe(true);
    expect(validPushEndpoint('https://web.push.apple.com/abc')).toBe(true);
    expect(validPushEndpoint('https://updates.push.services.mozilla.com/wpush/v2/x')).toBe(true);
    for (const bad of [
      'http://fcm.googleapis.com/x',
      'https://127.0.0.1/x',
      'https://[::1]/x',
      'https://localhost/x',
      'https://push.localhost/x',
      'https://user:pw@push.example.com/x',
      'https://intranet/x',
      'https://intranet.corp.example/x',
      'https://fcm.googleapis.com:8443/x',
      'https://evilfcm.googleapis.com.example/x',
      'file:///etc/passwd',
      42,
    ]) {
      expect(validPushEndpoint(bad), String(bad)).toBe(false);
    }
  });
});
