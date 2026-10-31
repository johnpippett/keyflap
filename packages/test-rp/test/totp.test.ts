import { describe, expect, it } from 'vitest';
import { hotp, totp, verifyTotp } from '../src/totp.ts';

const RFC_KEY = Buffer.from('12345678901234567890', 'ascii');
const RFC_KEY_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('totp', () => {
  it('matches RFC 4226 HOTP vectors', () => {
    const expected = ['755224', '287082', '359152', '969429', '338314'];
    expected.forEach((code, i) => {
      expect(hotp(RFC_KEY, i)).toBe(code);
    });
  });

  it('matches RFC 6238 TOTP vectors (6-digit truncation)', () => {
    expect(totp(RFC_KEY_B32, 59_000, 30, 8)).toBe('94287082');
    expect(totp(RFC_KEY_B32, 1111111109_000, 30, 8)).toBe('07081804');
    expect(totp(RFC_KEY_B32, 1234567890_000, 30, 8)).toBe('89005924');
  });

  it('accepts one step of drift and rejects more', () => {
    const now = 1_700_000_000_000;
    expect(verifyTotp(RFC_KEY_B32, totp(RFC_KEY_B32, now - 30_000), now)).toBe(true);
    expect(verifyTotp(RFC_KEY_B32, totp(RFC_KEY_B32, now - 90_000), now)).toBe(false);
  });
});
