import { describe, expect, it } from 'vitest';
import { validPassword } from '../../signer/src/server.ts';
import { REMEMBER_MIN } from '../src/handoff.ts';
import { MIN_SCRUBBED_LENGTH, secretForms } from '../src/scrub.ts';

describe('the shortest secret is the shortest string the scrubber can find', () => {
  it('the scrubber drops forms shorter than MIN_SCRUBBED_LENGTH and keeps the rest', () => {
    expect(secretForms('x'.repeat(MIN_SCRUBBED_LENGTH - 1))).toEqual([]);
    expect(secretForms('x'.repeat(MIN_SCRUBBED_LENGTH))).toContain('x'.repeat(MIN_SCRUBBED_LENGTH));
  });

  it('the signer refuses passwords the scrubber could not remove from tool output', () => {
    expect(validPassword('x'.repeat(MIN_SCRUBBED_LENGTH - 1))).toBe(false);
    expect(validPassword('x'.repeat(MIN_SCRUBBED_LENGTH))).toBe(true);
  });

  it('the handoff remembers every text the scrubber can remove, and none it cannot', () => {
    expect(REMEMBER_MIN).toBe(MIN_SCRUBBED_LENGTH);
  });
});
