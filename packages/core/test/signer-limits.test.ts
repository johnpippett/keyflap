import { HANDOFF_GRANT_MAX_MS, MAX_GRANT_MS } from '@aab/signer/approval';
import { describe, expect, it } from 'vitest';
import { DEFAULT_HANDOFF_TTL_MS } from '../src/handoff.ts';
import { ALLOW_FOR_MAX_MS } from '../src/policy.ts';

describe('core time limits stay in step with the signer that enforces them', () => {
  it('the longest allow-for window is the longest grant the signer accepts', () => {
    expect(ALLOW_FOR_MAX_MS).toBe(MAX_GRANT_MS);
  });

  it('a handoff ends before the single-use grant the signer issues for it expires', () => {
    expect(DEFAULT_HANDOFF_TTL_MS).toBeLessThan(HANDOFF_GRANT_MAX_MS);
  });
});
