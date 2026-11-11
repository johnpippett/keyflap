import type { ApprovalStatement } from '@aab/signer/approval';
import { describe, expect, it } from 'vitest';
import {
  type CardEvent,
  type CardState,
  nextCardState,
  signingStatement,
} from '../src/approval-card.ts';

const stmt = (requestId: string): ApprovalStatement => ({
  v: 1,
  requestId,
  kind: 'fill',
  verifiedOrigin: 'https://example.com',
  rpId: 'example.com',
  credentialId: 'item-1',
  intentHash: 'aW50ZW50',
  clientDataHash: 'c2NvcGU',
  userVerified: true,
  issuedAt: 1,
  expiresAt: 2,
});

const A = stmt('a');
const B = stmt('b');

const states: Record<CardState['kind'], CardState> = {
  queued: { kind: 'queued' },
  signing: { kind: 'signing', statement: A },
  approved: { kind: 'approved' },
  denied: { kind: 'denied', reason: 'user_denied' },
  timed_out: { kind: 'timed_out' },
};

const events: Record<CardEvent['kind'], CardEvent> = {
  challenge: { kind: 'challenge', statement: B },
  approve: { kind: 'approve' },
  deny: { kind: 'deny', reason: 'aborted' },
  timeout: { kind: 'timeout' },
};

const moves: Partial<Record<CardState['kind'], Partial<Record<CardEvent['kind'], CardState>>>> = {
  queued: {
    challenge: { kind: 'signing', statement: B },
    deny: { kind: 'denied', reason: 'aborted' },
    timeout: { kind: 'timed_out' },
  },
  signing: {
    challenge: { kind: 'signing', statement: B },
    approve: { kind: 'approved' },
    deny: { kind: 'denied', reason: 'aborted' },
    timeout: { kind: 'timed_out' },
  },
};

describe('approval card states: every state against every event', () => {
  for (const k of Object.keys(states) as CardState['kind'][]) {
    for (const e of Object.keys(events) as CardEvent['kind'][]) {
      const want = moves[k]?.[e];
      it(`${k} + ${e} -> ${want ? want.kind : 'unchanged'}`, () => {
        const next = nextCardState(states[k], events[e]);
        if (want) expect(next).toEqual(want);
        else expect(next).toBe(states[k]);
      });
    }
  }

  it('one statement per card: the latest challenge replaces it', () => {
    expect(signingStatement(states.queued)).toBeNull();
    const a = nextCardState(states.queued, { kind: 'challenge', statement: A });
    const b = nextCardState(a, { kind: 'challenge', statement: B });
    expect(signingStatement(a)).toBe(A);
    expect(signingStatement(b)).toBe(B);
    for (const k of ['approved', 'denied', 'timed_out'] as const) {
      expect(signingStatement(states[k])).toBeNull();
    }
  });
});
