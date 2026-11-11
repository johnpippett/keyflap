import type { ApprovalStatement } from '@aab/signer/approval';

export type CardState =
  | { kind: 'queued' }
  | { kind: 'signing'; statement: ApprovalStatement }
  | { kind: 'approved' }
  | { kind: 'denied'; reason: string }
  | { kind: 'timed_out' };

export type CardEvent =
  | { kind: 'challenge'; statement: ApprovalStatement }
  | { kind: 'approve' }
  | { kind: 'deny'; reason: string }
  | { kind: 'timeout' };

export function nextCardState(state: CardState, event: CardEvent): CardState {
  switch (state.kind) {
    case 'queued':
    case 'signing':
      switch (event.kind) {
        case 'challenge':
          return { kind: 'signing', statement: event.statement };
        case 'approve':
          return state.kind === 'signing' ? { kind: 'approved' } : state;
        case 'deny':
          return { kind: 'denied', reason: event.reason };
        case 'timeout':
          return { kind: 'timed_out' };
        default: {
          const unhandled: never = event;
          return unhandled;
        }
      }
    case 'approved':
    case 'denied':
    case 'timed_out':
      return state;
    default: {
      const unhandled: never = state;
      return unhandled;
    }
  }
}

export function signingStatement(state: CardState): ApprovalStatement | null {
  return state.kind === 'signing' ? state.statement : null;
}
