import { describe, expect, it } from 'vitest';
import { Mailbox } from '../src/mailbox.ts';

const WINDOW = 60_000;

type State = 'empty' | 'unread' | 'stale' | 'read';
type Event = 'take' | 'take-other' | 'take-at-edge' | 'take-past-edge' | 'put';

function inState(state: State): { box: Mailbox<string>; now: number } {
  const box = new Mailbox<string>({ windowMs: WINDOW });
  switch (state) {
    case 'empty':
      return { box, now: 1_000 };
    case 'unread':
      box.put('a', 1_000);
      return { box, now: 1_000 };
    case 'stale':
      box.put('a', 1_000);
      return { box, now: 1_000 + WINDOW + 1 };
    case 'read':
      box.put('a', 1_000);
      box.take(1_000);
      return { box, now: 1_000 };
    default: {
      const unhandled: never = state;
      return unhandled;
    }
  }
}

function run(box: Mailbox<string>, now: number, event: Event): string | undefined {
  switch (event) {
    case 'take':
      return box.take(now);
    case 'take-other':
      return box.take(now, (v) => v === 'other');
    case 'take-at-edge':
      return box.take(1_000 + WINDOW);
    case 'take-past-edge':
      return box.take(1_000 + WINDOW + 1);
    case 'put':
      box.put('b', now);
      return box.take(now);
    default: {
      const unhandled: never = event;
      return unhandled;
    }
  }
}

const table: [State, Event, string | undefined, boolean][] = [
  ['empty', 'take', undefined, false],
  ['empty', 'take-other', undefined, false],
  ['empty', 'take-at-edge', undefined, false],
  ['empty', 'take-past-edge', undefined, false],
  ['empty', 'put', 'b', false],
  ['unread', 'take', 'a', false],
  ['unread', 'take-other', undefined, true],
  ['unread', 'take-at-edge', 'a', false],
  ['unread', 'take-past-edge', undefined, true],
  ['unread', 'put', 'b', false],
  ['stale', 'take', undefined, true],
  ['stale', 'take-other', undefined, true],
  ['stale', 'take-at-edge', 'a', false],
  ['stale', 'take-past-edge', undefined, true],
  ['stale', 'put', 'b', false],
  ['read', 'take', undefined, false],
  ['read', 'take-other', undefined, false],
  ['read', 'take-at-edge', undefined, false],
  ['read', 'take-past-edge', undefined, false],
  ['read', 'put', 'b', false],
];

describe('mailbox states: every state against every event', () => {
  it('covers each state and event once', () => {
    expect(new Set(table.map(([s, e]) => `${s} ${e}`)).size).toBe(20);
  });

  for (const [state, event, got, stillUnread] of table) {
    it(`${state} + ${event} -> ${got ?? 'nothing'}`, () => {
      const { box, now } = inState(state);
      expect(run(box, now, event)).toBe(got);
      expect(box.has(1_000, (v) => v === 'a')).toBe(stillUnread);
    });
  }

  it('hands a value out at most once', () => {
    const box = new Mailbox<string>({ windowMs: WINDOW });
    box.put('a', 0);
    expect(box.has(0)).toBe(true);
    expect(box.take(0)).toBe('a');
    expect(box.has(0)).toBe(false);
    expect(box.take(0)).toBeUndefined();
  });

  it('returns the newest unread match and keeps at most its capacity, oldest out first', () => {
    const box = new Mailbox<string>({ windowMs: WINDOW, capacity: 2 });
    box.put('a', 0);
    box.put('b', 1);
    expect(box.take(2, (v) => v !== 'x')).toBe('b');
    expect(box.take(2)).toBe('a');
    box.put('c', 3);
    box.put('d', 4);
    box.put('e', 5);
    expect(box.take(5, (v) => v === 'c')).toBeUndefined();
    expect(box.take(5)).toBe('e');
    expect(box.take(5)).toBe('d');
  });

  it('a read letter still takes its place in the capacity', () => {
    const box = new Mailbox<string>({ windowMs: WINDOW, capacity: 2 });
    box.put('a', 0);
    box.put('b', 0);
    expect(box.take(0, (v) => v === 'b')).toBe('b');
    box.put('c', 0);
    expect(box.take(0)).toBe('c');
    expect(box.take(0)).toBeUndefined();
  });
});
