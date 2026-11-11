import { describe, expect, it } from 'vitest';
import { type CoreGrant, type GrantBase, GrantBook, type GrantQuery } from '../src/grants.ts';

const NOW = 1_000_000;
const WINDOW_MS = 600_000;

const query: GrantQuery = {
  agentId: 'a1',
  kind: 'fill',
  verifiedOrigin: 'https://login.example.com',
  rpId: 'example.com',
  credentialId: 'item-1',
  fields: ['password'],
};

const base: GrantBase = {
  grantId: 'g1',
  agentId: query.agentId,
  kind: query.kind,
  verifiedOrigin: query.verifiedOrigin,
  rpId: query.rpId,
  credentialId: query.credentialId,
  scope: ['password'],
  createdAt: NOW,
  until: NOW + WINDOW_MS,
};

type State = 'window' | 'held' | 'armed';
type Event = 'find' | 'takeHandoff' | 'arm' | 'dropHandoff';

const grantIn = (state: State): CoreGrant =>
  state === 'window'
    ? { ...base, use: 'window' }
    : { ...base, use: 'single', handoffId: 'h1', phase: state };

function run(book: GrantBook, event: Event): CoreGrant | null {
  switch (event) {
    case 'find':
      return book.find(query, NOW, WINDOW_MS);
    case 'takeHandoff':
      return book.takeHandoff(query, NOW);
    case 'arm':
      return book.arm('h1');
    case 'dropHandoff':
      return book.dropHandoff('h1');
    default: {
      const unhandled: never = event;
      return unhandled;
    }
  }
}

const table: [State, Event, boolean, State | 'gone'][] = [
  ['window', 'find', true, 'window'],
  ['window', 'takeHandoff', false, 'window'],
  ['window', 'arm', false, 'window'],
  ['window', 'dropHandoff', false, 'window'],
  ['held', 'find', false, 'held'],
  ['held', 'takeHandoff', false, 'held'],
  ['held', 'arm', true, 'armed'],
  ['held', 'dropHandoff', true, 'gone'],
  ['armed', 'find', false, 'armed'],
  ['armed', 'takeHandoff', true, 'gone'],
  ['armed', 'arm', true, 'armed'],
  ['armed', 'dropHandoff', true, 'gone'],
];

function stateOf(book: GrantBook): State | 'gone' {
  if (book.size() === 0) return 'gone';
  if (book.find(query, NOW, WINDOW_MS)) return 'window';
  const taken = book.takeHandoff(query, NOW);
  if (!taken) return 'held';
  book.add(taken);
  return 'armed';
}

describe('grant states: every grant shape against every book operation', () => {
  it('covers each state and event once', () => {
    expect(new Set(table.map(([s, e]) => `${s} ${e}`)).size).toBe(12);
  });

  for (const [state, event, returned, after] of table) {
    it(`${state} + ${event} -> ${returned ? 'returns it' : 'nothing'}, then ${after}`, () => {
      const book = new GrantBook();
      book.add(grantIn(state));
      const got = run(book, event);
      expect(got?.grantId ?? null).toBe(returned ? 'g1' : null);
      expect(stateOf(book)).toBe(after);
    });
  }

  it('find only ever returns a window grant, takeHandoff only an armed single-use one', () => {
    const book = new GrantBook();
    book.add(grantIn('window'));
    book.add({ ...grantIn('armed'), grantId: 'g2' });
    expect(book.find(query, NOW, WINDOW_MS)).toMatchObject({ grantId: 'g1', use: 'window' });
    expect(book.takeHandoff(query, NOW)).toMatchObject({
      grantId: 'g2',
      use: 'single',
      phase: 'armed',
      handoffId: 'h1',
    });
  });
});
