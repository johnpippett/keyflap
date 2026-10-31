import { describe, expect, it } from 'vitest';
import { type CoreGrant, GrantBook, type GrantQuery } from '../src/grants.ts';

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

const grant = (over: Partial<CoreGrant>): CoreGrant => ({
  grantId: 'g1',
  agentId: query.agentId,
  kind: query.kind,
  verifiedOrigin: query.verifiedOrigin,
  rpId: query.rpId,
  credentialId: query.credentialId,
  scope: ['password'],
  createdAt: NOW,
  until: NOW + WINDOW_MS,
  ...over,
});

describe('grant book keeps single-use handoff grants out of allow-for lookups', () => {
  it('find returns an allow-for grant and never a single-use one, armed or not', () => {
    const book = new GrantBook();
    book.add(grant({ grantId: 'window' }));
    expect(book.find(query, NOW, WINDOW_MS)?.grantId).toBe('window');

    const single = new GrantBook();
    single.add(grant({ grantId: 'once', singleUse: true, handoffId: 'h1' }));
    expect(single.find(query, NOW, WINDOW_MS)).toBeNull();
    single.arm('h1');
    expect(single.find(query, NOW, WINDOW_MS)).toBeNull();
  });

  it('a single-use grant beside an allow-for grant never wins the lookup, even when it lasts longer', () => {
    const book = new GrantBook();
    book.add(grant({ grantId: 'window', until: NOW + 1000 }));
    book.add(grant({ grantId: 'once', singleUse: true, handoffId: 'h1', until: NOW + WINDOW_MS }));
    book.arm('h1');
    expect(book.find(query, NOW, WINDOW_MS)?.grantId).toBe('window');
  });

  it('takeHandoff returns an armed single-use grant exactly once, and an unarmed one never', () => {
    const book = new GrantBook();
    book.add(grant({ grantId: 'once', singleUse: true, handoffId: 'h1' }));
    expect(book.takeHandoff(query, NOW)).toBeNull();
    book.arm('h1');
    expect(book.takeHandoff(query, NOW)?.grantId).toBe('once');
    expect(book.takeHandoff(query, NOW)).toBeNull();
    expect(book.size()).toBe(0);
  });

  it('takeHandoff never returns an allow-for grant', () => {
    const book = new GrantBook();
    book.add(grant({ grantId: 'window', armed: true }));
    expect(book.takeHandoff(query, NOW)).toBeNull();
    expect(book.size()).toBe(1);
  });
});
