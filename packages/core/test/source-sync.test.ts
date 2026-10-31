import type { ListSourceItemsResult } from '@aab/signer/protocol';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from '../src/audit.ts';
import { CredentialRepo, openDb } from '../src/db.ts';
import { dropUnconfiguredSourceRows, SourceSync } from '../src/source-sync.ts';

type Item = ListSourceItemsResult['items'][number];

describe('SourceSync', () => {
  let items: Item[];
  let failure: Error | null;
  let calls: number;
  let now: number;
  let db: ReturnType<typeof openDb>;
  let audit: AuditLog;
  let sync: SourceSync;

  const rows = () =>
    new CredentialRepo(db)
      .sourcePasswords('proton-pass')
      .map(({ id, registrable_domain, username, has_totp, signer_ref, source }) => ({
        id,
        registrable_domain,
        username,
        has_totp,
        signer_ref,
        source,
      }));
  const events = () =>
    audit.all().map((r) => ({ ...JSON.parse(r.payload_json), event: r.event_type }));

  beforeEach(() => {
    items = [
      {
        ref: 'proton-pass:S:a',
        hosts: ['login.example.com', 'www.example.com', 'example.org', 'not a host', 'localhost'],
        username: 'alice',
        hasTotp: true,
      },
      { ref: 'proton-pass:S:b', hosts: ['bravo.co.uk'], username: null, hasTotp: false },
      { ref: 'other:S:c', hosts: ['c.test'], username: null, hasTotp: false },
    ];
    failure = null;
    calls = 0;
    now = 1_000_000;
    db = openDb(':memory:');
    audit = new AuditLog(db, () => now);
    sync = new SourceSync({
      source: 'proton-pass',
      signer: {
        listSourceItems: async (source) => {
          calls++;
          expect(source).toBe('proton-pass');
          if (failure) throw failure;
          return { items: structuredClone(items) };
        },
      },
      db,
      audit,
      now: () => now,
    });
  });

  it('adds one row per registrable domain of each item, and only its own source', async () => {
    expect(await sync.refresh()).toEqual({ items: 3, added: 3, removed: 0, updated: 0 });
    expect(rows()).toEqual([
      {
        id: 'proton-pass:S:a@example.com',
        registrable_domain: 'example.com',
        username: 'alice',
        has_totp: 1,
        signer_ref: 'proton-pass:S:a',
        source: 'proton-pass',
      },
      {
        id: 'proton-pass:S:a@example.org',
        registrable_domain: 'example.org',
        username: 'alice',
        has_totp: 1,
        signer_ref: 'proton-pass:S:a',
        source: 'proton-pass',
      },
      {
        id: 'proton-pass:S:b@bravo.co.uk',
        registrable_domain: 'bravo.co.uk',
        username: null,
        has_totp: 0,
        signer_ref: 'proton-pass:S:b',
        source: 'proton-pass',
      },
    ]);
    expect(new CredentialRepo(db).passwordsForDomain('example.com')).toHaveLength(1);
    expect(events().filter((e) => e.event === 'credential.added')).toHaveLength(3);
  });

  it('applies removals, additions and updates, and audits each (identifiers only)', async () => {
    await sync.refresh();
    items = [
      { ref: 'proton-pass:S:a', hosts: ['example.com'], username: 'alice2', hasTotp: false },
      { ref: 'proton-pass:S:d', hosts: ['delta.test'], username: 'dee', hasTotp: false },
    ];
    expect(await sync.refresh()).toEqual({ items: 2, added: 1, removed: 2, updated: 1 });
    expect(rows().map((r) => [r.id, r.username, r.has_totp])).toEqual([
      ['proton-pass:S:a@example.com', 'alice2', 0],
      ['proton-pass:S:d@delta.test', 'dee', 0],
    ]);
    const types = events().map((e) => e.event);
    expect(types.filter((t) => t === 'credential.removed')).toHaveLength(2);
    expect(types.filter((t) => t === 'credential.updated')).toHaveLength(1);
    expect(audit.verify()).toBeNull();
  });

  it('drops a vault username with terminal or bidi controls (the row stays, username-less)', async () => {
    items = [
      { ref: 'proton-pass:S:x', hosts: ['x.test'], username: 'c1\u009b31m', hasTotp: false },
      { ref: 'proton-pass:S:y', hosts: ['y.test'], username: 'rlo\u202eevil', hasTotp: false },
    ];
    await sync.refresh();
    expect(rows().map((r) => [r.registrable_domain, r.username])).toEqual([
      ['x.test', null],
      ['y.test', null],
    ]);
  });

  it('leaves native items alone', async () => {
    new CredentialRepo(db).insertPassword({
      itemId: 'pw_native',
      domain: 'example.com',
      username: 'n',
      hasTotp: false,
      now,
    });
    await sync.refresh();
    items = [];
    await sync.refresh();
    expect(new CredentialRepo(db).allPasswords().map((r) => [r.id, r.source])).toEqual([
      ['pw_native', 'signer'],
    ]);
  });

  it('keeps the rows when the source fails, and audits each distinct failure once', async () => {
    await sync.refresh();
    const before = rows();
    failure = new Error('source_not_logged_in');
    await expect(sync.refresh()).rejects.toThrow('source_not_logged_in');
    await expect(sync.refresh()).rejects.toThrow('source_not_logged_in');
    expect(rows()).toEqual(before);
    failure = null;
    await sync.refresh();
    const types = events().map((e) => e.event);
    expect(types.filter((t) => t === 'source.sync_failed')).toHaveLength(1);
    expect(types.filter((t) => t === 'source.sync_ok')).toHaveLength(1);
    expect(events().find((e) => e.event === 'source.sync_failed')).toMatchObject({
      source: 'proton-pass',
      reason: 'source_not_logged_in',
    });
  });

  it('refreshIfStale is rate-limited, shares an in-flight run, and never throws', async () => {
    await Promise.all([sync.refresh(), sync.refresh(), sync.refreshIfStale()]);
    expect(calls).toBe(1);
    now += 10_000;
    await sync.refreshIfStale();
    expect(calls).toBe(1);
    now += 30_000;
    failure = new Error('source_timeout');
    await sync.refreshIfStale();
    expect(calls).toBe(2);
  });

  it('at startup, drops rows of a source that is no longer configured; native rows stay', async () => {
    const repo = new CredentialRepo(db);
    repo.insertPassword({
      itemId: 'native-1',
      domain: 'native.test',
      username: 'n',
      hasTotp: false,
      now,
    });
    await sync.refresh();
    const mirrored = rows().length;
    expect(mirrored).toBeGreaterThan(1);

    expect(dropUnconfiguredSourceRows(db, audit, 'proton-pass')).toBe(0);
    expect(rows()).toHaveLength(mirrored);

    expect(dropUnconfiguredSourceRows(db, audit, '1password')).toBe(mirrored);
    expect(rows()).toEqual([]);
    expect(repo.allPasswords().map((r) => r.id)).toEqual(['native-1']);
    const removed = events().filter((e) => e.reason === 'source_not_configured');
    expect(removed).toHaveLength(mirrored);
    for (const e of removed) {
      expect(e.event).toBe('credential.removed');
      expect(e.source).toBe('proton-pass');
    }

    expect(dropUnconfiguredSourceRows(db, audit, null)).toBe(0);
    expect(repo.allPasswords()).toHaveLength(1);
  });
});
