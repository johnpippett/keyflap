import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { CredentialRepo, hasUnsafeText, openDb, signerPaths } from '@aab/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { KeyStore } from '../../signer/src/keystore.ts';
import {
  formatPreview,
  ImportError,
  parseCsv,
  parseExport,
  planImport,
} from '../src/password-import.ts';
import { runCli, tmpDir } from './helpers.ts';

const PASSPHRASE = 'import-test-passphrase';
const SEED = 'JBSWY3DPEHPK3PXP';

const APPLE = [
  'Title,URL,Username,Password,Notes,OTPAuth',
  `example.com (alice),https://login.example.com/,alice,apple-pw-Example1!,,otpauth://totp/Example:alice?secret=${SEED}&issuer=Example`,
  'shop.test.co.uk,https://www.shop.test.co.uk/account,bob@mail.test,"pw,with ""quotes"", and commas","a note\nover two lines",',
  'Some App,android://hash@com.example.app/,carol,app-only-pw-9,,',
  'Wi-Fi,,,wifi-secret-pw,,',
].join('\r\n');

const CHROME = [
  'name,url,username,password,note',
  'example.com,https://example.com/login,alice,chrome-pw-Example1!,',
  'example.com,https://www.example.com/,alice,chrome-pw-Example1!,',
  'github.com,https://github.com/session,dave,gh-pw-one-1234,',
  'github.com,https://github.com/login,dave,gh-pw-two-5678,',
  'tiny.example,https://tiny.example/,erin,abc,',
].join('\n');

describe('CSV parsing', () => {
  it('handles quotes, escaped quotes, commas and newlines inside fields, CRLF and a BOM', () => {
    const rows = parseCsv('﻿a,b\r\n"x,1","say ""hi""\nthere"\r\nlast,row');
    expect(rows).toEqual([
      { fields: ['a', 'b'], line: 1 },
      { fields: ['x,1', 'say "hi"\nthere'], line: 2 },
      { fields: ['last', 'row'], line: 4 },
    ]);
  });

  it('refuses an unterminated quote instead of guessing', () => {
    expect(() => parseCsv('a,b\n"open,1\n')).toThrow(ImportError);
  });

  it('refuses a file that is not a password export', () => {
    expect(() => parseExport('date,amount\n2026-01-01,4\n')).toThrow(/not a password export/);
  });
});

describe('Apple Passwords export', () => {
  const parsed = parseExport(APPLE);

  it('is recognised and keeps web logins with their TOTP', () => {
    expect(parsed.format).toBe('apple');
    expect(parsed.logins).toEqual([
      expect.objectContaining({
        line: 2,
        domain: 'example.com',
        username: 'alice',
        password: 'apple-pw-Example1!',
        totp: { secret: SEED },
      }),
      expect.objectContaining({
        line: 3,
        domain: 'test.co.uk',
        username: 'bob@mail.test',
        password: 'pw,with "quotes", and commas',
        totp: null,
      }),
    ]);
  });

  it('skips app-only and URL-less entries with a fixed reason', () => {
    expect(parsed.skipped).toEqual([
      { line: 5, domain: null, username: 'carol', reason: 'no website address' },
      { line: 6, domain: null, username: null, reason: 'no website address' },
    ]);
  });
});

describe('Google Password Manager / Chrome export', () => {
  const parsed = parseExport(CHROME);

  it('merges identical rows for one site and skips rows that disagree', () => {
    expect(parsed.format).toBe('chrome');
    const plan = planImport(parsed, { sites: [], all: true }, []);
    expect(plan.toStore.map((l) => [l.domain, l.username])).toEqual([['example.com', 'alice']]);
    expect(plan.skipped.map((r) => [r.line, r.reason])).toEqual([
      [4, 'other rows for this site and username have a different password or TOTP'],
      [5, 'other rows for this site and username have a different password or TOTP'],
      [6, 'password shorter than 4 or longer than 1024 characters'],
    ]);
  });
});

describe('other managers by column name', () => {
  it('reads Bitwarden (first of several URIs) and Firefox exports', () => {
    const bw = parseExport(
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n' +
        `,,login,Ex,,,0,"https://a.example.com,https://b.example.org",u1,bw-pw-1234,${SEED}\n`,
    );
    expect(bw.format).toBe('bitwarden');
    expect(bw.logins[0]).toMatchObject({ domain: 'example.com', totp: { secret: SEED } });
    const ff = parseExport(
      '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n' +
        '"https://ff.example","u2","ff-pw-1234",,"https://ff.example","{x}","1","1","1"\n',
    );
    expect(ff.format).toBe('firefox');
    expect(ff.logins[0]).toMatchObject({ domain: 'ff.example', username: 'u2' });
  });

  it('skips a TOTP cell it does not understand rather than storing without it', () => {
    const p = parseExport(
      'url,username,password,otpauth\nhttps://x.example,u,pw-1234,otpauth://hotp/x?secret=A\n',
    );
    expect(p.logins).toEqual([]);
    expect(p.skipped[0]?.reason).toMatch(/one-time code setup not understood/);
  });

  it("reads Dashlane's otpSecret column", () => {
    const p = parseExport(
      'username,username2,username3,title,password,note,url,category,otpSecret\n' +
        `u,,,Ex,dl-pw-1234,,https://dl.example,,${SEED}\n`,
    );
    expect(p.logins[0]).toMatchObject({ domain: 'dl.example', totp: { secret: SEED } });
  });

  it('refuses a file with a one-time code column it does not read, rather than drop the TOTP', () => {
    for (const col of ['2FA Secret', 'mfa', 'Authenticator key', 'otp_seed']) {
      expect(() =>
        parseExport(`url,username,password,${col}\nhttps://x.example,u,pw-1234,${SEED}\n`),
      ).toThrow(/looks like one-time codes/);
    }
    expect(() =>
      parseExport(`url,username,password,totp,otp\nhttps://x.example,u,pw-1234,${SEED},${SEED}\n`),
    ).toThrow(/"otp" looks like one-time codes/);
  });
});

describe('selection', () => {
  const parsed = parseExport(APPLE);

  it('stores nothing without --site or --all (preview)', () => {
    const plan = planImport(parsed, { sites: [], all: false }, []);
    expect(plan.preview).toBe(true);
    expect(plan.toStore).toEqual([]);
    expect(plan.available).toHaveLength(2);
  });

  it('--site picks by registrable domain, in any form', () => {
    const plan = planImport(parsed, { sites: ['https://app.example.com/x'], all: false }, []);
    expect(plan.toStore.map((l) => l.domain)).toEqual(['example.com']);
  });

  it('--site for a site the file lacks is an error, not a silent no-op', () => {
    expect(() => planImport(parsed, { sites: ['nothere.example'], all: false }, [])).toThrow(
      /no login for nothere\.example/,
    );
  });

  it('leaves logins already stored for the same site and username alone', () => {
    const plan = planImport(parsed, { sites: [], all: true }, [
      { domain: 'example.com', username: 'alice' },
    ]);
    expect(plan.toStore.map((l) => l.domain)).toEqual(['test.co.uk']);
    expect(plan.alreadyStored.map((l) => l.domain)).toEqual(['example.com']);
  });
});

describe('terminal safety and the file fingerprint', () => {
  const HOSTILE = [
    'url,username,password',
    'https://a.example/,"x\u001b]52;c;cHduZWQ=\u0007\u001b[2J",pw-a-1234',
    'https://b.example/,"c1\u009b31m",pw-b-1234',
    'https://c.example/,"rlo\u202eevil",pw-c-1234',
    'android://h@app/,"\u001b[31mred",pw-d-1234',
    'https://ok.example/,carol,pw-ok-1234',
  ].join('\n');

  it('rejects C1 and bidi usernames and escapes every one it reports', () => {
    const plan = planImport(parseExport(HOSTILE), { sites: [], all: false }, []);
    expect(plan.available.map((l) => l.username)).toEqual(['carol']);
    expect(plan.skipped.map((r) => r.reason)).toEqual([
      'username longer than 256 characters or not printable',
      'username longer than 256 characters or not printable',
      'username longer than 256 characters or not printable',
      'no website address',
    ]);
    const text = formatPreview(plan, 'evil\u001b[2J.csv');
    expect(hasUnsafeText(text.replaceAll('\n', ''))).toBe(false);
    expect(text).toContain('line 2: a.example (x\\u001b]52;c;cHduZWQ=\\u0007\\u001b[2J)');
    expect(text).toContain('line 3: b.example (c1\\u009b31m)');
    expect(text).toContain('line 4: c.example (rlo\\u202eevil)');
    expect(text).toContain('evil\\u001b[2J.csv');
  });

  it('the preview shows a fingerprint and puts --expect in the commands it suggests', () => {
    const parsed = parseExport(APPLE);
    expect(parsed.fingerprint).toMatch(/^[0-9a-f]{16}$/);
    const text = formatPreview(planImport(parsed, { sites: [], all: false }, []), 'P.csv');
    expect(text).toContain(`File fingerprint ${parsed.fingerprint}.`);
    expect(text).toContain(`keyflap password import P.csv --expect ${parsed.fingerprint} --all`);
  });

  it('--expect refuses a file that changed since the preview, by one character', () => {
    const before = parseExport(APPLE);
    const after = parseExport(APPLE.replace('alice', 'alicf'));
    expect(after.fingerprint).not.toBe(before.fingerprint);
    expect(() =>
      planImport(after, { sites: ['example.com'], all: false, expect: before.fingerprint }, []),
    ).toThrow(/the file changed since the preview/);
    const ok = planImport(
      before,
      { sites: ['example.com'], all: false, expect: before.fingerprint.toUpperCase() },
      [],
    );
    expect(ok.toStore.map((l) => l.username)).toEqual(['alice']);
  });
});

describe('keyflap password import (dev mode, separate processes)', () => {
  let dir: string;
  let file: string;
  const env = { KEYFLAP_PASSPHRASE: PASSPHRASE };
  const secrets = [
    'apple-pw-Example1!',
    'with ""quotes""',
    'with "quotes"',
    SEED,
    'wifi-secret-pw',
    'app-only-pw-9',
  ];

  beforeAll(() => {
    dir = tmpDir();
    file = join(dir, 'Passwords.csv');
    writeFileSync(file, APPLE, { mode: 0o600 });
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('previews without a passphrase and stores nothing', async () => {
    const r = await runCli(['password', 'import', file, '--data-dir', dir], {
      env: { KEYFLAP_PASSPHRASE: undefined },
    });
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('Apple Passwords export, 2 usable logins');
    expect(r.stdout).toMatch(/example\.com\s+alice\s+yes/);
    expect(r.stdout).toMatch(/Nothing stored\. File fingerprint [0-9a-f]{16}\./);
    expect(r.stdout).toContain('line 5: (no site) (carol): no website address');
    for (const s of secrets) expect(r.stdout).not.toContain(s);
  });

  it('refuses to store when the file changed after the preview (--expect)', async () => {
    const preview = await runCli(['password', 'import', file, '--data-dir', dir], {
      env: { KEYFLAP_PASSPHRASE: undefined },
    });
    const fp = /--expect ([0-9a-f]{16})/.exec(preview.stdout)?.[1] as string;
    writeFileSync(file, APPLE.replace(',alice,', ',mallory,'), { mode: 0o600 });
    try {
      const r = await runCli(
        ['password', 'import', file, '--expect', fp, '--site', 'example.com', '--data-dir', dir],
        { env },
      );
      expect(r.code).not.toBe(0);
      expect(r.stderr).toContain('the file changed since the preview');
      expect(r.stdout).not.toContain('Imported');
    } finally {
      writeFileSync(file, APPLE, { mode: 0o600 });
    }
  });

  it('stores only the named site, in the signer, and says to delete the export', async () => {
    const preview = await runCli(['password', 'import', file, '--data-dir', dir], {
      env: { KEYFLAP_PASSPHRASE: undefined },
    });
    const fp = /--expect ([0-9a-f]{16})/.exec(preview.stdout)?.[1] as string;
    const r = await runCli(
      ['password', 'import', file, '--expect', fp, '--site', 'example.com', '--data-dir', dir],
      { env },
    );
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(
      /Imported 1 login from the Apple Passwords export:\n {2}pw_\S+ {2}example\.com \(alice\) \+ TOTP/,
    );
    expect(r.stdout).toContain('still holds every password in plaintext. Delete it');
    for (const s of secrets) {
      expect(r.stdout).not.toContain(s);
      expect(r.stderr).not.toContain(s);
    }
    const id = /(pw_[A-Za-z0-9_-]+)/.exec(r.stdout)?.[1] as string;
    const store = KeyStore.open(signerPaths(dir).storePath, PASSPHRASE);
    expect(store.item(id)).toMatchObject({ domain: 'example.com', password: 'apple-pw-Example1!' });
    expect(store.item(id)?.totp).toMatchObject({ secret: SEED });

    const db = openDb(join(dir, 'broker.sqlite'));
    try {
      expect(new CredentialRepo(db).allPasswords().map((p) => p.registrable_domain)).toEqual([
        'example.com',
      ]);
    } finally {
      db.close();
    }
    const bytes = readFileSync(join(dir, 'broker.sqlite')).toString('latin1');
    for (const s of secrets) expect(bytes).not.toContain(s);
  });

  it('--all adds the rest and skips what is already stored', async () => {
    const r = await runCli(['password', 'import', file, '--all', '--data-dir', dir], { env });
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(
      /Imported 1 login .*:\n {2}pw_\S+ {2}test\.co\.uk \(bob@mail\.test\)\n/,
    );
    expect(r.stdout).toContain(
      'Already stored (same site and username), left as they are: example.com (alice).',
    );
    for (const s of secrets) expect(r.stdout).not.toContain(s);
  });

  it('rejects --site together with --all', async () => {
    const r = await runCli([
      'password',
      'import',
      file,
      '--all',
      '--site',
      'x.example',
      '--data-dir',
      dir,
    ]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain('use --site or --all, not both');
  });
});
