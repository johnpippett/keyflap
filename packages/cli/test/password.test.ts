import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { CredentialRepo, hasUnsafeText, openDb, signerPaths } from '@aab/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSigner } from '../../signer/src/client.ts';
import { KeyStore } from '../../signer/src/keystore.ts';
import { formatPasswords } from '../src/password.ts';
import { runCli, tmpDir } from './helpers.ts';

const PASSPHRASE = 'cli-test-passphrase';
const PASSWORD = 'pw-from-stdin-7Hq!';
const SEED = 'JBSWY3DPEHPK3PXP';

describe('keyflap password', () => {
  let dir: string;
  let id: string;
  const env = { KEYFLAP_PASSPHRASE: PASSPHRASE };

  beforeAll(() => {
    dir = tmpDir();
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('add stores the password and TOTP seed in the signer, bound to the registrable domain', async () => {
    const r = await runCli(
      [
        'password',
        'add',
        'https://login.example.com/x',
        '--username',
        'alice',
        '--totp',
        '--data-dir',
        dir,
      ],
      { input: `${PASSWORD}\notpauth://totp/Ex:alice?secret=${SEED}&issuer=Ex&digits=6\n`, env },
    );
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(
      /Added a password \+ TOTP for example\.com \(username alice\), id pw_/,
    );
    id = /id (pw_[A-Za-z0-9_-]+)/.exec(r.stdout)?.[1] as string;
    for (const s of [PASSWORD, SEED]) {
      expect(r.stdout).not.toContain(s);
      expect(r.stderr).not.toContain(s);
    }

    const store = KeyStore.open(signerPaths(dir).storePath, PASSPHRASE);
    const item = store.item(id);
    expect(item).toMatchObject({ domain: 'example.com', password: PASSWORD });
    expect(item?.totp).toEqual({ secret: SEED, algorithm: 'SHA1', digits: 6, period: 30 });

    const db = openDb(join(dir, 'broker.sqlite'));
    try {
      expect(new CredentialRepo(db).passwordsForDomain('example.com')).toEqual([
        expect.objectContaining({ id, username: 'alice', has_totp: 1, signer_ref: id }),
      ]);
    } finally {
      db.close();
    }
    for (const f of ['broker.sqlite', 'broker.sqlite-wal']) {
      let bytes = '';
      try {
        bytes = readFileSync(join(dir, f)).toString('latin1');
      } catch {
        continue;
      }
      expect(bytes).not.toContain(PASSWORD);
      expect(bytes).not.toContain(SEED);
    }
  });

  it('list shows domain, username and TOTP, never secrets', async () => {
    const r = await runCli(['password', 'list', '--data-dir', dir]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(id);
    expect(r.stdout).toMatch(/example\.com\s+alice\s+yes\s+native/);
    const j = await runCli(['password', 'list', '--json', '--data-dir', dir]);
    expect(JSON.parse(j.stdout)).toEqual([
      {
        id,
        domain: 'example.com',
        username: 'alice',
        totp: true,
        source: 'native',
        createdAt: expect.any(Number),
      },
    ]);
    expect(r.stdout + j.stdout).not.toContain(PASSWORD);
  });

  it('refuses while another signer (the daemon) holds the key store', async () => {
    const held = await spawnSigner({
      ...signerPaths(dir),
      passphrase: PASSPHRASE,
      trustedApproverKeys: {},
    });
    try {
      const r = await runCli(['password', 'add', 'other.com', '--data-dir', dir], {
        input: 'another-password\n',
        env,
      });
      expect(r.code).toBe(1);
      expect(r.stderr).toMatch(/is `keyflap daemon` running\?/);
      expect(r.stderr).not.toContain('another-password');
    } finally {
      await held.stop();
    }
  });

  it('refuses a wrong passphrase, an empty password and a site without a registrable domain', async () => {
    const wrong = await runCli(['password', 'add', 'other.com', '--data-dir', dir], {
      input: 'another-password\n',
      env: { KEYFLAP_PASSPHRASE: 'wrong' },
    });
    expect(wrong.code).toBe(1);
    expect(wrong.stderr).toMatch(/wrong passphrase/);
    const empty = await runCli(['password', 'add', 'other.com', '--data-dir', dir], {
      input: '\n',
      env,
    });
    expect(empty.code).toBe(1);
    expect(empty.stderr).toMatch(/empty password/);
    const ip = await runCli(['password', 'add', 'https://127.0.0.1/', '--data-dir', dir], {
      input: 'another-password\n',
      env,
    });
    expect(ip.code).toBe(1);
    expect(ip.stderr).toMatch(/no registrable domain/);
  });

  it('never takes a secret from argv', async () => {
    const r = await runCli(['password', 'add', 'other.com', '--password', 'x', '--data-dir', dir]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/Unknown option '--password'/);
  });

  it('remove deletes the item from the signer and the database', async () => {
    const r = await runCli(['password', 'remove', id, '--data-dir', dir], { env });
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    expect(KeyStore.open(signerPaths(dir).storePath, PASSPHRASE).item(id)).toBeUndefined();
    const list = await runCli(['password', 'list', '--json', '--data-dir', dir]);
    expect(JSON.parse(list.stdout)).toEqual([]);
    const again = await runCli(['password', 'remove', id, '--data-dir', dir], { env });
    expect(again.code).toBe(1);
    expect(again.stderr).toMatch(/no password with id/);
  });

  it('lists Proton Pass logins the daemon matched, and refuses to remove them', async () => {
    const ref = 'proton-pass:SHARE:item1';
    const db = openDb(join(dir, 'broker.sqlite'));
    try {
      new CredentialRepo(db).insertSourcePassword({
        id: `${ref}@bravo.test`,
        ref,
        source: 'proton-pass',
        domain: 'bravo.test',
        username: 'bob',
        hasTotp: false,
        now: Date.now(),
      });
    } finally {
      db.close();
    }
    const list = await runCli(['password', 'list', '--data-dir', dir]);
    expect(list.stdout).toMatch(/bravo\.test\s+bob\s+no\s+proton-pass/);
    const r = await runCli(['password', 'remove', `${ref}@bravo.test`, '--data-dir', dir], { env });
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/is a proton-pass login: remove it .* in proton-pass/);
  });
});

describe('password list output', () => {
  it('escapes terminal and bidi controls in usernames stored before they were refused', () => {
    const db = openDb(':memory:');
    new CredentialRepo(db).insertPassword({
      itemId: 'pw_old',
      domain: 'example.com',
      username: `x\u001b]52;c;cHduZWQ=\u0007\u009b2J${String.fromCharCode(0x202e)}evil`,
      hasTotp: false,
      now: 1,
    });
    const text = formatPasswords(new CredentialRepo(db).allPasswords(), false);
    expect(hasUnsafeText(text.replaceAll('\n', ''))).toBe(false);
    expect(text).toContain('x\\u001b]52;c;cHduZWQ=\\u0007\\u009b2J\\u202eevil');
  });
});
