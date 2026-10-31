import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { signerPaths } from '@aab/core';
import { nativeKeyId } from '@aab/signer/approval';
import { FAKE_TAILSCALE, fakeTailscale, serveConfig } from '@aab/sources/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { KeyStore } from '../../signer/src/keystore.ts';
import { runCli, tmpDir } from './helpers.ts';

const PASSPHRASE = 'cli-test-passphrase';

describe('keyflap approver', () => {
  let dir: string;
  const credentialId = randomBytes(32).toString('base64url');
  const env = { KEYFLAP_PASSPHRASE: PASSPHRASE };
  let nativeId = '';

  beforeAll(() => {
    dir = tmpDir();
    mkdirSync(dirname(signerPaths(dir).storePath), { recursive: true, mode: 0o700 });
    const jwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
      format: 'jwk',
    });
    KeyStore.open(signerPaths(dir).storePath, PASSPHRASE).addApprover({
      credentialId,
      x: jwk.x as string,
      y: jwk.y as string,
      rpId: 'broker.example.net',
      origin: 'https://broker.example.net:8766',
      signCount: 0,
      createdAt: Date.UTC(2026, 0, 1),
    });
    const n = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
      format: 'jwk',
    });
    nativeId = nativeKeyId(n.x as string, n.y as string);
    KeyStore.open(signerPaths(dir).storePath, PASSPHRASE).addNativeApprover({
      keyId: nativeId,
      x: n.x as string,
      y: n.y as string,
      origin: 'https://broker.example.net:8766',
      userVerification: 'biometry',
      createdAt: Date.UTC(2026, 0, 2),
    });
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('lists the trusted phone approvers (public data only)', async () => {
    const r = await runCli(['approver', 'list', '--json', '--data-dir', dir], { env });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual([
      {
        id: credentialId,
        type: 'passkey',
        origin: 'https://broker.example.net:8766',
        createdAt: Date.UTC(2026, 0, 1),
      },
      {
        id: nativeId,
        type: 'ios-app',
        origin: 'https://broker.example.net:8766',
        createdAt: Date.UTC(2026, 0, 2),
      },
    ]);
  });

  it('shows the open pairing link as a QR code, in full cells when the width is unknown', async () => {
    const none = await runCli(['approver', 'qr', '--data-dir', dir], { env });
    expect(none.code).toBe(1);
    expect(none.stderr).toContain('no pairing link is open');
    mkdirSync(join(dir, 'approver'), { recursive: true });
    const url = `https://broker.example.net:8766/pair#${'A'.repeat(43)}`;
    writeFileSync(join(dir, 'approver', 'pairing-url'), `${url}\n`, { mode: 0o600 });
    const r = await runCli(['approver', 'qr', '--data-dir', dir], { env });
    expect(r.code).toBe(0);
    const lightCell = ['107', '48;5;231', '48;2;255;255;255'].map((ink) => `\u001b[${ink}m  `);
    expect(lightCell.some((cell) => r.stdout.includes(cell))).toBe(true);
    expect(r.stdout).not.toContain('▀');
    expect(r.stdout).toContain(url);
    rmSync(join(dir, 'approver'), { recursive: true });
  });

  it('removes one, after which the signer no longer trusts it', async () => {
    const r = await runCli(['approver', 'remove', credentialId, '--data-dir', dir], { env });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(`Removed phone approver ${credentialId}`);
    expect(KeyStore.open(signerPaths(dir).storePath, PASSPHRASE).approvers()).toEqual([]);
    const n = await runCli(['approver', 'remove', nativeId, '--data-dir', dir], { env });
    expect(n.code).toBe(0);
    const store = KeyStore.open(signerPaths(dir).storePath, PASSPHRASE);
    expect(store.nativeApprovers()).toEqual([]);
    expect(store.phoneLatched).toBe(false);
    const again = await runCli(['approver', 'remove', credentialId, '--data-dir', dir], { env });
    expect(again.code).toBe(1);
    expect(again.stderr).toContain('no phone approver with id');
  });
});

describe('keyflap approver pair --approver-origin (dev mode, daemon stopped): the approval address', () => {
  const HOST = 'box.tail1.ts.net';
  const PORT = 48766;
  const ORIGIN = `https://${HOST}:${PORT}`;
  let dir: string;
  let bin: string;
  let fake: ReturnType<typeof fakeTailscale>;

  beforeAll(() => {
    dir = tmpDir();
    mkdirSync(dirname(signerPaths(dir).storePath), { recursive: true, mode: 0o700 });
    KeyStore.open(signerPaths(dir).storePath, PASSPHRASE);
    fake = fakeTailscale(
      serveConfig({ host: HOST, port: PORT, target: `http://127.0.0.1:${PORT}` }),
    );
    bin = join(dir, 'bin');
    mkdirSync(bin);
    writeFileSync(
      join(bin, 'tailscale'),
      `#!/bin/sh\nexport KEYFLAP_FAKE_TAILSCALE_DIR=${fake.dir}\nexec ${process.execPath} ${FAKE_TAILSCALE} "$@"\n`,
      { mode: 0o755 },
    );
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  const pair = (args: string[], path = `${bin}:${process.env.PATH}`) =>
    runCli(['approver', 'pair', '--data-dir', dir, ...args], {
      env: { KEYFLAP_PASSPHRASE: PASSPHRASE, PATH: path },
    });

  it('without --approver-origin: says how pairing starts, and how to re-check', async () => {
    const r = await pair([]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('pairing starts with the daemon');
    expect(r.stderr).toContain(
      'keyflap approver pair --approver-origin URL [--approver-listen HOST:PORT]',
    );
  });

  it('a correct serve config: ok, and the daemon is the next step', async () => {
    const r = await pair(['--approver-origin', ORIGIN, '--approver-listen', `127.0.0.1:${PORT}`]);
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    expect(r.stdout).toBe(
      `Approval address: ok (${ORIGIN} -> http://127.0.0.1:${PORT}, watched)\n` +
        'Start the daemon (keyflap daemon --unprotected --approver phone …): it offers pairing.\n',
    );
    expect(fake.calls().map((c) => c.argv.join(' '))).toContain('serve status --json');
  });

  it('a wrong serve config: refused with what was seen and the fix, exit 1', async () => {
    fake.serve(serveConfig({ host: HOST, port: PORT, target: 'http://127.0.0.1:9999' }));
    const r = await pair(['--approver-origin', ORIGIN, '--approver-listen', `127.0.0.1:${PORT}`]);
    expect(r.code).toBe(1);
    expect(r.stdout).toBe('');
    expect(r.stderr).toMatch(
      new RegExp(
        `^keyflap: the approval address is off: it was changed at 20\\S+ \\(${HOST}:${PORT} proxies to "http://127\\.0\\.0\\.1:9999"\\), so phones were signed out to be safe\\. It is still wrong\\.\\n` +
          ' {2}Approvals are off until it is fixed at this computer\\.\\n' +
          ` {2}fix: ${bin}/tailscale serve --bg --https=${PORT} http://127\\.0\\.0\\.1:${PORT}, then keyflap approver pair --approver-origin ${ORIGIN} \\(daemon stopped\\), then start the daemon again\\n`,
      ),
    );
    fake.serve(serveConfig({ host: HOST, port: PORT, target: `http://127.0.0.1:${PORT}` }));
    const again = await pair([
      '--approver-origin',
      ORIGIN,
      '--approver-listen',
      `127.0.0.1:${PORT}`,
    ]);
    expect(again.code).toBe(0);
    expect(again.stdout).toContain('Approval address: ok');
  });

  it('no tailscale on PATH: unreadable, with the install step', async () => {
    const r = await pair(['--approver-origin', ORIGIN], '/nonexistent-bin');
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(
      'keyflap: the approval address is unreadable: no tailscale CLI configured.',
    );
    expect(r.stderr).toContain('fix: install Tailscale (tailscale.com/download)');
  });

  it('a name outside the tailnet is not watched, so there is nothing to re-check', async () => {
    const r = await pair(['--approver-origin', 'https://approver.example.net:8766']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('Approval address: not watched (not a Tailscale name)');
  });

  it('--approver-listen alone is a usage error', async () => {
    const r = await pair(['--approver-listen', '127.0.0.1:1']);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('--approver-listen needs --approver-origin');
  });
});
