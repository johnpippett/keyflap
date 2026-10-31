import { existsSync, readdirSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { ApproverKey } from '@aab/approver';
import type { Daemon } from '@aab/core';
import { SignerDenied } from '@aab/signer/client';
import { afterEach, describe, expect, it } from 'vitest';
import { type DaemonCliOptions, runDaemon } from '../src/daemon.ts';
import { createCredentialAs } from './create-credential-fixture.ts';
import { tmpDir } from './helpers.ts';

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => resolve(p));
    });
  });
}

function approverKeyFiles(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile() && e.name.includes('approver-key'))
    .map((e) => join(e.parentPath, e.name));
}

async function phoneOptions(dataDir: string): Promise<DaemonCliOptions> {
  const port = await freePort();
  return {
    dataDir,
    mcpPort: 0,
    headed: false,
    unprotected: true,
    passphrase: 'phone-mode-test-passphrase',
    phone: {
      origin: `http://approver.localhost:${port}`,
      listen: { host: '127.0.0.1', port },
      tlsCert: null,
      tlsKey: null,
      pair: false,
      apns: null,
    },
  };
}

describe('invariant 6: no approval-forging key on the broker machine in phone mode', () => {
  let daemon: Daemon | undefined;
  afterEach(async () => {
    await daemon?.stop();
    daemon = undefined;
  });

  it('the phone-mode daemon (runDaemon) writes no approver key and its signer refuses an Ed25519 approval', async () => {
    const dataDir = tmpDir();
    daemon = await runDaemon(await phoneOptions(dataDir));

    expect(existsSync(join(dataDir, 'approver-key.json'))).toBe(false);
    expect(approverKeyFiles(dataDir)).toEqual([]);
    await expect(
      daemon.signer.client.createCredential(createCredentialAs(ApproverKey.generate())),
    ).rejects.toThrow(new SignerDenied('untrusted_approver'));
  });

  it('control: the terminal-mode daemon keeps an approver key and its signer accepts that key', async () => {
    const dataDir = tmpDir();
    daemon = await runDaemon({
      dataDir,
      mcpPort: 0,
      headed: false,
      unprotected: true,
      passphrase: 'terminal-mode-test-passphrase',
    });

    const keyFile = join(dataDir, 'approver-key.json');
    expect(existsSync(keyFile)).toBe(true);
    const created = await daemon.signer.client.createCredential(
      createCredentialAs(ApproverKey.loadOrCreate(keyFile)),
    );
    expect(created.credentialId).toEqual(expect.any(String));
  });
});
