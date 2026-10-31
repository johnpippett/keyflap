import { type ChildProcess, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ApproverKey } from '@aab/approver';
import { connectSigner, SignerDenied, spawnSigner } from '@aab/signer/client';
import { afterEach, describe, expect, it } from 'vitest';
import { createCredentialAs } from './create-credential-fixture.ts';
import { tmpDir } from './helpers.ts';

const SIGNER_MAIN = join(
  dirname(fileURLToPath(import.meta.resolve('@aab/signer/client'))),
  'main.ts',
);
const SRC = join(import.meta.dirname, '..', 'src');
const CORE_SRC = join(import.meta.dirname, '..', '..', 'core', 'src');

const running: ChildProcess[] = [];
const stops: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const c of running.splice(0)) c.kill('SIGKILL');
  for (const stop of stops.splice(0)) await stop();
});

function startServiceSigner(): Promise<{ socketPath: string; channelKey: Buffer }> {
  const dir = tmpDir();
  const creds = join(dir, 'creds');
  mkdirSync(creds, { mode: 0o700 });
  const channelKey = randomBytes(32);
  writeFileSync(join(creds, 'channel-key'), channelKey, { mode: 0o400 });
  writeFileSync(join(creds, 'kek'), randomBytes(32), { mode: 0o400 });
  const socketPath = join(dir, 's.sock');
  const config = join(dir, 'signer.json');
  writeFileSync(
    config,
    JSON.stringify({
      storePath: join(dir, 'keys.enc.json'),
      socketPath,
      adminSocketPath: join(dir, 'a.sock'),
    }),
  );
  chmodSync(config, 0o644);
  const child = spawn(
    process.execPath,
    ['--disable-warning=ExperimentalWarning', SIGNER_MAIN, '--service', '--config', config],
    {
      env: { PATH: process.env.PATH ?? '', CREDENTIALS_DIRECTORY: creds },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  running.push(child);
  return new Promise((resolve, reject) => {
    let err = '';
    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (d: string) => {
      err += d;
      if (/"event":"ready"/.test(err)) resolve({ socketPath, channelKey });
    });
    child.once('exit', (code) => reject(new Error(`signer exited ${code}: ${err}`)));
  });
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith('.ts'))
    .map((e) => join(e.parentPath, e.name));
}

describe.runIf(process.platform === 'linux')(
  'invariant 6: service mode holds no approval-forging key',
  () => {
    it('the service-mode signer refuses an approval signed by an Ed25519 approver key', async () => {
      const key = ApproverKey.generate('forger');
      const dev = await spawnSigner({
        socketPath: join(tmpDir(), 'd.sock'),
        storePath: join(tmpDir(), 'keys'),
        passphrase: 'pw',
        trustedApproverKeys: key.trustEntry(),
      });
      stops.push(() => dev.stop());
      const signer = await connectSigner(await startServiceSigner());
      stops.push(() => signer.stop());

      expect((await dev.client.createCredential(createCredentialAs(key))).credentialId).toEqual(
        expect.any(String),
      );
      await expect(signer.client.createCredential(createCredentialAs(key))).rejects.toThrow(
        new SignerDenied('untrusted_approver'),
      );
      await expect(
        signer.client.createCredential(createCredentialAs(ApproverKey.generate())),
      ).rejects.toThrow(new SignerDenied('untrusted_approver'));
      expect((await signer.client.listApprovers()).approvers).toEqual([]);
    });

    it('no source file of the service entry points or of the core library creates an approver key', () => {
      const files = [
        ...sourceFiles(join(SRC, 'service')),
        ...sourceFiles(CORE_SRC).filter((f) => !f.endsWith(`${join('core', 'src', 'main.ts')}`)),
      ];
      expect(files.length).toBeGreaterThan(10);
      const offenders = files.filter((f) =>
        /\bApproverKey\b|approver-key/.test(readFileSync(f, 'utf8')),
      );
      expect(offenders).toEqual([]);
    });
  },
);
