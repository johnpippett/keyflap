import { createInterface } from 'node:readline';
import type { TrustedApproverKeys } from './approval.ts';
import { parseApproverAddress } from './approver-address.ts';
import { KeyStore } from './keystore.ts';
import { acquireLock, type FileLock } from './lock.ts';
import { servicePlatformProblem } from './platform.ts';
import type { SignerSourcesConfig } from './protocol.ts';
import { SignerHandler, startSignerServer } from './server.ts';
import { buildSources, runSignerService } from './service.ts';

interface SignerConfig {
  socketPath: string;
  storePath: string;
  channelKey: string;
  passphrase: string;
  trustedApproverKeys: TrustedApproverKeys;
  highRiskDomains?: string[];
  approverAdmin?: boolean;
  sources?: SignerSourcesConfig;
  approverAddress?: unknown;
}

let lock: FileLock | undefined;
const setLock = (l: FileLock) => {
  lock = l;
};
process.on('exit', () => lock?.release());

function log(event: string, fields: Record<string, unknown> = {}): void {
  process.stderr.write(`${JSON.stringify({ src: 'signer', event, ...fields })}\n`);
}

async function spawnedMain(): Promise<void> {
  const rl = createInterface({ input: process.stdin });
  const line = await new Promise<string>((resolve, reject) => {
    rl.once('line', resolve);
    rl.once('close', () => reject(new Error('no config on stdin')));
  });
  rl.close();
  const cfg = JSON.parse(line) as SignerConfig;
  lock = acquireLock(`${cfg.storePath}.lock`);
  const store = KeyStore.open(cfg.storePath, cfg.passphrase);
  const handler = new SignerHandler({
    store,
    trustedApproverKeys: cfg.trustedApproverKeys,
    highRiskDomains: cfg.highRiskDomains ?? [],
    approverAdmin: cfg.approverAdmin === true,
    sources: buildSources(cfg.sources, { mode: 'same-user' }),
    ...(cfg.approverAddress !== undefined
      ? {
          approverAddress: {
            address: parseApproverAddress(cfg.approverAddress, {
              where: 'signer config: approverAddress',
              pollMs: 'allow',
            }),
            trust: { mode: 'same-user' },
          },
        }
      : {}),
    log,
  });
  await handler.startAddressWatch();
  const server = await startSignerServer({
    socketPath: cfg.socketPath,
    channelKey: Buffer.from(cfg.channelKey, 'base64url'),
    handler,
    log,
  });
  process.stdout.write('ready\n');
  const shutdown = () => {
    handler.stopAddressWatch();
    server.close();
    lock?.release();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  process.stdin.on('end', shutdown);
  process.stdin.resume();
}

const argv = process.argv.slice(2);
const unsupported = argv[0] === '--service' ? servicePlatformProblem() : null;
const run = unsupported
  ? Promise.reject(new Error(unsupported))
  : argv[0] === '--service'
    ? argv[1] === '--config' && typeof argv[2] === 'string' && argv.length === 3
      ? runSignerService(argv[2], { log, setLock })
      : Promise.reject(new Error('usage: main.ts --service --config FILE'))
    : spawnedMain();
run.catch((err: unknown) => {
  log('fatal', { message: err instanceof Error ? err.message : String(err) });
  process.exit(1);
});
