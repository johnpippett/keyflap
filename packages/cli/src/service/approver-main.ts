import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ApproverFront } from '@aab/approver/front';
import { servicePlatformProblem } from '@aab/signer/platform';
import {
  clearListenEnv,
  listenFds,
  readCredential,
  readProvisionedFile,
} from '@aab/signer/systemd';
import { type ApproverFrontConfig, parseApproverFrontConfig } from './config.ts';
import { SERVICE_PATHS } from './paths.ts';

const log = (line: string) => process.stderr.write(`${line}\n`);

export async function runApproverFront(cfg: ApproverFrontConfig): Promise<ApproverFront> {
  const tls = cfg.tls
    ? {
        cert: readCredential('approver-tls-cert') as Buffer,
        key: readCredential('approver-tls-key') as Buffer,
      }
    : null;
  const fds = listenFds();
  clearListenEnv();
  const fd = fds.get('approver');
  const fd6 = fds.get('approver6');
  const front = await ApproverFront.start({
    origin: cfg.origin,
    listen: fd !== undefined ? { fds: fd6 !== undefined ? [fd, fd6] : [fd] } : cfg.listen,
    ...(tls ? { tls } : {}),
    upstream: cfg.upstream,
    log,
  });
  log(`keyflap-approver serving the approver page for ${cfg.origin} on ${front.listenUrl}`);
  return front;
}

async function main(argv: string[]): Promise<void> {
  const unsupported = servicePlatformProblem();
  if (unsupported) throw new Error(unsupported);
  if (argv.length !== 2 || argv[0] !== '--config' || !argv[1]) {
    throw new Error(`usage: approver-main.ts --config ${SERVICE_PATHS.approverConfig}`);
  }
  const front = await runApproverFront(parseApproverFrontConfig(readProvisionedFile(argv[1])));
  const onSignal = () => {
    front.close().then(
      () => process.exit(0),
      () => process.exit(1),
    );
  };
  process.once('SIGTERM', onSignal);
  process.once('SIGINT', onSignal);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    log(`keyflap-approver: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
