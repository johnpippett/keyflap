import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ApnsSender, ApproverAddressSync, PairingRefused, PhoneApprover } from '@aab/approver';
import { type Daemon, registerCoreAdminOps, startDaemon } from '@aab/core';
import { startMcpHttpServer } from '@aab/mcp';
import { AdminError, startAdminServer } from '@aab/signer/admin-wire';
import { servicePlatformProblem } from '@aab/signer/platform';
import {
  clearListenEnv,
  listenFds,
  readCredential,
  readProvisionedFile,
} from '@aab/signer/systemd';
import { rootOnlyProblem } from '@aab/sources';
import { addressSummary } from '../approver-address.ts';
import { registerCliAdminOps } from './admin-cli-ops.ts';
import { AuditedAdminOps } from './audited-ops.ts';
import { type CoreServiceConfig, parseCoreConfig } from './config.ts';
import { serviceManager } from './manager.ts';
import { SERVICE_PATHS } from './paths.ts';
import { killStaleBrowsers } from './stale-browser.ts';
import { startXvfb, type XvfbDisplay } from './xvfb.ts';

const HOST_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

const log = (line: string) => process.stderr.write(`${line}\n`);

export interface CoreService {
  daemon: Daemon;
  stop(): Promise<void>;
}

export async function runCoreService(
  cfg: CoreServiceConfig,
  opts: {
    onSignerLost?: () => void;
  } = {},
): Promise<CoreService> {
  const channelKey = readCredential('channel-key') as Buffer;
  if (channelKey.length < 32) throw new Error('credential "channel-key" is shorter than 32 bytes');
  const hostToken = (readCredential('host-token') as Buffer).toString('utf8').trim();
  if (!HOST_TOKEN_RE.test(hostToken)) throw new Error('credential "host-token" is malformed');
  const tls = cfg.approver.tls
    ? {
        cert: readCredential('approver-tls-cert') as Buffer,
        key: readCredential('approver-tls-key') as Buffer,
      }
    : null;
  const apnsCfg = cfg.approver.apns;
  const apns = apnsCfg
    ? new ApnsSender({
        key: readCredential('apns-key') as Buffer,
        keyId: apnsCfg.keyId,
        teamId: apnsCfg.teamId,
        bundleId: apnsCfg.bundleId,
        defaultEnvironment: apnsCfg.sandbox ? 'sandbox' : 'production',
        generic: apnsCfg.generic,
      })
    : null;
  const fds = listenFds();
  clearListenEnv();
  const intentFd = fds.get('intent');
  const adminFd = fds.get('admin');
  const front = cfg.approver.front;
  const approverApiFd = fds.get('approver-api');
  const approverListen = front
    ? approverApiFd !== undefined
      ? { fd: approverApiFd }
      : { path: front.socket }
    : cfg.approver.listen;

  const channel = cfg.browser.mode === 'headless' ? cfg.browser.channel : undefined;
  const launchd = serviceManager()?.kind === 'launchd';
  const browsersPath = process.env.PLAYWRIGHT_BROWSERS_PATH;
  if (launchd && browsersPath && typeof process.getuid === 'function') {
    await killStaleBrowsers({ browsersPath, uid: process.getuid(), log });
  }
  let display: XvfbDisplay | null = null;
  if (cfg.browser.mode === 'xvfb') {
    const bad = rootOnlyProblem(cfg.browser.xvfbBin);
    if (bad) throw new Error(`refusing to run Xvfb: ${bad.detail} (re-run install.sh)`);
    display = await startXvfb({
      bin: cfg.browser.xvfbBin,
      display: cfg.browser.display,
      dir: join(cfg.dataDir, 'xvfb'),
      log,
    });
    process.env.DISPLAY = display.env.DISPLAY;
    process.env.XAUTHORITY = display.env.XAUTHORITY;
  }

  const phoneRef: { current: PhoneApprover | null } = { current: null };
  let daemon: Daemon;
  try {
    daemon = await startDaemon({
      dataDir: cfg.dataDir,
      signerService: { socketPath: cfg.signerSocket, channelKey },
      hostToken,
      intentSocketPath: cfg.intentSocket,
      ...(intentFd !== undefined ? { intentListenFd: intentFd } : {}),
      trustedApproverKeys: {},
      makeApprover: async ({ signer, audit, auditBefore }) => {
        const approver = await PhoneApprover.start({
          dir: join(cfg.dataDir, 'approver'),
          origin: cfg.approver.origin,
          listen: approverListen,
          ...(front ? { apiOnly: true } : {}),
          ...(tls ? { tls } : {}),
          ...(apns ? { apns } : {}),
          signer,
          platformWord: launchd ? 'Mac' : 'computer',
          log,
          onEvent: audit,
          auditBefore,
        });
        phoneRef.current = approver;
        return {
          approver,
          handoffs: approver,
          close: async () => {
            await approver.close();
            apns?.close();
          },
        };
      },
      ...(cfg.highRisk.length > 0 ? { highRiskDomains: cfg.highRisk } : {}),
      mcpHost: cfg.mcp.host,
      mcpPort: cfg.mcp.port,
      headless: display === null,
      ...(channel ? { browserChannel: channel } : {}),
      ...(launchd ? { browserSandbox: true } : {}),
      browserState: { persist: cfg.browser.persist },
      ...(cfg.passwordSource ? { passwordSource: { kind: cfg.passwordSource.kind } } : {}),
      startMcp: (deps) =>
        startMcpHttpServer({
          host: deps.host,
          port: deps.port,
          resolve: deps.resolve,
          onToolCall: deps.onToolCall,
        }),
    });
  } catch (err) {
    await display?.stop();
    throw err;
  }
  const audit = (event: string, fields: Record<string, unknown>) => {
    try {
      daemon.broker.audit.append(event, fields);
    } catch {}
  };
  const phone = phoneRef.current;
  if (!phone) throw new Error('the phone approver did not start');
  const addressSync = new ApproverAddressSync({ signer: daemon.signer.client, phone, audit });
  const address = await addressSync.start();

  const ops = new AuditedAdminOps(
    (op) => {
      daemon.broker.audit.append('admin.request', { op });
    },
    (op, ok) => audit('admin.result', { op, ok }),
  );
  registerCoreAdminOps(ops, daemon, {
    intentSocketPath: cfg.intentSocket,
    passwordSource: cfg.passwordSource?.kind ?? null,
  });
  registerCliAdminOps(ops, daemon.db, cfg.dataDir);
  ops.register('approver.pair', async () => {
    await addressSync.refresh();
    try {
      const url = phone.startPairing();
      return { url, origin: cfg.approver.origin, validMinutes: 10 };
    } catch (err) {
      if (err instanceof PairingRefused) throw new AdminError(err.message);
      throw err;
    }
  });
  const admin = await startAdminServer({
    listen: adminFd !== undefined ? { fd: adminFd } : { path: cfg.adminSocket },
    ops,
  });

  let stopping: Promise<void> | null = null;
  const stop = () => {
    stopping ??= (async () => {
      addressSync.stop();
      await new Promise<void>((r) => admin.close(() => r()));
      await daemon.stop();
      await display?.stop();
    })();
    return stopping;
  };
  daemon.signer.client.onUnexpectedClose(() => {
    log(
      `keyflap-core: lost the signer connection; exiting so ${serviceManager()?.kind ?? 'the service manager'} restarts the core`,
    );
    void stop().finally(opts.onSignerLost ?? (() => process.exit(1)));
  });

  const paired = (await daemon.signer.client.listApprovers()).approvers.some(
    (k) => k.origin === cfg.approver.origin,
  );
  audit('daemon.service', { socketActivated: intentFd !== undefined && adminFd !== undefined });
  log(`keyflap-core running as a service (approvals on your phone at ${cfg.approver.origin})`);
  log(`  MCP endpoint:  ${daemon.mcpUrl}`);
  log(`  intent socket: ${cfg.intentSocket}`);
  const browserLabel = display
    ? `headed on private display ${display.env.DISPLAY}`
    : channel
      ? 'headless (full Chromium, new headless mode)'
      : 'headless';
  log(`  browser:       ${browserLabel}`);
  log(
    `  browser state: ${daemon.persistence ? 'saved per agent, encrypted' : cfg.browser.persist ? 'NOT saved this run (no state key from the signer)' : 'ephemeral (browser.persist: false)'}`,
  );
  if (address.kind === 'latched' || address.kind === 'paused') {
    log(`  ${addressSummary(address).text}`);
    log('  details and the fix: sudo keyflap doctor');
  } else if (!paired) {
    log(`  no phone paired yet: run \`sudo keyflap approver pair\` for a one-time link`);
  }
  return { daemon, stop };
}

async function main(argv: string[]): Promise<void> {
  const unsupported = servicePlatformProblem();
  if (unsupported) throw new Error(unsupported);
  if (argv.length !== 2 || argv[0] !== '--config' || !argv[1]) {
    throw new Error(`usage: core-main.ts --config ${SERVICE_PATHS.coreConfig}`);
  }
  const cfg = parseCoreConfig(readProvisionedFile(argv[1]));
  const service = await runCoreService(cfg);
  let signalled = false;
  const onSignal = () => {
    if (signalled) return;
    signalled = true;
    service.stop().then(
      () => process.exit(0),
      () => process.exit(1),
    );
  };
  process.on('SIGTERM', onSignal);
  process.on('SIGINT', onSignal);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    log(`keyflap-core: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
