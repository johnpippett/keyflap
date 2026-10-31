import {
  type CredentialSource,
  isSha256,
  OnePasswordSource,
  ProtonPassSource,
  type ToolProblem,
} from '@aab/sources';
import { AdminError, AdminOps, startAdminServer } from './admin-wire.ts';
import { type ApproverAddress, parseApproverAddress } from './approver-address.ts';
import { KeyStore } from './keystore.ts';
import { acquireLock, type FileLock } from './lock.ts';
import type { SignerSourcesConfig } from './protocol.ts';
import { SignerError, SignerHandler, startSignerServer } from './server.ts';
import { clearListenEnv, listenFds, readCredential, readProvisionedFile } from './systemd.ts';

export interface SignerServiceConfig {
  storePath: string;
  socketPath?: string;
  adminSocketPath?: string;
  highRiskDomains?: string[];
  sources?: SignerSourcesConfig;
  approverAddress?: ApproverAddress;
}

export type SourceTrust =
  | { mode: 'system'; reread?: () => SignerSourcesConfig | undefined }
  | { mode: 'same-user' };

export function buildSources(
  cfg: SignerSourcesConfig | undefined,
  trust: SourceTrust,
  onToolRefused?: (e: { tool: string; path: string; problem: ToolProblem; detail: string }) => void,
): CredentialSource[] {
  const out: CredentialSource[] = [];
  const pp = cfg?.protonPass;
  if (pp) {
    out.push(
      new ProtonPassSource({
        bin: pp.bin,
        env: pp.env,
        trust:
          trust.mode === 'system'
            ? {
                mode: 'system',
                ...(pp.sha256 !== undefined ? { sha256: pp.sha256 } : {}),
                currentPin: () => trust.reread?.()?.protonPass?.sha256,
              }
            : trust,
        ...(onToolRefused ? { onToolRefused } : {}),
        ...(pp.vault !== undefined ? { vault: pp.vault } : {}),
      }),
    );
  }
  const op = cfg?.onePassword;
  if (op) {
    out.push(
      new OnePasswordSource({
        bin: op.bin,
        env: op.env,
        trust:
          trust.mode === 'system'
            ? {
                mode: 'system',
                ...(op.sha256 !== undefined ? { sha256: op.sha256 } : {}),
                currentPin: () => trust.reread?.()?.onePassword?.sha256,
              }
            : trust,
        ...(onToolRefused ? { onToolRefused } : {}),
        ...(op.vault !== undefined ? { vault: op.vault } : {}),
      }),
    );
  }
  return out;
}

export const OP_TOKEN_CREDENTIAL = 'op-service-account-token';

export function withServiceSecrets(
  cfg: SignerSourcesConfig | undefined,
  read: (name: string) => Buffer | null,
  log: (event: string, fields?: Record<string, unknown>) => void,
): SignerSourcesConfig | undefined {
  if (!cfg?.onePassword) return cfg;
  const raw = read(OP_TOKEN_CREDENTIAL);
  const token = raw?.toString('utf8').trim() ?? '';
  raw?.fill(0);
  if (token.length === 0) {
    log('source_token_missing', { source: '1password', credential: OP_TOKEN_CREDENTIAL });
    return cfg;
  }
  return {
    ...cfg,
    onePassword: {
      ...cfg.onePassword,
      env: { ...cfg.onePassword.env, OP_SERVICE_ACCOUNT_TOKEN: token },
    },
  };
}

function checkSourceEntry(
  name: 'protonPass' | 'onePassword',
  s: { bin?: unknown; env?: unknown; vault?: unknown; sha256?: unknown },
): void {
  if (typeof s !== 'object' || s === null) {
    throw new Error(`signer config: sources.${name} must be an object`);
  }
  if (typeof s.bin !== 'string' || !s.bin.startsWith('/')) {
    throw new Error(`signer config: sources.${name}.bin must be an absolute path`);
  }
  if (
    typeof s.env !== 'object' ||
    s.env === null ||
    Object.values(s.env).some((v) => typeof v !== 'string')
  ) {
    throw new Error(`signer config: sources.${name}.env must map names to strings`);
  }
  if (s.vault !== undefined && typeof s.vault !== 'string') {
    throw new Error(`signer config: sources.${name}.vault must be a vault name`);
  }
  if (s.sha256 !== undefined && !isSha256(s.sha256)) {
    throw new Error(`signer config: sources.${name}.sha256 must be 64 lower-case hex digits`);
  }
}

const SERVICE_KEYS = new Set([
  'storePath',
  'socketPath',
  'adminSocketPath',
  'highRiskDomains',
  'sources',
  'approverAddress',
]);

export function parseServiceConfig(text: string): SignerServiceConfig {
  const cfg = JSON.parse(text) as Record<string, unknown>;
  if (typeof cfg !== 'object' || cfg === null || Array.isArray(cfg)) {
    throw new Error('signer config must be a JSON object');
  }
  const stray = Object.keys(cfg).find((k) => !SERVICE_KEYS.has(k));
  if (stray) throw new Error(`signer config: unknown key "${stray}"`);
  const abs = (k: string, required: boolean): string | undefined => {
    const v = cfg[k];
    if (v === undefined && !required) return undefined;
    if (typeof v !== 'string' || !v.startsWith('/')) {
      throw new Error(`signer config: ${k} must be an absolute path`);
    }
    return v;
  };
  const hr = cfg.highRiskDomains;
  if (hr !== undefined && (!Array.isArray(hr) || hr.some((d) => typeof d !== 'string'))) {
    throw new Error('signer config: highRiskDomains must be a list of domains');
  }
  const sources = cfg.sources as SignerSourcesConfig | undefined;
  if (sources !== undefined) {
    if (typeof sources !== 'object' || sources === null || Array.isArray(sources)) {
      throw new Error('signer config: sources must be an object');
    }
    const strayKey = Object.keys(sources).find((k) => k !== 'protonPass' && k !== 'onePassword');
    if (strayKey) throw new Error(`signer config: unknown key "sources.${strayKey}"`);
  }
  if (sources?.protonPass !== undefined) checkSourceEntry('protonPass', sources.protonPass);
  const op = sources?.onePassword;
  if (op !== undefined) {
    checkSourceEntry('onePassword', op);
    if (Object.keys(op.env).some((k) => k.startsWith('OP_'))) {
      throw new Error(
        'signer config: sources.onePassword.env must not set OP_* (the token is the credential op-service-account-token)',
      );
    }
  }
  const out: SignerServiceConfig = { storePath: abs('storePath', true) as string };
  const sp = abs('socketPath', false);
  const ap = abs('adminSocketPath', false);
  if (sp !== undefined) out.socketPath = sp;
  if (ap !== undefined) out.adminSocketPath = ap;
  if (hr !== undefined) out.highRiskDomains = hr as string[];
  if (sources !== undefined) out.sources = sources;
  if (cfg.approverAddress !== undefined) {
    out.approverAddress = parseApproverAddress(cfg.approverAddress, {
      where: 'signer config: approverAddress',
      pollMs: 'refuse',
    });
  }
  return out;
}

export interface SignerServiceDeps {
  log: (event: string, fields?: Record<string, unknown>) => void;
  setLock: (lock: FileLock) => void;
}

export async function runSignerService(configPath: string, deps: SignerServiceDeps): Promise<void> {
  const { log } = deps;
  const cfg = parseServiceConfig(readProvisionedFile(configPath));
  const channelKey = readCredential('channel-key') as Buffer;
  if (channelKey.length < 32) throw new Error('credential "channel-key" is shorter than 32 bytes');
  const kek = readCredential('kek') as Buffer;
  if (kek.length !== 32) throw new Error('credential "kek" must be 32 bytes');
  const fds = listenFds();
  clearListenEnv();

  const lock = acquireLock(`${cfg.storePath}.lock`);
  deps.setLock(lock);
  const store = KeyStore.open(cfg.storePath, kek.toString('base64url'));
  kek.fill(0);
  const handler = new SignerHandler({
    store,
    trustedApproverKeys: {},
    highRiskDomains: cfg.highRiskDomains ?? [],
    sources: buildSources(
      withServiceSecrets(cfg.sources, (n) => readCredential(n, { optional: true }), log),
      {
        mode: 'system',
        reread: () => parseServiceConfig(readProvisionedFile(configPath)).sources,
      },
      (e) => log('source_tool_refused', e),
    ),
    ...(cfg.approverAddress
      ? {
          approverAddress: {
            address: cfg.approverAddress,
            trust: { mode: 'system' },
          },
        }
      : {}),
    log,
  });
  await handler.startAddressWatch();

  const channelFd = fds.get('signer');
  const adminFd = fds.get('signer-admin');
  if (channelFd === undefined && cfg.socketPath === undefined) {
    throw new Error('no signer socket: not socket-activated and no socketPath in the config');
  }
  if (adminFd === undefined && cfg.adminSocketPath === undefined) {
    throw new Error('no admin socket: not socket-activated and no adminSocketPath in the config');
  }
  const server = await startSignerServer({
    ...(channelFd !== undefined ? { listenFd: channelFd } : { socketPath: cfg.socketPath }),
    channelKey,
    handler,
    log,
  });
  const ops = new AdminOps();
  for (const op of ['status', 'approver.list', 'approver.remove']) {
    ops.register(op, (params) => {
      try {
        return handler.admin(op, params);
      } catch (err) {
        throw new AdminError(err instanceof SignerError ? err.message : 'internal error');
      }
    });
  }
  ops.register('approver.address.clear', async () => ({
    state: await handler.clearApproverAddress(),
  }));
  const admin = await startAdminServer({
    listen: adminFd !== undefined ? { fd: adminFd } : { path: cfg.adminSocketPath as string },
    ops,
    onRequest: (op, ok) => log('admin_request', { op, ok }),
  });
  log('ready', { mode: 'service', socketActivated: channelFd !== undefined });
  const shutdown = () => {
    handler.stopAddressWatch();
    server.close();
    admin.close();
    lock.release();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}
