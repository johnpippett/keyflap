import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  ApnsSender,
  ApproverAddressSync,
  ApproverKey,
  encodeQr,
  PhoneApprover,
  renderQrTerminal,
  styleFor,
  TerminalApprover,
  type TermStyle,
} from '@aab/approver';
import { type Daemon, type DaemonOptions, onePasswordEnv, startDaemon } from '@aab/core';
import { startMcpHttpServer } from '@aab/mcp';
import type { AddressState } from '@aab/signer/approver-address';
import { unixSocketPathProblem } from '@aab/signer/platform';
import { addressWords, devAddressFixes, devApproverAddress } from './approver-address.ts';
import type { PasswordSourceCli, PhoneApproverCli } from './args.ts';
import { hasKeyFile, KeyFileError, unlockFromKeyFile } from './key-file.ts';
import { type HiddenInput, readHiddenLine } from './passphrase.ts';
import { realSystem, type System } from './setup/system.ts';
import { isSimpleMode, PROTECTS_LESS, simpleStopHint } from './simple-install.ts';

export interface DaemonCliOptions {
  dataDir: string;
  mcpPort: number;
  headed: boolean;
  unprotected: true;
  phone?: PhoneApproverCli | null;
  highRisk?: string[];
  passwordSource?: PasswordSourceCli | null;
  ephemeralBrowser?: boolean;
  passphrase?: string;
}

export const UNPROTECTED_BANNER = [
  '!! UNPROTECTED: this broker runs as your OS user. Any agent with shell access as',
  '!! you can read its key files, memory and code. Development only (docs/ISOLATION_PLAN.md).',
].join('\n');

export function unprotectedBanner(st: TermStyle): string {
  return st.level === 0
    ? UNPROTECTED_BANNER
    : UNPROTECTED_BANNER.split('\n').map(st.bad).join('\n');
}

export class DaemonStartError extends Error {}

const log = (line: string) => process.stderr.write(`${line}\n`);

export async function getPassphrase(dataDir: string): Promise<string> {
  let fromEnv = process.env.KEYFLAP_PASSPHRASE;
  const legacy = process.env.AAB_PASSPHRASE;
  delete process.env.KEYFLAP_PASSPHRASE;
  delete process.env.AAB_PASSPHRASE;
  if (fromEnv === undefined && legacy !== undefined) {
    log('keyflap: AAB_PASSPHRASE is deprecated; set KEYFLAP_PASSPHRASE instead');
    fromEnv = legacy;
  }
  let fromKeyFile: string | null;
  try {
    fromKeyFile = unlockFromKeyFile(dataDir, { create: isSimpleMode() });
  } catch (err) {
    if (err instanceof KeyFileError) throw new DaemonStartError(err.message);
    throw err;
  }
  if (fromKeyFile !== null) {
    if (fromEnv !== undefined) {
      throw new DaemonStartError(
        `${dataDir} is unlocked by its key file, and KEYFLAP_PASSPHRASE is set too: unset it`,
      );
    }
    return fromKeyFile;
  }
  if (fromEnv !== undefined) {
    if (fromEnv.length === 0) throw new DaemonStartError('KEYFLAP_PASSPHRASE is set but empty');
    return fromEnv;
  }
  const input = process.stdin as HiddenInput;
  if (!input.isTTY) {
    throw new DaemonStartError(
      'no passphrase: set KEYFLAP_PASSPHRASE or run keyflap in a terminal to be prompted',
    );
  }
  const isNew = !existsSync(join(dataDir, 'signer', 'keys.enc.json'));
  const first = await readHiddenLine(
    isNew ? 'New key-store passphrase: ' : 'Key-store passphrase: ',
    input,
    process.stderr,
  );
  if (first.length === 0) throw new DaemonStartError('empty passphrase');
  if (isNew) {
    const again = await readHiddenLine('Repeat passphrase: ', input, process.stderr);
    if (again !== first) throw new DaemonStartError('passphrases do not match');
  }
  return first;
}

export function takeOnePasswordEnv(env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const opEnv = onePasswordEnv(env);
  delete env.OP_SERVICE_ACCOUNT_TOKEN;
  if (!opEnv.OP_SERVICE_ACCOUNT_TOKEN) {
    throw new DaemonStartError(
      '--password-source 1password needs OP_SERVICE_ACCOUNT_TOKEN (a 1Password service account token) in the environment (docs/integrations/1password.md)',
    );
  }
  return opEnv;
}

export async function runDaemon(opts: DaemonCliOptions): Promise<Daemon> {
  for (const [name, what] of [
    ['intent.sock', 'intent socket'],
    ['signer.sock', 'signer socket'],
  ] as const) {
    const problem = unixSocketPathProblem(join(opts.dataDir, 'run', name), what);
    if (problem) throw new DaemonStartError(problem);
  }
  const opEnv = opts.passwordSource?.kind === '1password' ? takeOnePasswordEnv() : null;
  const passphrase = opts.passphrase ?? (await getPassphrase(opts.dataDir));
  mkdirSync(opts.dataDir, { recursive: true, mode: 0o700 });
  const phone = opts.phone ?? null;
  const sys = realSystem();
  const address = phone ? devApproverAddress(phone.origin, phone.listen, sys) : undefined;
  const phoneRef: { current: PhoneApprover | null } = { current: null };
  let approverOpts: Pick<
    DaemonOptions,
    'approver' | 'makeApprover' | 'trustedApproverKeys' | 'approverAddress'
  >;
  if (phone) {
    approverOpts = {
      trustedApproverKeys: {},
      ...(address ? { approverAddress: address } : {}),
      makeApprover: async ({ signer, audit, auditBefore }) => {
        const apns = phone.apns
          ? new ApnsSender({
              key: readFileSync(phone.apns.keyFile),
              keyId: phone.apns.keyId,
              teamId: phone.apns.teamId,
              bundleId: phone.apns.bundleId,
              defaultEnvironment: phone.apns.sandbox ? 'sandbox' : 'production',
              generic: phone.apns.generic,
            })
          : undefined;
        const approver = await PhoneApprover.start({
          dir: join(opts.dataDir, 'approver'),
          origin: phone.origin,
          listen: phone.listen,
          ...(phone.tlsCert && phone.tlsKey
            ? { tls: { cert: readFileSync(phone.tlsCert), key: readFileSync(phone.tlsKey) } }
            : {}),
          signer,
          ...(apns ? { apns } : {}),
          platformWord: sys.platform === 'darwin' ? 'Mac' : 'computer',
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
    };
  } else {
    const approverKey = ApproverKey.loadOrCreate(join(opts.dataDir, 'approver-key.json'));
    if (!process.stdin.isTTY) {
      log('warning: stdin is not a terminal; approval prompts can only be answered through it');
    }
    approverOpts = {
      approver: new TerminalApprover({ key: approverKey }),
      trustedApproverKeys: approverKey.trustEntry(),
    };
  }
  const daemon = await startDaemon({
    dataDir: opts.dataDir,
    passphrase,
    ...approverOpts,
    ...(opts.highRisk && opts.highRisk.length > 0 ? { highRiskDomains: opts.highRisk } : {}),
    mcpPort: opts.mcpPort,
    headless: !opts.headed,
    ...(opts.passwordSource
      ? {
          passwordSource: {
            kind: opts.passwordSource.kind,
            ...(opts.passwordSource.bin ? { bin: opts.passwordSource.bin } : {}),
            ...(opts.passwordSource.vault ? { vault: opts.passwordSource.vault } : {}),
            ...(opEnv ? { env: opEnv } : {}),
          },
        }
      : {}),
    ...(opts.ephemeralBrowser ? { browserState: { persist: false } } : {}),
    onSignerLog: (line) => log(line),
    startMcp: (deps) =>
      startMcpHttpServer({
        host: deps.host,
        port: deps.port,
        resolve: deps.resolve,
        onToolCall: deps.onToolCall,
      }),
  });
  let addressSync: ApproverAddressSync | null = null;
  if (phone && phoneRef.current) {
    const approver = phoneRef.current;
    addressSync = new ApproverAddressSync({
      signer: daemon.signer.client,
      phone: approver,
      audit: (event, fields) => daemon.broker.audit.append(event, fields),
    });
    const state = await addressSync.start();
    if (address && (state.kind === 'latched' || state.kind === 'paused')) {
      logAddressProblem(state, address, sys);
    } else {
      await offerPairing(approver, daemon, phone, opts.dataDir);
    }
  }
  const stop = () => {
    addressSync?.stop();
    return daemon.stop();
  };
  const simple = hasKeyFile(opts.dataDir);
  daemon.broker.audit.append('daemon.unprotected', {
    dataDir: opts.dataDir,
    ...(simple ? { install: 'simple' } : {}),
  });
  const active = daemon.registry.list().filter((a) => a.revokedAt === null);
  const st = styleFor(process.stderr);
  const label = (l: string) => st.dim(l);
  if (st.level !== 0) log(st.header('daemon'));
  log(simple ? st.bad(PROTECTS_LESS) : unprotectedBanner(st));
  log(
    phone
      ? `${st.ok('keyflap daemon running')} (approvals on your phone at ${phone.origin}${phone.apns ? ', APNs on' : ''})`
      : `${st.ok('keyflap daemon running')} (Phase A: approvals are asked on this terminal)`,
  );
  log(`  ${label('MCP endpoint: ')} ${daemon.mcpUrl}`);
  log(`  ${label('intent socket:')} ${daemon.intentSocketPath}`);
  log(`  ${label('data dir:     ')} ${opts.dataDir}`);
  log(
    `  ${label('browser state:')} ${
      daemon.persistence
        ? `saved per agent, encrypted (${join(opts.dataDir, 'browser-state')})`
        : opts.ephemeralBrowser
          ? 'ephemeral (--ephemeral-browser)'
          : st.bad('NOT saved this run (the signer gave no state key; see keyflap audit tail)')
    }`,
  );
  if (opts.passwordSource) {
    const vault = opts.passwordSource.vault ? ` (vault "${opts.passwordSource.vault}")` : '';
    const name = opts.passwordSource.kind === '1password' ? '1Password' : 'Proton Pass';
    log(
      `  ${label('passwords:    ')} native + ${name}${vault}, matching logins to sites in the background`,
    );
  }
  log(
    active.length === 0
      ? `  ${st.dim('no agents yet: run `keyflap agent add <name>` in another terminal')}`
      : `  ${label('agents:       ')} ${active.map((a) => a.name).join(', ')}`,
  );
  log(st.dim(simple ? simpleStopHint(process.getuid?.() ?? -1, homedir()) : 'Ctrl-C to stop.'));
  return { ...daemon, stop };
}

async function offerPairing(
  approver: PhoneApprover,
  daemon: Daemon,
  phone: PhoneApproverCli,
  dataDir: string,
): Promise<void> {
  const paired = (await daemon.signer.client.listApprovers()).approvers.some(
    (k) => k.origin === phone.origin,
  );
  if (paired && !phone.pair) return;
  const url = approver.startPairing();
  log(
    paired
      ? 'Pairing another phone (an already-paired phone must approve it).'
      : 'No phone paired yet. Open this one-time link on your phone to pair it:',
  );
  log(`  ${url}`);
  log(`  (valid 10 minutes; also in ${join(dataDir, 'approver', 'pairing-url')})`);
  if (process.stderr.isTTY) {
    log('  Or point your iPhone camera at this (it opens in Safari):');
    log(renderQrTerminal(encodeQr(url), process.stderr));
    log('  Pair in Safari first, then Share > Add to Home Screen: iOS copies the pairing');
    log('  into the home-screen app only when you add it.');
  }
}

function logAddressProblem(
  state: AddressState,
  address: { origin: string; target: string },
  sys: System,
): void {
  const words = addressWords(state, address, () => devAddressFixes(sys, address));
  log(`Approval address: ${words.line}`);
  if (words.approvalsOff) log(`  ${words.approvalsOff}`);
  if (words.fix) log(`  fix: ${words.fix}`);
}

export function stopOnSignals(daemon: Promise<Daemon>): void {
  let stopping = 0;
  const onSignal = (sig: NodeJS.Signals) => {
    if (stopping !== 0) {
      if (Date.now() - stopping < 1_000) return;
      log(`${sig} again: exiting without clean shutdown`);
      process.exit(1);
    }
    stopping = Date.now();
    log(`${sig}: stopping…`);
    daemon
      .then((d) => d.stop())
      .then(
        () => process.exit(0),
        () => process.exit(1),
      );
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  process.on('SIGHUP', onSignal);
}
