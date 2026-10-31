import { parseServiceConfig } from '@aab/signer/service';
import { buildServiceConfigs, parseCoreConfig } from '../src/service/config.ts';
import { LAUNCHD_MANAGER, type ServiceManager, SYSTEMD_MANAGER } from '../src/service/manager.ts';
import {
  DARWIN_SERVICE_PATHS,
  LINUX_SERVICE_PATHS,
  type ServicePaths,
} from '../src/service/paths.ts';
import type { ExecOptions, ExecResult } from '../src/setup/system.ts';
import { FakeSystem } from './setup-fakes.ts';

export const SIGNER_UID = 990;
export const MAC_SIGNER_UID = 492;
export const OP_TOKEN = 'ops_eyJzaWduSW5BZGRyZXNzIjoic2VjcmV0LXRva2VuIn0';
export const PROTON_TOKEN = 'pat-AAAA-BBBB-CCCC-DDDD';
export const OP_BIN = '/opt/keyflap/tools/op/op';
export const PASS_BIN = '/opt/keyflap/tools/pass-cli/pass-cli';
export const OP_SHA = 'c'.repeat(64);
export const PASS_SHA = 'd'.repeat(64);
export const ORIGIN = 'https://box.tail1.ts.net:8766';

export interface Call {
  cmd: string;
  args: string[];
  opts: ExecOptions;
}

export interface Machine {
  sys: FakeSystem;
  paths: ServicePaths;
  m: ServiceManager;
  platform: 'linux' | 'darwin';
  signerUid: number;
  vaults: { op: string[]; proton: string[] };
  protonLoggedIn: boolean;
  failRestart: boolean;
  down: boolean;
  calls: Call[];
  commands(): string[][];
  config(file: 'signer' | 'core'): Record<string, unknown>;
  snapshot(): string;
  assertValid(): void;
  allArgv(): string;
}

const NO_NETWORK_DROPIN = '[Service]\nRestrictAddressFamilies=\nRestrictAddressFamilies=AF_UNIX\n';

export function machine(
  platform: 'linux' | 'darwin',
  start: { source?: 'proton-pass' | '1password'; vault?: string } = {},
): Machine {
  const sys = new FakeSystem();
  sys.uid = 0;
  sys.gid = 0;
  sys.platform = platform;
  const paths = platform === 'linux' ? LINUX_SERVICE_PATHS : DARWIN_SERVICE_PATHS;
  const m = platform === 'linux' ? SYSTEMD_MANAGER : LAUNCHD_MANAGER;
  const signerUid = platform === 'linux' ? SIGNER_UID : MAC_SIGNER_UID;
  const etc = paths.signerConfig.replace(/\/signer\.json$/, '');
  sys.dir(etc, 0o755, 0);
  const { core, signer } = buildServiceConfigs(
    {
      approverOrigin: ORIGIN,
      tls: false,
      highRisk: [],
      ...(start.source === 'proton-pass'
        ? {
            protonPassBin: PASS_BIN,
            protonPassSha256: PASS_SHA,
            ...(start.vault ? { protonPassVault: start.vault } : {}),
          }
        : {}),
      ...(start.source === '1password'
        ? {
            onePasswordBin: OP_BIN,
            onePasswordSha256: OP_SHA,
            ...(start.vault ? { onePasswordVault: start.vault } : {}),
          }
        : {}),
    },
    paths,
    platform,
  );
  sys.file(paths.signerConfig, `${JSON.stringify(signer, null, 2)}\n`, 0o644, 0);
  sys.file(paths.coreConfig, `${JSON.stringify(core, null, 2)}\n`, 0o644, 0);
  if (platform === 'linux') {
    sys.dir('/etc/keyflap/credentials', 0o700, 0);
    sys.dir('/etc/systemd/system/keyflap-signer.service.d', 0o755, 0);
    if (start.source === '1password') {
      sys.file(paths.opToken, 'SEALED:old', 0o600, 0);
      sys.file(
        '/etc/systemd/system/keyflap-signer.service.d/1password.conf',
        `[Service]\nLoadCredentialEncrypted=op-service-account-token:${paths.opToken}\n`,
        0o644,
        0,
      );
    } else if (start.source === undefined) {
      sys.file(
        '/etc/systemd/system/keyflap-signer.service.d/no-network.conf',
        NO_NETWORK_DROPIN,
        0o644,
        0,
      );
    }
    sys.file(
      '/etc/passwd',
      `keyflap-signer:x:${SIGNER_UID}:${SIGNER_UID}::/var/lib/keyflap/signer:/usr/sbin/nologin\n`,
      0o644,
      0,
    );
  } else {
    sys.dir('/Library/Keyflap/credentials/signer', 0o500, MAC_SIGNER_UID);
    if (start.source === '1password') {
      sys.file(paths.opToken, 'old', 0o400, MAC_SIGNER_UID);
    }
  }
  for (const [bin, sha] of [
    [OP_BIN, OP_SHA],
    [PASS_BIN, PASS_SHA],
  ] as const) {
    sys.dir(bin.replace(/\/[^/]+$/, ''), 0o755, 0);
    sys.file(bin, '#!/bin/sh\n', 0o755, 0);
    sys.tools.set(bin, { ok: true, path: bin, sha256: sha });
  }

  const mach: Machine = {
    sys,
    paths,
    m,
    platform,
    signerUid,
    vaults: { op: ['Agent', 'Private'], proton: ['Agent', 'Personal'] },
    protonLoggedIn: start.source === 'proton-pass',
    failRestart: false,
    down: false,
    calls: [],
    commands: () => mach.calls.map((c) => [c.cmd, ...c.args]),
    config: (file) =>
      JSON.parse(sys.text(file === 'signer' ? paths.signerConfig : paths.coreConfig) as string),
    snapshot: () => JSON.stringify([...sys.nodes.entries()].sort(([a], [b]) => a.localeCompare(b))),
    assertValid: () => {
      parseServiceConfig(sys.text(paths.signerConfig) as string);
      parseCoreConfig(sys.text(paths.coreConfig) as string, platform);
    },
    allArgv: () => mach.calls.map((c) => [c.cmd, ...c.args].join(' ')).join('\n'),
  };

  sys.exec_ = (cmd, args, opts): ExecResult => {
    mach.calls.push({ cmd, args, opts });
    const ok = (stdout = ''): ExecResult => ({ code: 0, stdout, stderr: '' });
    const no = (stderr: string): ExecResult => ({ code: 1, stdout: '', stderr });
    if (cmd === '/usr/bin/id') {
      return args[1] === '_keyflap-signer'
        ? ok(
            `_keyflap-signer:*:${MAC_SIGNER_UID}:${MAC_SIGNER_UID}::0:0:Keyflap:/Library/Keyflap/data/signer:/usr/bin/false\n`,
          )
        : no('no such user\n');
    }
    if (cmd === 'systemd-creds') {
      const out = args[args.length - 1] as string;
      sys.file(
        out,
        `SEALED:${Buffer.from(opts.input ?? '')
          .toString('base64')
          .split('')
          .reverse()
          .join('')}`,
        0o644,
        0,
      );
      return ok();
    }
    if (cmd === 'systemctl' && args[0] === 'is-active')
      return ok(mach.down ? 'failed\n' : 'active\n');
    if (cmd === 'systemctl' && args[0] === 'restart') {
      return mach.failRestart ? no('Job failed\n') : ok();
    }
    if (cmd === 'systemctl') return ok();
    if (cmd === 'launchctl' && args[0] === 'print') {
      return ok(mach.down ? '\tstate = waiting\n' : '\tstate = running\n');
    }
    if (cmd === 'launchctl') return mach.failRestart ? no('Could not kickstart\n') : ok();
    if (cmd === OP_BIN) {
      return opts.env?.OP_SERVICE_ACCOUNT_TOKEN === OP_TOKEN
        ? ok(JSON.stringify(mach.vaults.op.map((name) => ({ name }))))
        : no('[ERROR] invalid service account token');
    }
    if (cmd === PASS_BIN) {
      if (args[0] === 'login') {
        if (opts.env?.PROTON_PASS_PERSONAL_ACCESS_TOKEN !== PROTON_TOKEN) return no('bad token');
        mach.protonLoggedIn = true;
        return ok();
      }
      if (args[0] === 'logout') {
        mach.protonLoggedIn = false;
        return ok();
      }
      if (args[0] === 'vault') {
        return mach.protonLoggedIn
          ? ok(JSON.stringify({ vaults: mach.vaults.proton.map((name) => ({ name })) }))
          : no("Run 'pass-cli login'");
      }
    }
    return { code: null, stdout: '', stderr: '', error: 'ENOENT' };
  };
  return mach;
}
