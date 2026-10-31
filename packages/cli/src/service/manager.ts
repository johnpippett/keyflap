import {
  SERVICE_PLATFORMS,
  type ServiceManagerKind,
  servicePlatform,
  servicePlatformProblem,
} from '@aab/signer/platform';

export const SERVICE_NAMES = ['signer', 'core', 'approver'] as const;
export type ServiceName = (typeof SERVICE_NAMES)[number];
export type ServiceUser = 'core' | 'signer' | 'web';

export interface ServiceState {
  active: boolean;
  state: string;
}

export interface Runner {
  exec(
    cmd: string,
    args: string[],
    opts?: { timeoutMs?: number },
  ): Promise<{ code: number | null; stdout: string; error?: string }>;
  exists(path: string): boolean;
}

export interface ServiceManager {
  kind: ServiceManagerKind;
  installer: string;
  unit(name: ServiceName): string;
  user(name: ServiceUser): string;
  active(sys: Runner, name: ServiceName): Promise<ServiceState>;
  installed(sys: Runner): Promise<boolean>;
  statusCommand(names: readonly ServiceName[], sudo: boolean): string;
  logsCommand(name: ServiceName): string;
  restartCommands(names: readonly ServiceName[]): string[][];
  reloadCommands: string[][];
  signerDropIns: string | null;
  socketsFix: string;
  daemonHint: string;
}

const PROBE_TIMEOUT_MS = 5_000;

export const SYSTEMD_MANAGER: ServiceManager = {
  kind: 'systemd',
  installer: 'packages/install/linux/install.sh',
  unit: (name) => `keyflap-${name}`,
  user: (name) => `keyflap-${name}`,
  async active(sys, name) {
    const r = await sys.exec('systemctl', ['is-active', `keyflap-${name}.service`], {
      timeoutMs: PROBE_TIMEOUT_MS,
    });
    const state = r.stdout.trim();
    return { active: state === 'active', state: state || r.error || 'unknown' };
  },
  async installed(sys) {
    const r = await sys.exec('systemctl', ['list-unit-files', 'keyflap-core.service'], {
      timeoutMs: PROBE_TIMEOUT_MS,
    });
    return r.code === 0 && /keyflap-core\.service/.test(r.stdout);
  },
  statusCommand: (names, sudo) =>
    `${sudo ? 'sudo ' : ''}systemctl status ${names.map((n) => `keyflap-${n}`).join(' ')}`,
  logsCommand: (name) => `journalctl -u keyflap-${name}`,
  restartCommands: (names) => [['systemctl', 'restart', ...names.map((n) => `keyflap-${n}`)]],
  reloadCommands: [['systemctl', 'daemon-reload']],
  signerDropIns: '/etc/systemd/system/keyflap-signer.service.d',
  socketsFix: 'sudo systemctl restart keyflap-core.socket …, or re-run install.sh',
  daemonHint: '`systemctl status|restart keyflap-core`',
};

export const DARWIN_LOG_DIR = '/Library/Keyflap/log';
export const DARWIN_LAUNCH_DAEMONS = '/Library/LaunchDaemons';
export const darwinLogFile = (name: ServiceName) => `${DARWIN_LOG_DIR}/${name}/${name}.log`;

const label = (name: ServiceName) => `com.keyflap.${name}`;
const plist = (name: ServiceName) => `${DARWIN_LAUNCH_DAEMONS}/${label(name)}.plist`;

export const LAUNCHD_MANAGER: ServiceManager = {
  kind: 'launchd',
  installer: 'packages/install/macos/install.sh',
  unit: label,
  user: (name) => `_keyflap-${name}`,
  async active(sys, name) {
    const r = await sys.exec('launchctl', ['print', `system/${label(name)}`], {
      timeoutMs: PROBE_TIMEOUT_MS,
    });
    if (r.code !== 0) return { active: false, state: r.error ?? 'not loaded' };
    const state = /^\s*state = (\S+)/m.exec(r.stdout)?.[1] ?? 'unknown';
    return { active: state === 'running', state };
  },
  installed: async (sys) => sys.exists(plist('core')),
  statusCommand: (names, sudo) =>
    names.map((n) => `${sudo ? 'sudo ' : ''}launchctl print system/${label(n)}`).join('; '),
  logsCommand: (name) => `sudo tail -n 50 ${darwinLogFile(name)}`,
  restartCommands: (names) =>
    names.map((n) => ['launchctl', 'kickstart', '-k', `system/${label(n)}`]),
  reloadCommands: [],
  signerDropIns: null,
  socketsFix: `sudo launchctl bootout system/${label('core')}; sudo launchctl bootstrap system ${plist('core')} …, or re-run install.sh`,
  daemonHint: `\`sudo launchctl print system/${label('core')}\` and \`sudo launchctl kickstart -k system/${label('core')}\``,
};

export const SERVICE_MANAGERS: Record<ServiceManagerKind, ServiceManager> = {
  systemd: SYSTEMD_MANAGER,
  launchd: LAUNCHD_MANAGER,
};

export function serviceManager(platform: string = process.platform): ServiceManager | null {
  const p = servicePlatform(platform);
  return p === null ? null : SERVICE_MANAGERS[SERVICE_PLATFORMS[p].manager];
}

export function requireServiceManager(platform: string = process.platform): ServiceManager {
  const m = serviceManager(platform);
  if (m === null) throw new Error(servicePlatformProblem(platform) as string);
  return m;
}
