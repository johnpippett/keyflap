import { SERVICE_PLATFORMS } from '@aab/signer/platform';
import { describe, expect, it } from 'vitest';
import { parseCli } from '../src/args.ts';
import { runServiceCommand, ServiceCliError } from '../src/service/cli.ts';
import {
  DARWIN_LAUNCH_DAEMONS,
  DARWIN_LOG_DIR,
  LAUNCHD_MANAGER,
  requireServiceManager,
  SERVICE_MANAGERS,
  SERVICE_NAMES,
  SYSTEMD_MANAGER,
  serviceManager,
} from '../src/service/manager.ts';
import { DARWIN_SERVICE_PATHS, LINUX_SERVICE_PATHS } from '../src/service/paths.ts';
import { FakeSystem } from './setup-fakes.ts';

const LAUNCHCTL_PRINT = (state: string, pid: number | null) =>
  [
    'system/com.keyflap.core = {',
    '\tactive count = 1',
    '\tpath = /Library/LaunchDaemons/com.keyflap.core.plist',
    `\tstate = ${state}`,
    ...(pid === null ? [] : [`\tpid = ${pid}`]),
    '\tprogram = /opt/keyflap/bin/keyflap-launch',
    '}',
    '',
  ].join('\n');

describe('the service manager follows the service platform', () => {
  it('systemd on Linux, launchd on macOS, none elsewhere', () => {
    expect(serviceManager('linux')).toBe(SYSTEMD_MANAGER);
    expect(serviceManager('darwin')).toBe(LAUNCHD_MANAGER);
    expect(serviceManager('freebsd')).toBeNull();
    expect(() => requireServiceManager('win32')).toThrow(/not built for win32/);
    expect(Object.keys(SERVICE_MANAGERS).toSorted()).toEqual(
      Object.values(SERVICE_PLATFORMS)
        .map((p) => p.manager)
        .toSorted(),
    );
  });
});

describe('systemd (Linux): the strings and probes setup and doctor used before', () => {
  const m = SYSTEMD_MANAGER;

  it('names units and users keyflap-<service>', () => {
    expect(SERVICE_NAMES.map(m.unit)).toEqual([
      'keyflap-signer',
      'keyflap-core',
      'keyflap-approver',
    ]);
    expect(m.user('signer')).toBe('keyflap-signer');
    expect(m.user('web')).toBe('keyflap-web');
  });

  it('asks systemctl is-active and reports its word', async () => {
    const sys = new FakeSystem();
    sys.exec_ = (_c, args) => ({
      code: args[1] === 'keyflap-core.service' ? 3 : 0,
      stdout: args[1] === 'keyflap-core.service' ? 'failed\n' : 'active\n',
      stderr: '',
    });
    expect(await m.active(sys, 'signer')).toEqual({ active: true, state: 'active' });
    expect(await m.active(sys, 'core')).toEqual({ active: false, state: 'failed' });
    expect(sys.execs.map((e) => `${e.cmd} ${e.args.join(' ')}`)).toEqual([
      'systemctl is-active keyflap-signer.service',
      'systemctl is-active keyflap-core.service',
    ]);
    sys.exec_ = () => ({ code: null, stdout: '', stderr: '', error: 'ENOENT' });
    expect(await m.active(sys, 'core')).toEqual({ active: false, state: 'ENOENT' });
  });

  it('counts the install as present when the core unit file is listed', async () => {
    const sys = new FakeSystem();
    sys.exec_ = () => ({ code: 0, stdout: 'keyflap-core.service enabled enabled\n', stderr: '' });
    expect(await m.installed(sys)).toBe(true);
    sys.exec_ = () => ({ code: 1, stdout: '0 unit files listed.\n', stderr: '' });
    expect(await m.installed(sys)).toBe(false);
  });

  it('keeps the hints word for word', () => {
    expect(m.statusCommand(['core', 'signer'], true)).toBe(
      'sudo systemctl status keyflap-core keyflap-signer',
    );
    expect(m.statusCommand(['core', 'signer'], false)).toBe(
      'systemctl status keyflap-core keyflap-signer',
    );
    expect(m.logsCommand('core')).toBe('journalctl -u keyflap-core');
    expect(m.restartCommands(['signer', 'core'])).toEqual([
      ['systemctl', 'restart', 'keyflap-signer', 'keyflap-core'],
    ]);
    expect(m.socketsFix).toBe('sudo systemctl restart keyflap-core.socket …, or re-run install.sh');
    expect(m.installer).toBe('packages/install/linux/install.sh');
  });
});

describe('launchd (macOS): labels, hidden users, launchctl print, log files', () => {
  const m = LAUNCHD_MANAGER;

  it('names LaunchDaemons com.keyflap.<service> and users _keyflap-<service>', () => {
    expect(SERVICE_NAMES.map(m.unit)).toEqual([
      'com.keyflap.signer',
      'com.keyflap.core',
      'com.keyflap.approver',
    ]);
    expect(m.user('core')).toBe('_keyflap-core');
    expect(m.user('signer')).toBe('_keyflap-signer');
    expect(m.user('web')).toBe('_keyflap-web');
    expect(m.installer).toBe('packages/install/macos/install.sh');
  });

  it('reads the job state from launchctl print system/<label>; not loaded is inactive', async () => {
    const sys = new FakeSystem();
    sys.platform = 'darwin';
    sys.exec_ = (_c, args) =>
      args[1] === 'system/com.keyflap.core'
        ? { code: 0, stdout: LAUNCHCTL_PRINT('running', 4242), stderr: '' }
        : args[1] === 'system/com.keyflap.signer'
          ? { code: 0, stdout: LAUNCHCTL_PRINT('waiting', null), stderr: '' }
          : { code: 113, stdout: '', stderr: 'Could not find service "com.keyflap.approver"\n' };
    expect(await m.active(sys, 'core')).toEqual({ active: true, state: 'running' });
    expect(await m.active(sys, 'signer')).toEqual({ active: false, state: 'waiting' });
    expect(await m.active(sys, 'approver')).toEqual({ active: false, state: 'not loaded' });
    expect(sys.execs.map((e) => `${e.cmd} ${e.args.join(' ')}`)).toEqual([
      'launchctl print system/com.keyflap.core',
      'launchctl print system/com.keyflap.signer',
      'launchctl print system/com.keyflap.approver',
    ]);
  });

  it('counts the install as present when the core LaunchDaemon plist exists', async () => {
    const sys = new FakeSystem();
    sys.platform = 'darwin';
    expect(await m.installed(sys)).toBe(false);
    sys.file(`${DARWIN_LAUNCH_DAEMONS}/com.keyflap.core.plist`, '<plist/>', 0o644, 0);
    expect(await m.installed(sys)).toBe(true);
    expect(sys.execs).toEqual([]);
  });

  it('points at launchctl and the log files under /Library/Keyflap/log', () => {
    expect(m.statusCommand(['core', 'signer'], true)).toBe(
      'sudo launchctl print system/com.keyflap.core; sudo launchctl print system/com.keyflap.signer',
    );
    expect(m.logsCommand('core')).toBe(`sudo tail -n 50 ${DARWIN_LOG_DIR}/core/core.log`);
    expect(m.restartCommands(['signer', 'core'])).toEqual([
      ['launchctl', 'kickstart', '-k', 'system/com.keyflap.signer'],
      ['launchctl', 'kickstart', '-k', 'system/com.keyflap.core'],
    ]);
    expect(m.socketsFix).toContain('launchctl bootout system/com.keyflap.core');
    expect(m.socketsFix).toContain(`${DARWIN_LAUNCH_DAEMONS}/com.keyflap.core.plist`);
    expect(DARWIN_LOG_DIR).not.toMatch(/^\/(etc|var|tmp)(\/|$)/);
  });
});

describe('keyflap daemon under service mode names the real service manager', () => {
  const daemon = parseCli(['daemon', '--unprotected']);

  it('systemctl on Linux, launchctl on macOS', async () => {
    const linux = await runServiceCommand(
      daemon,
      () => {},
      LINUX_SERVICE_PATHS,
      SYSTEMD_MANAGER,
    ).catch((e: unknown) => e);
    expect(linux).toBeInstanceOf(ServiceCliError);
    expect((linux as Error).message).toBe(
      'the broker runs as a system service here (keyflap-core, keyflap-signer): ' +
        'use `systemctl status|restart keyflap-core`. `keyflap daemon --unprotected` is for a dev checkout.',
    );
    const mac = await runServiceCommand(
      daemon,
      () => {},
      DARWIN_SERVICE_PATHS,
      LAUNCHD_MANAGER,
    ).catch((e: unknown) => e);
    expect((mac as Error).message).toMatch(
      /^the broker runs as a system service here \(com\.keyflap\.core, com\.keyflap\.signer\): use `sudo launchctl print system\/com\.keyflap\.core`/,
    );
  });
});
