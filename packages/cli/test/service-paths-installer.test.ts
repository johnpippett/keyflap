import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { LINUX_SERVICE_PATHS as SERVICE_PATHS } from '../src/service/paths.ts';

const LINUX = join(import.meta.dirname, '..', '..', 'install', 'linux');
const read = (...parts: string[]) => readFileSync(join(LINUX, ...parts), 'utf8');

const installSh = read('install.sh');
const assignedPaths = [...installSh.matchAll(/^([a-z_]+)=(\/[^\s"']+)$/gm)];
const installShExpanded = assignedPaths
  .reduce((text, [, name, value]) => text.replaceAll(`$${name}`, value as string), installSh)
  .replaceAll('"', '');
const wrapper = read('keyflap-wrapper.sh');
const tmpfiles = read('tmpfiles.conf');
const unitFiles = readdirSync(join(LINUX, 'units'));

function setting(unit: string, key: string): string[] {
  return read('units', unit)
    .split('\n')
    .filter((l) => l.startsWith(`${key}=`))
    .map((l) => l.slice(key.length + 1));
}

const listened = unitFiles
  .filter((u) => u.endsWith('.socket'))
  .flatMap((u) => setting(u, 'ListenStream'))
  .filter((p) => p.startsWith('/'));

const tmpfilesDirs = tmpfiles
  .split('\n')
  .filter((l) => l.startsWith('d '))
  .map((l) => l.split(/\s+/)[1]);

const SOCKETS = [
  'intentSocket',
  'adminSocket',
  'signerSocket',
  'signerAdminSocket',
  'approverApiSocket',
] as const;

describe('SERVICE_PATHS names exactly what packages/install/linux creates', () => {
  it('every service socket path is a ListenStream= of a socket unit, and no unit listens elsewhere', () => {
    const wanted = SOCKETS.map((k) => SERVICE_PATHS[k]);
    expect(listened.toSorted()).toEqual(wanted.toSorted());
  });

  it('the directory of every service socket is created by tmpfiles.d', () => {
    for (const k of SOCKETS) expect(tmpfilesDirs, k).toContain(dirname(SERVICE_PATHS[k]));
  });

  it('the installer creates the code prefix and the data directories', () => {
    const created = installShExpanded
      .split('\n')
      .filter((l) => l.startsWith('install -d '))
      .flatMap((l) => l.split(/\s+/));
    for (const k of ['prefix', 'coreData', 'signerData', 'hookDir'] as const) {
      expect(created, k).toContain(SERVICE_PATHS[k]);
    }
  });

  it('the installer writes the host token where the hook reads it', () => {
    expect(SERVICE_PATHS.hostToken).toBe(join(SERVICE_PATHS.hookDir, 'host-token'));
    expect(installShExpanded).toContain(`>${SERVICE_PATHS.hostToken}`);
  });

  it('each service reads the config file the installer writes for it', () => {
    const chmodLine = installSh.split('\n').find((l) => l.startsWith('chmod 0644 /etc/keyflap/'));
    for (const [unit, key] of [
      ['keyflap-core.service', 'coreConfig'],
      ['keyflap-signer.service', 'signerConfig'],
      ['keyflap-approver.service', 'approverConfig'],
    ] as const) {
      expect(setting(unit, 'ExecStart').join('\n'), unit).toMatch(
        new RegExp(` --config ${SERVICE_PATHS[key].replaceAll('/', '\\/')}$`),
      );
      expect(chmodLine, key).toContain(SERVICE_PATHS[key]);
    }
  });

  it('the wrapper is installed where the CLI says, and runs code under the prefix', () => {
    expect(installSh).toContain(`"$here/keyflap-wrapper.sh" ${SERVICE_PATHS.wrapper}`);
    expect(wrapper).toMatch(
      new RegExp(
        `^exec ${SERVICE_PATHS.prefix}/node/bin/node .* ${SERVICE_PATHS.prefix}/app/packages/cli/src/main\\.ts "\\$@"$`,
        'm',
      ),
    );
  });
});
