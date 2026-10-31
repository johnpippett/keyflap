import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { darwinLogFile, LAUNCHD_MANAGER, SERVICE_NAMES } from '../src/service/manager.ts';
import { DARWIN_SERVICE_PATHS as SERVICE_PATHS } from '../src/service/paths.ts';

const MACOS = join(import.meta.dirname, '..', '..', 'install', 'macos');
const read = (...parts: string[]) => readFileSync(join(MACOS, ...parts), 'utf8');

const installSh = read('install.sh');
const assignedPaths = [...installSh.matchAll(/^([a-z_]+)=(\/[^\s"']+)$/gm)];
const installShExpanded = assignedPaths
  .reduce((text, [, name, value]) => text.replaceAll(`$${name}`, value as string), installSh)
  .replaceAll('"', '');
const wrapper = read('keyflap-wrapper.sh');
const plist = (name: (typeof SERVICE_NAMES)[number]) =>
  read('launchd', `${LAUNCHD_MANAGER.unit(name)}.plist`);

const strings = (xml: string, key: string): string[] =>
  [...xml.matchAll(new RegExp(`<key>${key}</key>\\s*<string>([^<]*)</string>`, 'g'))].map(
    (m) => m[1] as string,
  );
const programArguments = (xml: string): string[] => {
  const m = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(xml);
  return [...(m?.[1] ?? '').matchAll(/<string>([^<]*)<\/string>/g)].map((x) => x[1] as string);
};
const socketNames = (xml: string): string[] => {
  const m = /<key>Sockets<\/key>\s*<dict>([\s\S]*?)\n {2}<\/dict>/.exec(xml);
  return [...(m?.[1] ?? '').matchAll(/^ {4}<key>([^<]+)<\/key>/gm)].map((x) => x[1] as string);
};

const SOCKETS = [
  'intentSocket',
  'adminSocket',
  'signerSocket',
  'signerAdminSocket',
  'approverApiSocket',
] as const;

const createdDirs = installShExpanded
  .split('\n')
  .filter((l) => l.startsWith('install -d '))
  .flatMap((l) => l.split(/\s+/));

describe('DARWIN_SERVICE_PATHS names exactly what packages/install/macos creates', () => {
  it('every service socket path is a launchd SockPathName, and no plist binds a path elsewhere', () => {
    const listened = SERVICE_NAMES.flatMap((n) => strings(plist(n), 'SockPathName'));
    expect(listened.toSorted()).toEqual(SOCKETS.map((k) => SERVICE_PATHS[k]).toSorted());
  });

  it('the installer creates the directory of every socket, root-owned (launchd will not replace a planted file)', () => {
    for (const k of SOCKETS) {
      const dir = dirname(SERVICE_PATHS[k]);
      const line = installShExpanded
        .split('\n')
        .find((l) => l.startsWith('install -d ') && l.split(/\s+/).includes(dir));
      expect(line, k).toMatch(/-o root -g (wheel|_keyflap-\w+)/);
    }
  });

  it('the installer creates the code prefix, the data directories and the hook dir', () => {
    for (const k of ['prefix', 'coreData', 'signerData', 'hookDir'] as const) {
      expect(createdDirs, k).toContain(SERVICE_PATHS[k]);
    }
  });

  it('the installer writes the host token where the hook reads it', () => {
    expect(SERVICE_PATHS.hostToken).toBe(join(SERVICE_PATHS.hookDir, 'host-token'));
    expect(installShExpanded).toContain(`>${SERVICE_PATHS.hostToken}`);
  });

  it('each service runs through keyflap-launch and reads the config file the installer writes for it', () => {
    const chmodLine = installSh
      .split('\n')
      .find((l) => l.startsWith('chmod 0644 /Library/Keyflap/etc/'));
    for (const [name, key] of [
      ['core', 'coreConfig'],
      ['signer', 'signerConfig'],
      ['approver', 'approverConfig'],
    ] as const) {
      const args = programArguments(plist(name));
      expect(args[0], name).toBe(`${SERVICE_PATHS.prefix}/libexec/keyflap-launch`);
      expect(args.slice(-2), name).toEqual(['--config', SERVICE_PATHS[key]]);
      expect(args[args.indexOf('--') + 1], name).toBe(`${SERVICE_PATHS.prefix}/node/bin/node`);
      expect(chmodLine, key).toContain(SERVICE_PATHS[key]);
    }
  });

  it('the socket names keyflap-launch hands over are the Sockets keys, which are the names the entry points read', () => {
    const expected = {
      signer: ['signer', 'signer-admin'],
      core: ['intent', 'admin', 'approver-api'],
      approver: ['approver', 'approver6'],
    };
    for (const name of SERVICE_NAMES) {
      const args = programArguments(plist(name));
      const handed = args
        .slice(0, args.indexOf('--'))
        .filter((_, i, a) => i > 0 && a[i - 1] === '--socket');
      expect(handed, name).toEqual(expected[name]);
      expect(socketNames(plist(name)), name).toEqual(expected[name]);
    }
  });

  it('every socket entry sets a mode (launchd defaults to 0666) and the TCP ones an IP literal and family', () => {
    for (const name of SERVICE_NAMES) {
      const xml = plist(name);
      const entries = xml.split(/<key>Sock(?:PathName|NodeName)<\/key>/).slice(1);
      for (const e of entries) {
        if (/SockPathMode|SockFamily/.test(e)) continue;
        throw new Error(
          `${name}: a Sockets entry without SockPathMode or SockFamily: ${e.slice(0, 80)}`,
        );
      }
    }
    expect(strings(plist('approver'), 'SockNodeName')).toEqual(['@LISTEN_HOST@', '::1']);
    expect(strings(plist('approver'), 'SockFamily')).toEqual(['@LISTEN_FAMILY@', 'IPv6']);
  });

  it('each plist runs as its service user with no GroupName, logs under its own dir, and keeps the Linux limits', () => {
    for (const name of SERVICE_NAMES) {
      const xml = plist(name);
      expect(strings(xml, 'Label'), name).toEqual([LAUNCHD_MANAGER.unit(name)]);
      expect(strings(xml, 'UserName'), name).toEqual([
        LAUNCHD_MANAGER.user(name === 'approver' ? 'web' : name),
      ]);
      expect(xml, name).not.toContain('GroupName');
      expect(strings(xml, 'StandardErrorPath'), name).toEqual([darwinLogFile(name)]);
      expect(strings(xml, 'CREDENTIALS_DIRECTORY'), name).toEqual([
        `/Library/Keyflap/credentials/${name}`,
      ]);
      expect(xml, name).toMatch(/<key>Umask<\/key><integer>63<\/integer>/);
      expect(xml, name).toMatch(/<key>ExitTimeOut<\/key><integer>30<\/integer>/);
      expect(xml, name).toMatch(/<key>SuccessfulExit<\/key><false\/>/);
      expect(xml.match(/<key>Core<\/key><integer>0<\/integer>/g), name).toHaveLength(2);
      expect(createdDirs, name).toContain(dirname(darwinLogFile(name)));
      expect(createdDirs, name).toContain(`/Library/Keyflap/credentials/${name}`);
    }
    expect(strings(plist('core'), 'HOME')).toEqual([SERVICE_PATHS.coreData]);
    expect(strings(plist('signer'), 'HOME')).toEqual([SERVICE_PATHS.signerData]);
    expect(strings(plist('core'), 'PLAYWRIGHT_BROWSERS_PATH')).toEqual([
      `${SERVICE_PATHS.prefix}/browsers`,
    ]);
  });

  it('the wrapper is installed where the CLI says, by full path, and runs code under the prefix with a clean environment', () => {
    expect(installSh).toContain(`"$here/keyflap-wrapper.sh" ${SERVICE_PATHS.wrapper}`);
    expect(wrapper).toMatch(/^exec \/usr\/bin\/env -i \\$/m);
    expect(wrapper).toContain('KEYFLAP_MODE=service');
    expect(wrapper).toMatch(
      new RegExp(
        `^  ${SERVICE_PATHS.prefix}/node/bin/node .* ${SERVICE_PATHS.prefix}/app/packages/cli/src/main\\.ts "\\$@"$`,
        'm',
      ),
    );
    expect(wrapper.replace(/^#.*$/gm, '')).not.toMatch(/\bHOME\b/);
    expect(installSh).toContain('sudo keyflap setup');
  });
});
