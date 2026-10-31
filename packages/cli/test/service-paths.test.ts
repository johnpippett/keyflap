import { dirname, join } from 'node:path';
import { SERVICE_PLATFORMS, unixSocketPathProblem } from '@aab/signer/platform';
import { describe, expect, it } from 'vitest';
import {
  DARWIN_SERVICE_PATHS,
  LINUX_SERVICE_PATHS,
  SERVICE_PATHS,
  SERVICE_PATHS_BY_PLATFORM,
  type ServicePaths,
  servicePaths,
} from '../src/service/paths.ts';

const SOCKETS = [
  'intentSocket',
  'adminSocket',
  'signerSocket',
  'signerAdminSocket',
  'approverApiSocket',
] as const satisfies readonly (keyof ServicePaths)[];

describe('SERVICE_PATHS follows the platform', () => {
  it('has a table for exactly the platforms service mode runs on', () => {
    expect(Object.keys(SERVICE_PATHS_BY_PLATFORM).toSorted()).toEqual(
      Object.keys(SERVICE_PLATFORMS).toSorted(),
    );
  });

  it('picks the table by platform, Linux for anything the gates refuse anyway', () => {
    expect(servicePaths('linux')).toBe(LINUX_SERVICE_PATHS);
    expect(servicePaths('darwin')).toBe(DARWIN_SERVICE_PATHS);
    expect(servicePaths('freebsd')).toBe(LINUX_SERVICE_PATHS);
    expect(servicePaths('constructor')).toBe(LINUX_SERVICE_PATHS);
    expect(SERVICE_PATHS).toBe(servicePaths(process.platform));
  });

  it('every table has the same keys', () => {
    expect(Object.keys(DARWIN_SERVICE_PATHS).toSorted()).toEqual(
      Object.keys(LINUX_SERVICE_PATHS).toSorted(),
    );
  });
});

describe('the macOS table is the layout in docs/MAC_PLAN.md ("Shape on macOS")', () => {
  it('names the planned paths', () => {
    expect(DARWIN_SERVICE_PATHS).toEqual({
      prefix: '/opt/keyflap',
      coreConfig: '/Library/Keyflap/etc/core.json',
      signerConfig: '/Library/Keyflap/etc/signer.json',
      approverConfig: '/Library/Keyflap/etc/approver.json',
      coreData: '/Library/Keyflap/data/core',
      signerData: '/Library/Keyflap/data/signer',
      hookDir: '/Library/Keyflap/hook',
      hostToken: '/Library/Keyflap/hook/host-token',
      intentSocket: '/Library/Keyflap/run/core/intent.sock',
      adminSocket: '/Library/Keyflap/run/core/admin.sock',
      signerSocket: '/Library/Keyflap/run/signer/signer.sock',
      signerAdminSocket: '/Library/Keyflap/run/signer/admin.sock',
      approverApiSocket: '/Library/Keyflap/run/approver/api.sock',
      wrapper: '/usr/local/bin/keyflap',
      opToken: '/Library/Keyflap/credentials/signer/op-service-account-token',
    });
  });

  it('avoids the /etc, /var and /tmp symlinks (the realpath rule in sources/src/tool.ts) and spaces', () => {
    for (const [key, path] of Object.entries(DARWIN_SERVICE_PATHS)) {
      expect(path, key).not.toMatch(/^\/(etc|var|tmp)(\/|$)/);
      expect(path, key).not.toMatch(/\s/);
      expect(path, key).toMatch(/^\//);
    }
  });

  it('keeps every socket path under the 103-byte macOS limit', () => {
    for (const k of SOCKETS) {
      expect(unixSocketPathProblem(DARWIN_SERVICE_PATHS[k], k, 'darwin')).toBeNull();
    }
  });

  it('keeps the host token inside the hook dir, where the hook reads it', () => {
    expect(DARWIN_SERVICE_PATHS.hostToken).toBe(join(DARWIN_SERVICE_PATHS.hookDir, 'host-token'));
  });

  it('gives each service its own socket directory, as the launchd Sockets will', () => {
    expect(dirname(DARWIN_SERVICE_PATHS.intentSocket)).toBe(
      dirname(DARWIN_SERVICE_PATHS.adminSocket),
    );
    expect(dirname(DARWIN_SERVICE_PATHS.signerSocket)).toBe(
      dirname(DARWIN_SERVICE_PATHS.signerAdminSocket),
    );
    expect(
      new Set([
        dirname(DARWIN_SERVICE_PATHS.intentSocket),
        dirname(DARWIN_SERVICE_PATHS.signerSocket),
        dirname(DARWIN_SERVICE_PATHS.approverApiSocket),
      ]).size,
    ).toBe(3);
  });
});
