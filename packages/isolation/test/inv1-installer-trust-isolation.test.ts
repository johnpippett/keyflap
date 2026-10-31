import { afterAll, describe, expect, it } from 'vitest';
import { env, host, skipReason, where } from './helpers.ts';
import { L, servicePids } from './platform.ts';

const AGENT_USER = L.agentUser;
const NODE = L.node;
const PROBE_DIR = L.probeDir;
const darwin = L.os === 'darwin';
const HOME = darwin ? '/Users/Shared/keyflap-isolation-probe' : `/home/${AGENT_USER}`;
const PP = `${HOME}/.local/bin/pass-cli`;
const TRUE = darwin ? '/usr/bin/true' : '/bin/true';
const container = host;

function installer(extra: string[]): string[] {
  const common = [
    '--user',
    AGENT_USER,
    '--approver-origin',
    'http://approver.localhost:8766',
    '--high-risk',
    'rp.localhost',
    ...extra,
  ];
  if (!darwin) {
    return [
      'bash',
      '/root/installer/install.sh',
      '--bundle',
      '/root/bundle',
      '--node-dir',
      '/root/node',
      ...common,
    ];
  }
  const rel = env.darwin?.dir as string;
  const tarball = host()
    .exec(['sh', '-c', `ls ${rel} | grep '^node-v22.*-darwin-arm64.tar.xz$'`], { check: true })
    .stdout.trim();
  return [
    'bash',
    `${env.stage}/install/macos/install.sh`,
    '--bundle',
    `${env.stage}/bundle`,
    '--launcher',
    `${rel}/keyflap-launch`,
    '--node-tarball',
    `${rel}/${tarball}`,
    ...common,
  ];
}

function configSnapshot(): string {
  const h = host();
  const sums = h.exec(
    ['sh', '-c', darwin ? `shasum -a 256 ${L.configDir}/*.json` : 'sha256sum /etc/keyflap/*.json'],
    { check: true },
  ).stdout;
  return `${sums}${JSON.stringify(servicePids(h))}`;
}

describe.skipIf(skipReason !== null)(
  `invariant 1: root-run setup and password tools (${where})`,
  () => {
    afterAll(() => {
      const c = container();
      c.exec([
        'rm',
        '-rf',
        `${L.hookDir}/setup.json`,
        `${HOME}/.claude`,
        `${HOME}/.claude.json`,
        `${HOME}/linked-dir`,
        `${HOME}/proj`,
        `${HOME}/.local`,
        '/opt/keyflap/tools/pass-cli',
        '/usr/local/bin/pass-cli',
      ]);
    });

    it('H2: setup as root refuses links the user planted and leaks nothing', () => {
      const c = container();
      const plant = (cmd: string) => {
        const r = c.as(AGENT_USER, ['sh', '-c', cmd]);
        expect(r.status, r.stderr).toBe(0);
      };
      plant(`mkdir -p ${HOME}/.claude && ln -s ${L.keyStore} ${HOME}/.claude/settings.json`);
      plant(`ln -s ${L.coreConfig} ${HOME}/.claude.json`);
      plant(`ln -s ${L.configDir} ${HOME}/linked-dir`);
      plant(`ln -s ${L.signerConfig} ${L.hookDir}/setup.json`);
      const ids = c
        .exec(['sh', '-c', `id -u ${AGENT_USER}; id -g ${AGENT_USER}`], { check: true })
        .stdout.trim()
        .split('\n')
        .map(Number);
      const r = c.exec(
        [
          NODE,
          `${PROBE_DIR}/setup-files.ts`,
          JSON.stringify({
            home: HOME,
            uid: ids[0],
            gid: ids[1],
            signerConfig: L.signerConfig,
            coreConfig: L.coreConfig,
            keyStore: L.keyStore,
            hookDir: L.hookDir,
          }),
        ],
        { timeoutMs: 60_000 },
      );
      expect(r.status, r.stderr).toBe(0);
      const o = JSON.parse(r.stdout);
      expect(o.readLinkToKeyStore).toBe('UnsafePathError');
      expect(o.readKeyStoreDirect).toMatch(/^(EACCES|UnsafePathError)$/);
      expect(o.readRootFile).toMatch(/^(EACCES|UnsafePathError)$/);
      expect(o.writeLinkToCoreCfg.ok).toBe(false);
      expect(o.writeLinkToCoreCfg.out).toContain('not written');
      expect(o.writeThroughLinkedDir.ok).toBe(false);
      expect(o.saveStateLinked).toBe('UnsafePathError');
      expect(o.unchanged).toEqual({ signer: true, core: true });
      expect(
        c.exec(['test', '-e', `${L.configDir}/settings.json`]).status,
        'nothing written into the linked root dir',
      ).toBe(1);
      expect(o.writeNormal.ok, o.writeNormal.out).toBe(true);
      expect(o.rewriteNormal.ok, o.rewriteNormal.out).toBe(true);
      expect([o.normalOwner, o.normalDirOwner, o.backupOwner]).toEqual([ids[0], ids[0], ids[0]]);
      expect(o.idsRestored).toBe(true);
      expect(o.euid).toBe(0);
    });

    it('H3: the signer check refuses a pass-cli the user could change, accepts a root-only one', () => {
      const c = container();
      c.as(AGENT_USER, ['sh', '-c', `mkdir -p ${HOME}/.local/bin && cp ${TRUE} ${PP}`]);
      c.exec(['install', '-d', '-m', '0755', '/opt/keyflap/tools/pass-cli'], { check: true });
      c.exec(['install', '-m', '0755', TRUE, '/opt/keyflap/tools/pass-cli/pass-cli'], {
        check: true,
      });
      c.exec(['ln', '-sf', PP, '/usr/local/bin/pass-cli'], { check: true });
      const check = () => {
        const r = c.exec(
          [
            NODE,
            `${PROBE_DIR}/tool-check.ts`,
            JSON.stringify([PP, '/usr/local/bin/pass-cli', '/opt/keyflap/tools/pass-cli/pass-cli']),
          ],
          { timeoutMs: 60_000 },
        );
        expect(r.status, r.stderr).toBe(0);
        return JSON.parse(r.stdout) as Record<string, string>;
      };
      const r = check();
      expect(r[PP]).toMatch(/^untrusted: .*not in a system bin directory/);
      expect(r['/usr/local/bin/pass-cli']).toMatch(/^untrusted: .*link/);
      expect(r['/opt/keyflap/tools/pass-cli/pass-cli']).toBe('ok');
      c.exec(['chmod', 'g+w', '/opt/keyflap/tools/pass-cli'], { check: true });
      expect(check()['/opt/keyflap/tools/pass-cli/pass-cli']).toMatch(/^untrusted: /);
      c.exec(['chmod', 'g-w', '/opt/keyflap/tools/pass-cli'], { check: true });
      c.exec(['chown', AGENT_USER, '/opt/keyflap/tools/pass-cli/pass-cli'], { check: true });
      expect(check()['/opt/keyflap/tools/pass-cli/pass-cli']).toMatch(/^untrusted: /);
      c.exec(['chown', 'root', '/opt/keyflap/tools/pass-cli/pass-cli'], { check: true });
    });

    it('H3: install.sh refuses an unsafe pass-cli before changing anything', () => {
      const c = container();
      c.as(AGENT_USER, ['sh', '-c', `mkdir -p ${HOME}/.local/bin && cp ${TRUE} ${PP}`]);
      const snapshot = configSnapshot;
      const run = (extra: string[]) =>
        c.exec(installer(['--password-source', 'proton-pass', ...extra]), { timeoutMs: 120_000 });
      const before = snapshot();

      c.exec(['rm', '-rf', '/opt/keyflap/tools/pass-cli', '/usr/local/bin/pass-cli']);
      const notFound = run([]);
      expect(notFound.status).toBe(1);
      expect(notFound.stderr).toContain('nothing was changed');
      expect(notFound.stderr).toContain('pass-cli not found');
      expect(notFound.stderr).toContain('/opt/keyflap/tools/pass-cli');

      const inHome = run(['--proton-pass-bin', PP]);
      expect(inHome.status).toBe(1);
      expect(inHome.stderr).toContain('the signer would refuse pass-cli');
      expect(inHome.stderr).toContain('not in a system bin directory');

      c.exec(['ln', '-s', PP, '/usr/local/bin/pass-cli'], { check: true });
      const linked = run([]);
      expect(linked.status).toBe(1);
      expect(linked.stderr).toContain('symbolic link');
      c.exec(['rm', '-f', '/usr/local/bin/pass-cli'], { check: true });

      c.exec(['install', '-d', '-m', '0775', '/opt/keyflap/tools/pass-cli'], { check: true });
      c.exec(['install', '-m', '0755', TRUE, '/opt/keyflap/tools/pass-cli/pass-cli'], {
        check: true,
      });
      const groupWritable = run([]);
      expect(groupWritable.status).toBe(1);
      expect(groupWritable.stderr).toContain('writable by group or others');

      expect(snapshot()).toBe(before);
      expect(c.exec(['test', '-e', '/opt/keyflap/bin']).status, 'no legacy copy dir').toBe(1);
    });

    if (darwin) {
      it('the LaunchDaemons drop core dumps; the tools dir is root-only', () => {
        const c = container();
        for (const l of ['signer', 'core', 'approver']) {
          for (const limit of ['HardResourceLimits', 'SoftResourceLimits']) {
            const plist = `/Library/LaunchDaemons/com.keyflap.${l}.plist`;
            const r = c.exec(['plutil', '-extract', `${limit}.Core`, 'raw', plist], {
              check: true,
            });
            expect(r.stdout.trim(), `${l} ${limit}`).toBe('0');
          }
        }
        expect(
          c.exec(['stat', '-f', '%Su %Lp', '/opt/keyflap/tools'], { check: true }).stdout.trim(),
        ).toBe('root 755');
      });
      return;
    }

    it('the units drop core dumps; the signer has no network without a password tool', () => {
      const c = container();
      const show = (unit: string, prop: string) =>
        c.exec(['systemctl', 'show', '-p', prop, '--value', unit], { check: true }).stdout.trim();
      for (const u of ['keyflap-signer', 'keyflap-core', 'keyflap-approver']) {
        expect(show(u, 'LimitCORE'), u).toBe('0');
      }
      expect(show('keyflap-signer', 'RestrictAddressFamilies')).toBe('AF_UNIX');
      expect(
        c.exec(['stat', '-c', '%U %a', '/opt/keyflap/tools'], { check: true }).stdout.trim(),
      ).toBe('root 755');
    });

    it('password-source add opens the signer network and remove closes it again', () => {
      const c = container();
      const family = () =>
        c
          .exec(
            ['systemctl', 'show', '-p', 'RestrictAddressFamilies', '--value', 'keyflap-signer'],
            {
              check: true,
            },
          )
          .stdout.trim();
      const keyflap = (...args: string[]) =>
        c.exec(['/usr/local/bin/keyflap', 'password-source', ...args], { timeoutMs: 120_000 });
      c.exec(['rm', '-rf', '/opt/keyflap/tools/pass-cli'], { check: true });
      c.exec(['install', '-d', '-m', '0755', '/opt/keyflap/tools/pass-cli'], { check: true });
      c.exec(
        [
          'sh',
          '-c',
          'cat > /opt/keyflap/tools/pass-cli/pass-cli && chmod 0755 /opt/keyflap/tools/pass-cli/pass-cli',
        ],
        { check: true, input: '#!/bin/sh\necho \'{"vaults":[{"name":"Agent"}]}\'\n' },
      );
      expect(family()).toBe('AF_UNIX');
      try {
        const added = keyflap('add', 'proton-pass', '--vault', 'Agent', '--yes');
        expect(added.status, added.stderr).toBe(0);
        expect(family()).not.toBe('AF_UNIX');
        const signer = JSON.parse(c.exec(['cat', L.signerConfig], { check: true }).stdout) as {
          sources: { protonPass?: { bin: string; sha256: string } };
        };
        expect(signer.sources.protonPass?.bin).toBe('/opt/keyflap/tools/pass-cli/pass-cli');
        expect(signer.sources.protonPass?.sha256).toMatch(/^[0-9a-f]{64}$/);
      } finally {
        const removed = keyflap('remove');
        expect(removed.status, removed.stderr).toBe(0);
      }
      expect(family()).toBe('AF_UNIX');
      const refused = keyflap('add', 'proton-pass', '--bin', PP, '--yes');
      expect(refused.status).not.toBe(0);
      expect(family()).toBe('AF_UNIX');
    });
  },
);
