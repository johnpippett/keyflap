import { describe, expect, it } from 'vitest';
import { env, host, pids, skipReason, whereOn } from './helpers.ts';
import { L } from './platform.ts';

const r = env.release;
const d = env.darwin;

describe.skipIf(skipReason !== null || L.os !== 'linux')(
  `service-mode release install (${whereOn('linux')})`,
  () => {
    it('the release tarball checks out against SHA256SUMS and installs without --bundle', () => {
      expect(r?.sums).toContain(`${r?.name}.tar.xz: OK`);
      expect(r?.installedVersion).toBe('0.0.0-isolation');
      expect(r?.install).toMatch(/installing 0\.0\.0-isolation/);
      expect(r?.install).toMatch(/headed on a private Xvfb display/);
      expect(r?.install).toContain('sudo keyflap setup');
      expect(r?.install).toContain('sudo keyflap approver pair');
    });

    it('the release holds the installer, units, bundle and pinned Node, all root-owned', () => {
      const c = host();
      const dir = `/root/release/${r?.name}`;
      const listing = c.exec(['find', dir, '-maxdepth', '1', '-printf', '%f %u:%g %m\n'], {
        check: true,
      }).stdout;
      for (const f of [
        'install.sh root:root 755',
        'uninstall.sh root:root 755',
        'runtime-pins.sh root:root 644',
        'progress.sh root:root 644',
        'units root:root 755',
        'bundle root:root 755',
        'RELEASE root:root 644',
      ]) {
        expect(listing).toContain(f);
      }
      expect(listing).toMatch(/node-v22\.\d+\.\d+-linux-(x64|arm64)\.tar\.xz root:root 644/);
      expect(c.exec(['find', dir, '!', '-user', 'root'], { check: true }).stdout).toBe('');
    });

    it('Xvfb is the default: missing Xvfb fails the preflight clearly and changes nothing', () => {
      expect(r?.noXvfb.status).toBe(1);
      const err = r?.noXvfb.stderr ?? '';
      expect(err).toContain("this machine isn't ready; nothing was changed");
      expect(err).toContain('Xvfb not found');
      expect(err).toContain('sudo apt install xvfb');
      expect(err).toContain('sudo dnf install xorg-x11-server-Xvfb');
      expect(err).toContain('sudo pacman -S xorg-server-xvfb');
      expect(err).toContain('--headless');
      expect(r?.noXvfb.untouched).toBe(true);
    });

    it('M4: install.sh run from a copy in the user home is refused and changes nothing', () => {
      expect(r?.fromHome.status).toBe(1);
      const err = r?.fromHome.stderr ?? '';
      expect(err).toContain(`refusing to run from /home/${L.agentUser}/rel`);
      expect(err).toContain('owned by uid 1500');
      expect(err).toContain('/opt/keyflap-release');
      expect(r?.fromHome.untouched).toBe(true);
    });

    it('the managed browser runs headed on Xvfb without --xvfb', () => {
      const c = host();
      const core = JSON.parse(
        c.exec(['cat', '/etc/keyflap/core.json'], { check: true }).stdout,
      ) as {
        browser: { mode: string; xvfbBin?: string };
      };
      expect(core.browser.mode).toBe('xvfb');
      expect(core.browser.xvfbBin).toBe('/usr/bin/Xvfb');
      const p = pids();
      expect(p.xvfb).toBeGreaterThan(0);
      const cmdline = c.exec(['cat', `/proc/${p.chromium}/cmdline`], { check: true }).stdout;
      expect(cmdline).toContain('chromium-1248/chrome-linux64/chrome');
      expect(cmdline).not.toContain('--headless');
    });

    it('an upgrade re-run keeps keys, phone and agents, and restarts the services', () => {
      const u = r?.upgrade;
      expect(u?.stdout).toMatch(/upgrading 0\.0\.0-isolation -> [0-9a-f]{12}/);
      expect(u?.stdout).toContain('Upgraded to');
      expect(u?.after.kek).toBe(u?.before.kek);
      expect(u?.after.channelKey).toBe(u?.before.channelKey);
      expect(u?.after.corePid).not.toBe(u?.before.corePid);
      expect(u?.after.signerPid).not.toBe(u?.before.signerPid);
      expect(u?.agents).toContain(env.agentId);
      expect(u?.approvers).toContain('http://approver.localhost:8766');
      expect(u?.agentToken).toEqual({ kept: true, mode: '600', owner: L.agentUser });
      expect(u?.plantedGone).toBe(true);
      expect(host().exec(['test', '-e', '/opt/keyflap/app/VERSION']).status).not.toBe(0);
    });
  },
);

describe.skipIf(skipReason !== null || L.os !== 'darwin')(
  `service-mode release install (${whereOn('darwin')})`,
  () => {
    it('the release tarball checks out against SHA256SUMS and installs without --bundle', () => {
      expect(d?.sums).toContain(`${d?.name}.tar.xz: OK`);
      expect(d?.installedVersion).toBe('0.0.0-isolation');
      expect(d?.install).toMatch(/installing 0\.0\.0-isolation/);
      expect(d?.install).toContain('headless (full Chromium, its own sandbox on)');
      expect(d?.install).toContain('sudo keyflap setup');
      expect(d?.install).toContain('sudo keyflap approver pair');
    });

    it('the release holds the installer, plists, launcher, bundle and pinned Node, all root-owned', () => {
      const h = host();
      const listing = h.exec(['sh', '-c', `cd ${d?.dir} && stat -f '%N %Su:%Sg %Lp' * | sort`], {
        check: true,
      }).stdout;
      for (const f of [
        'install.sh root:wheel 755',
        'uninstall.sh root:wheel 755',
        'keyflap-launch root:wheel 755',
        'runtime-pins.sh root:wheel 644',
        'progress.sh root:wheel 644',
        'launchd root:wheel 755',
        'bundle root:wheel 755',
        'RELEASE root:wheel 644',
      ]) {
        expect(listing).toContain(f);
      }
      expect(listing).toMatch(/node-v22\.\d+\.\d+-darwin-arm64\.tar\.xz root:wheel 644/);
      expect(h.exec(['find', d?.dir as string, '!', '-user', 'root'], { check: true }).stdout).toBe(
        '',
      );
      expect(h.exec(['cat', `${d?.dir}/RELEASE`]).stdout).toContain('os=darwin');
    });

    it('a Linux-only option fails the preflight clearly and changes nothing', () => {
      expect(d?.linuxOnly.status).toBe(1);
      expect(d?.linuxOnly.stderr).toContain('--xvfb is Linux-only');
      expect(d?.linuxOnly.untouched).toBe(true);
    });

    it('M4: install.sh run from a copy in the user home is refused and changes nothing', () => {
      expect(d?.fromHome.status).toBe(1);
      const err = d?.fromHome.stderr ?? '';
      expect(err).toContain(`refusing to run from ${d?.fromHome.dir}`);
      expect(err).toContain(`owned by uid ${env.probeUid}`);
      expect(err).toContain('/opt/keyflap-release');
      expect(d?.fromHome.untouched).toBe(true);
    });

    it('the managed browser is the full Chromium, headless, with its own sandbox', () => {
      const core = JSON.parse(host().exec(['cat', L.coreConfig], { check: true }).stdout) as {
        browser: { mode: string; channel?: string };
      };
      expect(core.browser).toMatchObject({ mode: 'headless', channel: 'chromium' });
      const p = pids();
      expect(p.chromium).toBeGreaterThan(0);
    });

    it('an upgrade re-run keeps keys, phone and agents, and restarts the services', () => {
      const u = d?.upgrade;
      expect(u?.stdout).toMatch(/upgrading 0\.0\.0-isolation -> [0-9a-f]{12}/);
      expect(u?.stdout).toContain('Upgraded to');
      expect(u?.after.kek).toBe(u?.before.kek);
      expect(u?.after.channelKey).toBe(u?.before.channelKey);
      expect(u?.after.corePid).not.toBe(u?.before.corePid);
      expect(u?.after.signerPid).not.toBe(u?.before.signerPid);
      expect(u?.agents).toContain(env.agentId);
      expect(u?.approvers).toContain('http://approver.localhost:8766');
      expect(u?.agentToken).toEqual({ kept: true, mode: '600', owner: L.agentUser });
      expect(u?.plantedGone).toBe(true);
      expect(u?.versionGone).toBe(true);
    });

    it('uninstall keeps the key store and KEK; a reinstall picks up the same keys, phone and agent', () => {
      const x = d?.reinstall;
      expect(x?.uninstallStatus).toBe(0);
      expect(x?.uninstall).toContain('Kept: /Library/Keyflap/data');
      expect(x?.gone).toBe('');
      expect(x?.kept).toBe('');
      expect(x?.reinstall).toContain('installing 0.0.0-isolation');
      expect(x?.kekKept).toBe(true);
      expect(x?.agents).toContain(env.agentId);
      expect(x?.approvers).toContain('http://approver.localhost:8766');
      expect(x?.tokenKept).toBe(true);
    });
  },
);
