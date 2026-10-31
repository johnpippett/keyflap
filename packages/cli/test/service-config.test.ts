import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildServiceConfigs,
  ConfigError,
  onePasswordServiceEnv,
  parseApproverFrontConfig,
  parseCoreConfig,
  protonPassServiceEnv,
} from '../src/service/config.ts';
import { installConfig } from '../src/service/install-config.ts';
import { DARWIN_SERVICE_PATHS, isServiceMode, SERVICE_PATHS } from '../src/service/paths.ts';
import { xauthorityEntry } from '../src/service/xvfb.ts';
import { MACOS_APP_CLI } from '../src/setup/tailscale.ts';
import { tmpDir } from './helpers.ts';

const base = { approverOrigin: 'https://box.tail1.ts.net', tls: false, highRisk: [] };

describe('service config', () => {
  it('builds the core, signer and approver front configs from installer options', () => {
    const { core, signer, approver } = buildServiceConfigs({
      ...base,
      highRisk: ['Bank.Example'],
    });
    expect(core).toEqual({
      dataDir: '/var/lib/keyflap/core',
      signerSocket: '/run/keyflap-signer/signer.sock',
      intentSocket: '/run/keyflap/intent.sock',
      adminSocket: '/run/keyflap/admin.sock',
      mcp: { host: '127.0.0.1', port: 8765 },
      approver: {
        origin: 'https://box.tail1.ts.net',
        listen: { host: '127.0.0.1', port: 8766 },
        tls: false,
        front: { socket: '/run/keyflap-approver/api.sock' },
      },
      highRisk: ['bank.example'],
      passwordSource: null,
      browser: { mode: 'headless', persist: true },
    });
    expect(signer).toEqual({
      approverAddress: { origin: 'https://box.tail1.ts.net', target: 'http://127.0.0.1:8766' },
      storePath: '/var/lib/keyflap/signer/keys.enc.json',
      highRiskDomains: ['bank.example'],
    });
    expect(parseCoreConfig(JSON.stringify(core))).toEqual(core);
    expect(approver).toEqual({
      origin: 'https://box.tail1.ts.net',
      listen: { host: '127.0.0.1', port: 8766 },
      tls: false,
      upstream: '/run/keyflap-approver/api.sock',
    });
    expect(parseApproverFrontConfig(JSON.stringify(approver))).toEqual(approver);
  });

  it('TLS belongs to the approver front: the core never gets it next to the front', () => {
    const { core, approver } = buildServiceConfigs({ ...base, tls: true });
    expect(approver.tls).toBe(true);
    expect(core.approver.tls).toBe(false);
    const both = { ...core, approver: { ...core.approver, tls: true } };
    expect(() => parseCoreConfig(JSON.stringify(both))).toThrow(/front/);
    expect(() =>
      parseApproverFrontConfig(JSON.stringify({ ...approver, upstream: 'relative.sock' })),
    ).toThrow(ConfigError);
    expect(() => parseApproverFrontConfig(JSON.stringify({ ...approver, extra: 1 }))).toThrow(
      ConfigError,
    );
  });

  it('Proton Pass runs inside the signer with its own session and the file key provider', () => {
    const { core, signer } = buildServiceConfigs({
      ...base,
      protonPassBin: '/opt/keyflap/bin/pass-cli',
      protonPassVault: 'Agent',
    });
    expect(core.passwordSource).toEqual({ kind: 'proton-pass' });
    expect(signer.sources).toEqual({
      protonPass: {
        bin: '/opt/keyflap/bin/pass-cli',
        vault: 'Agent',
        env: {
          HOME: '/var/lib/keyflap/signer',
          PROTON_PASS_SESSION_DIR: '/var/lib/keyflap/signer/proton-pass',
          PROTON_PASS_KEY_PROVIDER: 'fs',
        },
      },
    });
    expect(protonPassServiceEnv()).not.toHaveProperty('PROTON_PASS_PERSONAL_ACCESS_TOKEN');
    expect(() => buildServiceConfigs({ ...base, protonPassVault: 'Agent' })).toThrow(ConfigError);
  });

  it('1Password runs inside the signer; the token is never in a config file', () => {
    const { core, signer } = buildServiceConfigs({
      ...base,
      onePasswordBin: '/opt/keyflap/bin/op',
      onePasswordVault: 'Agent',
    });
    expect(core.passwordSource).toEqual({ kind: '1password' });
    expect(parseCoreConfig(JSON.stringify(core)).passwordSource).toEqual({ kind: '1password' });
    expect(signer.sources).toEqual({
      onePassword: {
        bin: '/opt/keyflap/bin/op',
        vault: 'Agent',
        env: { HOME: '/var/lib/keyflap/signer' },
      },
    });
    expect(JSON.stringify(signer)).not.toContain('OP_SERVICE_ACCOUNT_TOKEN');
    expect(onePasswordServiceEnv()).toEqual({ HOME: '/var/lib/keyflap/signer' });
    expect(() => buildServiceConfigs({ ...base, onePasswordVault: 'Agent' })).toThrow(ConfigError);
    expect(() => buildServiceConfigs({ ...base, onePasswordBin: 'op' })).toThrow(ConfigError);
    expect(() =>
      buildServiceConfigs({
        ...base,
        onePasswordBin: '/opt/keyflap/bin/op',
        protonPassBin: '/opt/keyflap/bin/pass-cli',
      }),
    ).toThrow(/one password source/);
  });

  it('headed on a private Xvfb display when asked', () => {
    const { core } = buildServiceConfigs({ ...base, xvfbBin: '/usr/bin/Xvfb' });
    expect(core.browser).toEqual({
      mode: 'xvfb',
      xvfbBin: '/usr/bin/Xvfb',
      display: 99,
      persist: true,
    });
    expect(parseCoreConfig(JSON.stringify(core)).browser).toEqual(core.browser);
    expect(() => buildServiceConfigs({ ...base, xvfbBin: 'Xvfb' })).toThrow(/absolute/);
  });

  it('on macOS the service browser is the full Chromium in new headless mode; Xvfb is refused', () => {
    const { core } = buildServiceConfigs(base, DARWIN_SERVICE_PATHS, 'darwin');
    expect(core.browser).toEqual({ mode: 'headless', channel: 'chromium', persist: true });
    expect(core.dataDir).toBe('/Library/Keyflap/data/core');
    expect(core.signerSocket).toBe('/Library/Keyflap/run/signer/signer.sock');
    expect(parseCoreConfig(JSON.stringify(core), 'darwin')).toEqual(core);
    expect(parseCoreConfig(JSON.stringify(core), 'linux').browser).toEqual(core.browser);
    expect(() =>
      buildServiceConfigs(
        { ...base, xvfbBin: '/opt/X11/bin/Xvfb' },
        DARWIN_SERVICE_PATHS,
        'darwin',
      ),
    ).toThrow(/--xvfb is Linux-only/);
    const linuxXvfb = buildServiceConfigs({ ...base, xvfbBin: '/usr/bin/Xvfb' }).core;
    expect(() => parseCoreConfig(JSON.stringify(linuxXvfb), 'darwin')).toThrow(
      /browser\.mode xvfb is Linux-only/,
    );
    expect(parseCoreConfig(JSON.stringify(linuxXvfb), 'linux').browser).toEqual(linuxXvfb.browser);
    expect(() =>
      parseCoreConfig(
        JSON.stringify({ ...core, browser: { mode: 'headless', channel: 'chrome' } }),
        'darwin',
      ),
    ).toThrow(/browser\.channel must be chromium/);
    expect(buildServiceConfigs(base).core.browser).toEqual({ mode: 'headless', persist: true });
  });

  it('browser.persist: on by default, off with --ephemeral-browser, and checked', () => {
    const { core } = buildServiceConfigs({ ...base, ephemeralBrowser: true });
    expect(core.browser).toEqual({ mode: 'headless', persist: false });
    expect(parseCoreConfig(JSON.stringify(core)).browser.persist).toBe(false);
    const legacy = { ...core, browser: { mode: 'headless' } };
    expect(parseCoreConfig(JSON.stringify(legacy)).browser.persist).toBe(true);
    const { browser: _omit, ...noBrowser } = core;
    expect(parseCoreConfig(JSON.stringify(noBrowser)).browser).toEqual({
      mode: 'headless',
      persist: true,
    });
    expect(() =>
      parseCoreConfig(JSON.stringify({ ...core, browser: { mode: 'headless', persist: 'no' } })),
    ).toThrow(/persist must be true or false/);
  });

  it('APNs for the iOS app: ids in the config, the key only as a credential', () => {
    const apns = {
      keyId: 'ABCDE12345',
      teamId: 'TEAM123456',
      bundleId: 'me.example.Keyflap',
      sandbox: true,
      generic: false,
    };
    const { core } = buildServiceConfigs({ ...base, apns });
    expect(core.approver.apns).toEqual(apns);
    expect(parseCoreConfig(JSON.stringify(core)).approver.apns).toEqual(apns);
    expect(JSON.stringify(core)).not.toMatch(/PRIVATE KEY|\.p8/);
    for (const bad of [
      { ...apns, keyId: 'short' },
      { ...apns, teamId: 'lowercase1' },
      { ...apns, bundleId: 'nodots' },
      { ...apns, sandbox: 'yes' },
      { ...apns, keyFile: '/etc/keyflap/AuthKey.p8' },
    ]) {
      expect(() =>
        parseCoreConfig(JSON.stringify({ ...core, approver: { ...core.approver, apns: bad } })),
      ).toThrow(ConfigError);
    }
  });

  it('refuses a core config without a phone approver (D5), unknown keys, or MCP off loopback', () => {
    const { core } = buildServiceConfigs(base);
    const without = { ...core } as Record<string, unknown>;
    delete without.approver;
    expect(() => parseCoreConfig(JSON.stringify(without))).toThrow(/phone approver/);
    expect(() => parseCoreConfig(JSON.stringify({ ...core, trustedApproverKeys: {} }))).toThrow(
      /unknown key "trustedApproverKeys"/,
    );
    expect(() =>
      parseCoreConfig(JSON.stringify({ ...core, mcp: { host: '0.0.0.0', port: 8765 } })),
    ).toThrow(/127\.0\.0\.1/);
    expect(() =>
      parseCoreConfig(
        JSON.stringify({ ...core, approver: { ...core.approver, origin: 'http://example.com' } }),
      ),
    ).toThrow(ConfigError);
    expect(() =>
      parseCoreConfig(JSON.stringify({ ...core, browser: { mode: 'xvfb', xvfbBin: '/x' } })),
    ).toThrow(/display/);
    expect(() => parseCoreConfig('not json')).toThrow(ConfigError);
  });

  it('install-config writes the three files, world-readable and owner-writable only', () => {
    const dir = tmpDir();
    installConfig([
      '--out-dir',
      dir,
      '--approver-origin',
      'https://box.tail1.ts.net',
      '--high-risk',
      'bank.example',
      '--mcp-port',
      '9876',
    ]);
    for (const f of ['core.json', 'signer.json', 'approver.json']) {
      expect(statSync(join(dir, f)).mode & 0o777).toBe(0o644);
    }
    const front = parseApproverFrontConfig(readFileSync(join(dir, 'approver.json'), 'utf8'));
    expect(front.upstream).toBe('/run/keyflap-approver/api.sock');
    const core = parseCoreConfig(readFileSync(join(dir, 'core.json'), 'utf8'));
    expect(core.mcp.port).toBe(9876);
    expect(() => installConfig(['--out-dir', dir])).toThrow(/approver-origin is required/);
  });

  it('install-config refuses a pass-cli the signer would refuse, and pins the one it accepts', () => {
    const dir = tmpDir();
    const userCopy = join(dir, 'pass-cli');
    writeFileSync(userCopy, '#!/bin/sh\n', { mode: 0o755 });
    const args = ['--out-dir', dir, '--approver-origin', 'https://box.tail1.ts.net'];
    expect(() => installConfig([...args, '--proton-pass-bin', userCopy])).toThrow(
      /not in a system bin directory or \/opt\/keyflap\/tools\/pass-cli\/[\s\S]*fix: install pass-cli as root/,
    );
    expect(existsSync(join(dir, 'signer.json'))).toBe(false);
    const sys = '/usr/bin/env';
    const st = statSync(sys);
    if (st.uid !== 0 || (st.mode & 0o022) !== 0) return;
    installConfig([...args, '--proton-pass-bin', sys]);
    const signer = JSON.parse(readFileSync(join(dir, 'signer.json'), 'utf8'));
    expect(signer.sources.protonPass.bin).toBe(sys);
    expect(signer.sources.protonPass.sha256).toBe(
      createHash('sha256').update(readFileSync(sys)).digest('hex'),
    );
  });

  it('the signer watches the approver address for a Tailscale name, or when a tailscale is given', () => {
    const tailnet = buildServiceConfigs({ ...base, approverListen: '127.0.0.1:8766' }).signer;
    expect(tailnet.approverAddress).toEqual({
      origin: 'https://box.tail1.ts.net',
      target: 'http://127.0.0.1:8766',
    });
    const local = { ...base, approverOrigin: 'https://approver.localhost:8766' };
    expect(buildServiceConfigs(local).signer.approverAddress).toBeUndefined();
    expect(
      buildServiceConfigs({ ...local, tailscaleBin: '/usr/bin/tailscale' }).signer.approverAddress,
    ).toEqual({
      origin: 'https://approver.localhost:8766',
      target: 'http://127.0.0.1:8766',
      tailscale: { via: 'cli', bin: '/usr/bin/tailscale' },
    });
    expect(() => buildServiceConfigs({ ...local, tailscaleBin: 'tailscale' })).toThrow(
      /--tailscale-bin must be an absolute path/,
    );
  });

  it('install-config refuses a tailscale the signer would, the Tailscale app CLI included, and pins none', () => {
    const dir = tmpDir();
    const userCopy = join(dir, 'tailscale');
    writeFileSync(userCopy, '#!/bin/sh\n', { mode: 0o755 });
    const args = ['--out-dir', dir, '--approver-origin', 'https://approver.localhost:8766'];
    expect(() => installConfig([...args, '--tailscale-bin', userCopy])).toThrow(
      /not in a system bin directory or \/opt\/keyflap\/tools\/tailscale\/[\s\S]*fix: install tailscale as root/,
    );
    expect(() => installConfig([...args, '--tailscale-bin', MACOS_APP_CLI])).toThrow(
      /not in a system bin directory or \/opt\/keyflap\/tools\/tailscale\//,
    );
    expect(existsSync(join(dir, 'signer.json'))).toBe(false);
    installConfig(args);
    expect(
      JSON.parse(readFileSync(join(dir, 'signer.json'), 'utf8')).approverAddress,
    ).toBeUndefined();
    const sys = '/usr/bin/env';
    const st = statSync(sys);
    if (st.uid !== 0 || (st.mode & 0o022) !== 0) return;
    const dir2 = tmpDir();
    installConfig([
      '--out-dir',
      dir2,
      '--approver-origin',
      'https://box.tail1.ts.net',
      '--tailscale-bin',
      sys,
    ]);
    expect(JSON.parse(readFileSync(join(dir2, 'signer.json'), 'utf8')).approverAddress).toEqual({
      origin: 'https://box.tail1.ts.net',
      target: 'http://127.0.0.1:8766',
      tailscale: { via: 'cli', bin: sys },
    });
  });

  it('install-config reads the setting through the LocalAPI only from a root-only directory, never with a CLI too', () => {
    const dir = tmpDir();
    const args = ['--out-dir', dir, '--approver-origin', 'https://box.tail1.ts.net'];
    expect(() => installConfig([...args, '--tailscale-localapi', dir])).toThrow(
      /(not root|writable by)[\s\S]*fix: the signer reads Tailscale's setting only from a directory nobody but root can change/,
    );
    expect(() => installConfig([...args, '--tailscale-localapi', 'Library/Tailscale'])).toThrow(
      /Library\/Tailscale: not an absolute path/,
    );
    expect(existsSync(join(dir, 'signer.json'))).toBe(false);
    expect(() =>
      buildServiceConfigs({
        ...base,
        tailscaleBin: '/usr/bin/tailscale',
        tailscaleLocalApi: '/Library/Tailscale',
      }),
    ).toThrow(/--tailscale-bin and --tailscale-localapi: one or the other/);
    expect(
      buildServiceConfigs({ ...base, tailscaleLocalApi: '/Library/Tailscale' }).signer
        .approverAddress,
    ).toEqual({
      origin: 'https://box.tail1.ts.net',
      target: 'http://127.0.0.1:8766',
      tailscale: { via: 'localapi', dir: '/Library/Tailscale' },
    });
    const rootOnly = '/usr/share';
    const st = statSync(rootOnly);
    if (st.uid !== 0 || (st.mode & 0o022) !== 0) return;
    installConfig([...args, '--tailscale-localapi', rootOnly]);
    expect(JSON.parse(readFileSync(join(dir, 'signer.json'), 'utf8')).approverAddress).toEqual({
      origin: 'https://box.tail1.ts.net',
      target: 'http://127.0.0.1:8766',
      tailscale: { via: 'localapi', dir: rootOnly },
    });
  });

  it('service mode is the installed wrapper, never a checkout run', () => {
    expect(isServiceMode({})).toBe(false);
    expect(isServiceMode({ KEYFLAP_MODE: 'service' })).toBe(true);
    expect(SERVICE_PATHS.adminSocket).toBe('/run/keyflap/admin.sock');
  });

  it('Xauthority entry: FamilyWild, display number, MIT-MAGIC-COOKIE-1', () => {
    const cookie = Buffer.alloc(16, 0xab);
    const e = xauthorityEntry(99, cookie);
    expect(e.readUInt16BE(0)).toBe(0xffff);
    expect(e.readUInt16BE(2)).toBe(0);
    expect(e.readUInt16BE(4)).toBe(2);
    expect(e.subarray(6, 8).toString()).toBe('99');
    expect(e.readUInt16BE(8)).toBe(18);
    expect(e.subarray(10, 28).toString()).toBe('MIT-MAGIC-COOKIE-1');
    expect(e.readUInt16BE(28)).toBe(16);
    expect(e.subarray(30)).toEqual(cookie);
  });
});
