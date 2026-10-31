import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ToolCheck } from '@aab/sources';
import { describe, expect, it } from 'vitest';
import { passwordToolCheck } from '../src/doctor.ts';
import { SERVICE_PATHS } from '../src/service/paths.ts';
import { trustTool } from '../src/service/tool-trust.ts';
import { tmpDir } from './helpers.ts';
import { FakeSystem } from './setup-fakes.ts';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);

function signerJson(bin: string, sha256?: string) {
  return JSON.stringify({
    storePath: '/var/lib/keyflap/signer/keys.enc.json',
    sources: { protonPass: { bin, env: {}, ...(sha256 ? { sha256 } : {}) } },
  });
}

describe('invariant 1 (service mode): doctor reports a password tool the signer would refuse', () => {
  it('a pass-cli in your home: fail, and the fix is the root-only tools dir', () => {
    const sys = new FakeSystem();
    sys.file(SERVICE_PATHS.signerConfig, signerJson('/home/u/.local/bin/pass-cli', A), 0o644, 0);
    sys.checkTool = () => ({
      ok: false,
      problem: 'untrusted',
      detail: '/home/u/.local/bin/pass-cli is not in a system bin directory',
      fix: 'install pass-cli as root into /opt/keyflap/tools/pass-cli/',
    });
    const c = passwordToolCheck(sys, SERVICE_PATHS);
    expect(c.status).toBe('fail');
    expect(c.detail).toMatch(/refuses to run \/home\/u\/\.local\/bin\/pass-cli/);
    expect(c.fix).toContain('/opt/keyflap/tools/pass-cli/');
  });

  it('a changed binary: fail, fix is password-source trust', () => {
    const sys = new FakeSystem();
    const bin = '/usr/bin/pass-cli';
    sys.file(SERVICE_PATHS.signerConfig, signerJson(bin, A), 0o644, 0);
    sys.tools.set(bin, { ok: true, path: bin, sha256: B });
    const c = passwordToolCheck(sys, SERVICE_PATHS);
    expect(c.status).toBe('fail');
    expect(c.fix).toBe('trust it');
    sys.tools.set(bin, { ok: true, path: bin, sha256: A });
    expect(passwordToolCheck(sys, SERVICE_PATHS).status).toBe('ok');
  });
});

describe('invariant 1 (service mode): password-source trust', () => {
  function setup(bin: string, sha256?: string) {
    const dir = tmpDir();
    const paths = { ...SERVICE_PATHS, signerConfig: join(dir, 'signer.json') };
    writeFileSync(paths.signerConfig, signerJson(bin, sha256), { mode: 0o644 });
    return paths;
  }

  it('pins the new hash of a tool that passes the location checks', () => {
    const bin = '/usr/bin/pass-cli';
    const paths = setup(bin, A);
    const out: string[] = [];
    trustTool('pass-cli', (t) => out.push(t), {
      paths,
      check: (): ToolCheck => ({ ok: true, path: bin, sha256: B }),
    });
    const cfg = JSON.parse(readFileSync(paths.signerConfig, 'utf8'));
    expect(cfg.sources.protonPass.sha256).toBe(B);
    expect(out.join('')).toContain(`SHA-256 ${B}`);
  });

  it('refuses a tool in an unsafe place and leaves the pin as it was', () => {
    const paths = setup('/home/u/.local/bin/pass-cli', A);
    expect(() =>
      trustTool('pass-cli', () => {}, {
        paths,
        check: () => ({
          ok: false,
          problem: 'untrusted',
          detail: 'not root-owned',
          fix: 'reinstall',
        }),
      }),
    ).toThrow(/not root-owned[\s\S]*fix: reinstall/);
    expect(JSON.parse(readFileSync(paths.signerConfig, 'utf8')).sources.protonPass.sha256).toBe(A);
  });

  it('re-pins op for 1Password in sources.onePassword, leaving everything else alone', () => {
    const dir = tmpDir();
    const paths = { ...SERVICE_PATHS, signerConfig: join(dir, 'signer.json') };
    const bin = '/opt/keyflap/tools/op/op';
    writeFileSync(
      paths.signerConfig,
      JSON.stringify({ storePath: '/k', sources: { onePassword: { bin, env: {}, sha256: A } } }),
    );
    const out: string[] = [];
    trustTool('op', (t) => out.push(t), {
      paths,
      check: (_p, spec): ToolCheck => {
        expect(spec.command).toBe('op');
        return { ok: true, path: bin, sha256: B };
      },
    });
    const cfg = JSON.parse(readFileSync(paths.signerConfig, 'utf8'));
    expect(cfg.sources.onePassword).toEqual({ bin, env: {}, sha256: B });
    expect(cfg.sources.protonPass).toBeUndefined();
    expect(() => trustTool('pass-cli', () => {}, { paths })).toThrow(
      /no password source uses pass-cli .*password-source add proton-pass/,
    );
  });

  it('unknown tools and a config without the source are refused', () => {
    const paths = setup('/usr/bin/pass-cli', A);
    expect(() => trustTool('rm', () => {}, { paths })).toThrow(/unknown tool/);
    expect(() => trustTool('tailscale', () => {}, { paths })).toThrow(
      /unknown tool "tailscale" \(known: pass-cli, op\)/,
    );
    writeFileSync(paths.signerConfig, JSON.stringify({ storePath: '/k' }));
    expect(() => trustTool('pass-cli', () => {}, { paths })).toThrow(/no password source/);
    expect(() => trustTool('op', () => {}, { paths })).toThrow(/password-source add 1password/);
  });
});
