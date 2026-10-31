import { createHash } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdtempSync,
  renameSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  checkTool,
  checkToolLocation,
  OnePasswordSource,
  OP_TOOL,
  PASS_CLI_TOOL,
  ProtonPassSource,
  SourceError,
  ToolLauncher,
  type ToolSpec,
  toolCandidates,
  toolSha256,
} from '../src/index.ts';
import { fakeOp, fakePassCli } from './fake.ts';

const TOKEN = 'ops_test-token';

const ENV: ToolSpec = { command: 'env', installHint: 'coreutils' };
const SYSTEM_ENV = '/usr/bin/env';
const haveSystemEnv = (() => {
  try {
    const st = lstatSync(SYSTEM_ENV);
    return st.isFile() && st.uid === 0 && (st.mode & 0o022) === 0;
  } catch {
    return false;
  }
})();

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'resolved';
  } catch (err) {
    return err instanceof SourceError ? err.reason : `other: ${(err as Error).message}`;
  }
}

describe('invariant 1 (service mode): the signer runs only a tool nobody but root can change', () => {
  it("refuses a tool in the user's home or any directory outside the allowed ones", () => {
    const dir = mkdtempSync(join(tmpdir(), 'inv1-tool-'));
    const bin = join(dir, 'pass-cli');
    copyFileSync(SYSTEM_ENV, bin);
    chmodSync(bin, 0o755);
    const r = checkToolLocation(bin, PASS_CLI_TOOL);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.detail).toMatch(
        /not in a system bin directory or \/opt\/keyflap\/tools\/pass-cli\//,
      );
      expect(r.fix).toMatch(/into \/opt\/keyflap\/tools\/pass-cli\//);
    }
    expect(checkToolLocation('/home/u/.local/bin/pass-cli', PASS_CLI_TOOL).ok).toBe(false);
    expect(checkToolLocation('pass-cli', PASS_CLI_TOOL).ok).toBe(false);
    expect(checkToolLocation('/opt/keyflap/tools/pass-cli/../../../tmp/x', PASS_CLI_TOOL).ok).toBe(
      false,
    );
  });

  it('refuses a missing tool and a symbolic link (the configured path must be the real one)', () => {
    expect(checkToolLocation('/usr/bin/keyflap-no-such-tool', ENV).ok).toBe(false);
    let binIsLink = false;
    try {
      binIsLink = lstatSync('/bin').isSymbolicLink();
    } catch {
      binIsLink = false;
    }
    if (binIsLink && haveSystemEnv) {
      const r = checkToolLocation('/bin/env', ENV);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.detail).toMatch(/symbolic link/);
    }
  });

  it.runIf(haveSystemEnv)('accepts a root-owned system binary, and pins its SHA-256', () => {
    const ok = checkTool(SYSTEM_ENV, ENV);
    expect(ok.ok).toBe(true);
    const sha = toolSha256(SYSTEM_ENV);
    expect(checkTool(SYSTEM_ENV, ENV, sha).ok).toBe(true);
    const changed = checkTool(SYSTEM_ENV, ENV, '0'.repeat(64));
    expect(changed.ok).toBe(false);
    if (!changed.ok) {
      expect(changed.problem).toBe('changed');
      expect(changed.fix).toBe(
        'make sure the new env is genuine, then: sudo keyflap password-source trust env',
      );
    }
  });

  it.runIf(haveSystemEnv)('a changed binary is refused until the owner trusts it again', () => {
    let pin = '0'.repeat(64);
    const refused: string[] = [];
    const t = new ToolLauncher(
      ENV,
      SYSTEM_ENV,
      { mode: 'system', sha256: '1'.repeat(64), currentPin: () => pin },
      (e) => refused.push(e.problem),
    );
    expect(() => t.path()).toThrow(expect.objectContaining({ reason: 'source_tool_changed' }));
    expect(() => t.path()).toThrow(SourceError);
    expect(refused).toEqual(['changed']);
    pin = toolSha256(SYSTEM_ENV);
    expect(t.path()).toBe(SYSTEM_ENV);
  });

  it('every launch is checked: the adapter never runs an untrusted pass-cli', async () => {
    const f = fakePassCli({ loggedIn: true, vaults: [] });
    const refused: { problem: string; path: string }[] = [];
    const src = new ProtonPassSource({
      bin: f.bin,
      env: f.env,
      trust: { mode: 'system' },
      onToolRefused: (e) => refused.push(e),
    });
    expect(await reason(src.list())).toBe('source_tool_untrusted');
    expect(await reason(src.fetch('proton-pass:abc:def', 'r'))).toBe('source_tool_untrusted');
    expect(f.calls()).toEqual([]);
    expect(refused).toEqual([
      { tool: 'pass-cli', path: f.bin, problem: 'untrusted', detail: expect.any(String) },
    ]);
  });

  it('every launch is checked: the adapter never runs an untrusted op', async () => {
    const f = fakeOp({ token: TOKEN, vaults: [] });
    const refused: { problem: string; path: string }[] = [];
    const src = new OnePasswordSource({
      bin: f.bin,
      env: f.env,
      trust: { mode: 'system' },
      onToolRefused: (e) => refused.push(e),
    });
    const ref = `1password:${'a'.repeat(26)}:${'b'.repeat(26)}`;
    expect(await reason(src.list())).toBe('source_tool_untrusted');
    expect(await reason(src.fetch(ref, 'r'))).toBe('source_tool_untrusted');
    expect(f.calls()).toEqual([]);
    expect(refused).toEqual([
      { tool: 'op', path: f.bin, problem: 'untrusted', detail: expect.any(String) },
    ]);
  });

  it('dev mode (same uid as the user) runs the tool it is given', async () => {
    const f = fakePassCli({ loggedIn: true, vaults: [] });
    const src = new ProtonPassSource({ bin: f.bin, env: f.env, trust: { mode: 'same-user' } });
    expect(await src.list()).toEqual([]);
    expect(f.calls().length).toBeGreaterThan(0);
  });

  it('an adapter must say how its tool is trusted: there is no default', () => {
    expect(() => new ProtonPassSource({ bin: 'pass-cli' } as never)).toThrow(/trust/);
    expect(() => new OnePasswordSource({ bin: 'op' } as never)).toThrow(/trust/);
    expect(
      () => new ToolLauncher(ENV, SYSTEM_ENV, { mode: 'system', sha256: 'not-a-hash' }),
    ).toThrow(/SHA-256/);
  });

  describe('the hash a pin is checked against is the hash of the file that is there', () => {
    const sha = (text: string) => createHash('sha256').update(text).digest('hex');
    const fresh = () => mkdtempSync(join(tmpdir(), 'inv1-hash-'));

    it('a file swapped in by rename gets its own hash, not the cached one', () => {
      const dir = fresh();
      const bin = join(dir, 'tool');
      writeFileSync(bin, 'genuine');
      expect(toolSha256(bin)).toBe(sha('genuine'));
      writeFileSync(join(dir, 'fake'), 'fake');
      renameSync(join(dir, 'fake'), bin);
      expect(toolSha256(bin)).toBe(sha('fake'));
    });

    it('a file rewritten in place gets its own hash', () => {
      const bin = join(fresh(), 'tool');
      writeFileSync(bin, 'genuine');
      expect(toolSha256(bin)).toBe(sha('genuine'));
      writeFileSync(bin, 'fake!!!');
      expect(toolSha256(bin)).toBe(sha('fake!!!'));
    });

    it('a symbolic link is refused, so a target swapped behind it never borrows a cached hash', () => {
      const dir = fresh();
      writeFileSync(join(dir, 'target'), 'genuine');
      symlinkSync(join(dir, 'target'), join(dir, 'tool'));
      expect(() => toolSha256(join(dir, 'tool'))).toThrow();
      writeFileSync(join(dir, 'fake'), 'fake');
      renameSync(join(dir, 'fake'), join(dir, 'target'));
      expect(() => toolSha256(join(dir, 'tool'))).toThrow();
      expect(toolSha256(join(dir, 'target'))).toBe(sha('fake'));
    });
  });

  it('the fix names the command that connects the tool, else the installer flag the spec gives', () => {
    const other = join(mkdtempSync(join(tmpdir(), 'inv1-hint-')), 'other');
    const r = checkToolLocation(other, {
      ...ENV,
      command: 'tailscale',
      reinstallFlag: '--tailscale-bin',
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.fix).toMatch(/--tailscale-bin \/opt\/keyflap\/tools\/tailscale\/tailscale/);
    const p = checkToolLocation(other, PASS_CLI_TOOL);
    expect(p.ok).toBe(false);
    if (!p.ok) {
      expect(p.fix).toMatch(/then run: sudo keyflap password-source add proton-pass$/);
      expect(p.fix).not.toContain('install.sh');
    }
    const op = checkToolLocation(other, OP_TOOL);
    expect(op.ok).toBe(false);
    if (!op.ok) {
      expect(op.fix).toMatch(/then run: sudo keyflap password-source add 1password$/);
      expect(op.fix).not.toContain('--proton-pass-bin');
    }
  });

  it('install.sh looks only in root locations, never on a user PATH', () => {
    expect(toolCandidates(PASS_CLI_TOOL)).toEqual([
      '/opt/keyflap/tools/pass-cli/pass-cli',
      '/usr/local/bin/pass-cli',
      '/usr/bin/pass-cli',
    ]);
  });
});
