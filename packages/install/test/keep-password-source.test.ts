import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildServiceConfigs } from '../../cli/src/service/config.ts';
import { keptOrFreshPin } from '../../cli/src/service/install-config.ts';
import { DARWIN_SERVICE_PATHS, LINUX_SERVICE_PATHS } from '../../cli/src/service/paths.ts';

const scripts = {
  linux: readFileSync(join(import.meta.dirname, '..', 'linux', 'install.sh'), 'utf8'),
  macos: readFileSync(join(import.meta.dirname, '..', 'macos', 'install.sh'), 'utf8'),
};
const PIN = 'a'.repeat(64);

function shellFunction(text: string, name: string): string {
  const m = new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}\\n`, 'm').exec(text);
  if (!m) throw new Error(`no function ${name}`);
  return m[0];
}

type Source = 'proton-pass' | '1password' | null;

function signerJson(
  os: 'linux' | 'macos',
  source: Source,
  o: { vault?: string; pin?: boolean } = {},
): string {
  const paths = os === 'linux' ? LINUX_SERVICE_PATHS : DARWIN_SERVICE_PATHS;
  const { signer } = buildServiceConfigs(
    {
      approverOrigin: 'https://box.tail1.ts.net:8766',
      tls: false,
      highRisk: [],
      ...(source === 'proton-pass'
        ? {
            protonPassBin: '/opt/keyflap/tools/pass-cli/pass-cli',
            ...(o.pin === false ? {} : { protonPassSha256: PIN }),
            ...(o.vault !== undefined ? { protonPassVault: o.vault } : {}),
          }
        : {}),
      ...(source === '1password'
        ? {
            onePasswordBin: '/usr/bin/op',
            ...(o.pin === false ? {} : { onePasswordSha256: PIN }),
            ...(o.vault !== undefined ? { onePasswordVault: o.vault } : {}),
          }
        : {}),
    },
    paths,
    os === 'linux' ? 'linux' : 'darwin',
  );
  return `${JSON.stringify(signer, null, 2)}\n`;
}

interface Kept {
  password_source: string;
  kept_source: string;
  pp_bin: string;
  pp_vault: string;
  pp_vault_set: string;
  op_bin: string;
  op_vault: string;
  op_vault_set: string;
  kept_sha: string;
}

interface Attempt {
  status: number | null;
  stdout: string;
  stderr: string;
}

function attempt(
  os: 'linux' | 'macos',
  config: string | null,
  o: {
    password_source?: string;
    none?: boolean;
    node?: string;
    op_bin?: string;
    op_vault?: string;
    op_token_file?: string;
    pp_bin?: string;
  } = {},
): Attempt {
  const dir = mkdtempSync(join(tmpdir(), 'kf-keep-'));
  const file = join(dir, 'signer.json');
  if (config !== null) writeFileSync(file, config);
  const code = [
    'set -euo pipefail',
    'die() { echo "install: $*" >&2; exit 1; }',
    ...['read_kept_source', 'keep_password_source', 'check_password_source_flags'].map((n) =>
      shellFunction(scripts[os], n),
    ),
    `password_source='${o.password_source ?? ''}' no_password_source=${o.none ? 1 : 0}`,
    `pp_bin='${o.pp_bin ?? ''}' pp_vault='' pp_vault_set=0 op_bin='${o.op_bin ?? ''}'`,
    `op_vault='${o.op_vault ?? ''}' op_vault_set=${o.op_vault === undefined ? 0 : 1}`,
    `op_token_file='${o.op_token_file ?? ''}'`,
    `keep_password_source '${o.node ?? process.execPath}' '${file}'`,
    'check_password_source_flags',
    ...[
      'password_source',
      'kept_source',
      'pp_bin',
      'pp_vault',
      'pp_vault_set',
      'op_bin',
      'op_vault',
      'op_vault_set',
      'kept_sha',
    ].map((v) => `printf '%s=%s\\n' ${v} "\${${v}-}"`),
  ].join('\n');
  return spawnSync('bash', ['-c', code], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
}

function keep(...args: Parameters<typeof attempt>): Kept {
  const r = attempt(...args);
  expect(r.status, r.stderr).toBe(0);
  const out: Record<string, string> = {};
  for (const line of r.stdout.split('\n')) {
    const i = line.indexOf('=');
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1);
  }
  return out as unknown as Kept;
}

describe.each(['linux', 'macos'] as const)(
  '%s install.sh keeps the connected password manager',
  (os) => {
    it('Proton Pass: tool, vault and pin carry over without --password-source', () => {
      expect(keep(os, signerJson(os, 'proton-pass', { vault: 'Agent' }))).toMatchObject({
        password_source: 'proton-pass',
        kept_source: '1',
        pp_bin: '/opt/keyflap/tools/pass-cli/pass-cli',
        pp_vault: 'Agent',
        pp_vault_set: '1',
        kept_sha: PIN,
        op_bin: '',
      });
    });

    it('1Password: tool and pin carry over; no vault stays every vault', () => {
      expect(keep(os, signerJson(os, '1password'))).toMatchObject({
        password_source: '1password',
        kept_source: '1',
        op_bin: '/usr/bin/op',
        op_vault_set: '0',
        kept_sha: PIN,
        pp_bin: '',
      });
    });

    it('a source that was never pinned is kept without a pin', () => {
      expect(keep(os, signerJson(os, '1password', { pin: false }))).toMatchObject({
        kept_source: '1',
        kept_sha: '',
      });
    });

    it('nothing connected keeps nothing', () => {
      expect(keep(os, signerJson(os, null))).toMatchObject({
        password_source: '',
        kept_source: '0',
        pp_bin: '',
        op_bin: '',
      });
    });

    it('an explicit --password-source wins and keeps nothing', () => {
      expect(
        keep(os, signerJson(os, 'proton-pass', { vault: 'Agent' }), {
          password_source: '1password',
        }),
      ).toMatchObject({ password_source: '1password', kept_source: '0', pp_bin: '', op_bin: '' });
    });

    it('--password-source none disconnects: nothing is kept', () => {
      expect(keep(os, signerJson(os, '1password'), { none: true })).toMatchObject({
        password_source: '',
        kept_source: '0',
        op_bin: '',
      });
    });

    it('a fresh machine (no config yet) keeps nothing and does not fail', () => {
      expect(keep(os, null).kept_source).toBe('0');
      expect(keep(os, null, { node: '/nonexistent/node' }).kept_source).toBe('0');
    });

    it('a config it cannot read stops the install and says how to choose', () => {
      const unreadable = attempt(os, '{ not json');
      expect(unreadable.status).toBe(1);
      expect(unreadable.stderr).toContain('cannot read the password manager connected in');
      expect(unreadable.stderr).toContain('--password-source');
      const noNode = attempt(os, signerJson(os, '1password'), { node: '/nonexistent/node' });
      expect(noNode.status).toBe(1);
      expect(noNode.stderr).toContain('no Node at /nonexistent/node');
      const cfg = JSON.parse(signerJson(os, '1password'));
      cfg.sources.onePassword.vault = 'two\tfields';
      const odd = attempt(os, JSON.stringify(cfg));
      expect(odd.status).toBe(1);
      expect(odd.stderr).toContain('cannot read the password manager connected in');
    });

    it('an explicit --password-source never reads the config, so it can repair a broken one', () => {
      expect(keep(os, '{ not json', { password_source: '1password' }).kept_source).toBe('0');
    });

    it('rotating the token with --op-token-file alone keeps the tool, vault and pin', () => {
      expect(
        keep(os, signerJson(os, '1password', { vault: 'Agent' }), { op_token_file: '/tmp/t' }),
      ).toMatchObject({
        password_source: '1password',
        op_bin: '/usr/bin/op',
        op_vault: 'Agent',
        kept_sha: PIN,
      });
    });

    it('--op-token-file with Proton Pass connected is still refused', () => {
      const r = attempt(os, signerJson(os, 'proton-pass'), { op_token_file: '/tmp/t' });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('need --password-source 1password');
    });

    it('an explicit vault or tool beats the kept one, and a different tool drops the kept pin', () => {
      const kept = signerJson(os, '1password', { vault: 'Agent' });
      expect(keep(os, kept, { op_vault: 'Other', op_token_file: '/tmp/t' })).toMatchObject({
        op_vault: 'Other',
        kept_sha: PIN,
      });
      expect(
        keep(os, kept, { op_bin: '/usr/local/bin/op', op_token_file: '/tmp/t' }),
      ).toMatchObject({
        op_bin: '/usr/local/bin/op',
        kept_sha: '',
      });
    });

    it('documents none, and reads the config only after the options are parsed', () => {
      const text = scripts[os];
      expect(text).toContain('--password-source none');
      expect(text).toContain('die "--password-source must be proton-pass, 1password or none"');
      const parsed = text.indexOf('if [[ $password_source == none ]]');
      const kept = text.search(/^keep_password_source [^(]/m);
      expect(parsed).toBeGreaterThan(text.indexOf('-h|--help) usage'));
      expect(kept).toBeGreaterThan(parsed);
      expect(text.search(/^check_password_source_flags$/m)).toBeGreaterThan(kept);
    });

    it('passes the kept pin to install-config, and the drop-in and token follow the tool variables', () => {
      const text = scripts[os];
      expect(text).toMatch(/--proton-pass-sha256 "\$kept_sha"/);
      expect(text).toMatch(/--op-sha256 "\$kept_sha"/);
      expect(text).toMatch(
        /if \[\[ \$password_source == 1password \]\]; then\n\s+if \[\[ -n \$op_token_file \]\]/,
      );
    });
  },
);

describe('install-config keeps a pin, and says when the tool changed since', () => {
  const spec = { command: 'op', installHint: 'x' };
  const ok = (sha: string) => () => ({ ok: true as const, path: '/usr/bin/op', sha256: sha });

  it('uses a fresh pin when none was kept', () => {
    expect(keptOrFreshPin('/usr/bin/op', spec, undefined, () => {}, ok('b'.repeat(64)))).toBe(
      'b'.repeat(64),
    );
  });

  it('keeps the old pin even when the tool changed, and warns with the trust command', () => {
    const said: string[] = [];
    expect(keptOrFreshPin('/usr/bin/op', spec, PIN, (t) => said.push(t), ok('b'.repeat(64)))).toBe(
      PIN,
    );
    expect(said.join('')).toContain('sudo keyflap password-source trust op');
  });

  it('says nothing when the tool is the one that was trusted', () => {
    const said: string[] = [];
    keptOrFreshPin('/usr/bin/op', spec, PIN, (t) => said.push(t), ok(PIN));
    expect(said).toEqual([]);
  });

  it('refuses a pin that is not a hash, and a tool in the wrong place', () => {
    expect(() => keptOrFreshPin('/usr/bin/op', spec, 'abc', () => {}, ok(PIN))).toThrow(
      /64 hex digits/,
    );
    expect(() =>
      keptOrFreshPin(
        '/home/u/op',
        spec,
        PIN,
        () => {},
        () => ({
          ok: false as const,
          problem: 'untrusted' as const,
          detail: 'not root-owned',
          fix: 'move it',
        }),
      ),
    ).toThrow(/not root-owned/);
  });
});
