import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const scripts = {
  linux: readFileSync(join(import.meta.dirname, '..', 'linux', 'install.sh'), 'utf8'),
  macos: readFileSync(join(import.meta.dirname, '..', 'macos', 'install.sh'), 'utf8'),
};
const macUninstall = readFileSync(join(import.meta.dirname, '..', 'macos', 'uninstall.sh'), 'utf8');
const ROOT_ONLY_CANDIDATES = '(/usr/bin/tailscale /usr/sbin/tailscale /usr/local/bin/tailscale)';

function shellFunction(text: string, name: string): string {
  const m = new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}\\n`, 'm').exec(text);
  if (!m) throw new Error(`no function ${name}`);
  return m[0];
}

interface Machine {
  root: string;
  candidates: [string, string, string];
  tailscaleDir: string;
  file: (path: string) => string;
  standaloneApp: () => void;
}

function machine(): Machine {
  const root = mkdtempSync(join(tmpdir(), 'kf-tailscale-pick-'));
  const file = (path: string) => {
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, '#!/bin/sh\n', { mode: 0o755 });
    return path;
  };
  const tailscaleDir = join(root, 'Library/Tailscale');
  return {
    root,
    candidates: [
      join(root, 'usr/bin/tailscale'),
      join(root, 'usr/sbin/tailscale'),
      join(root, 'usr/local/bin/tailscale'),
    ],
    tailscaleDir,
    file,
    standaloneApp: () => {
      mkdirSync(tailscaleDir, { recursive: true });
      symlinkSync('49152', join(tailscaleDir, 'ipnport'));
    },
  };
}

interface Pick {
  bin: string;
  localapi: string;
  problems: string[];
}

function choose(
  os: keyof typeof scripts,
  m: Machine,
  o: { origin?: string; bin?: string; rootOnly?: string[] } = {},
): Pick {
  const text = scripts[os];
  const origin = o.origin ?? 'https://box.tail1.ts.net:8766';
  const code = [
    'set -euo pipefail',
    ...['pick_tool', 'choose_tailscale'].map((n) => shellFunction(text, n)),
    'tool_problem() { case " $ROOT_ONLY " in *" $1 "*) ;; *) if [[ -e $1 ]]; then echo "$1 is owned by uid 501, not root"; else echo "$1 does not exist"; fi ;; esac; }',
    'localapi_problem() { case " $ROOT_ONLY " in *" $1 "*) ;; *) echo "$1 (owned by uid 501): someone other than root could change it" ;; esac; }',
    'problem() { echo "PROBLEM: $*"; }',
    `prefix=${m.root}/opt/keyflap`,
    `tailscale_candidates=(${m.candidates.join(' ')})`,
    `tailscale_dir=${m.tailscaleDir}`,
    `origin=${origin}`,
    `origin_host=${new URL(origin).hostname}`,
    'tailscale_bin=$GIVEN_BIN',
    'tailscale_localapi=',
    'choose_tailscale',
    'echo "bin=$tailscale_bin"',
    'echo "localapi=$tailscale_localapi"',
  ].join('\n');
  const r = spawnSync('bash', ['-c', code], {
    encoding: 'utf8',
    env: {
      PATH: '/usr/bin:/bin',
      ROOT_ONLY: (o.rootOnly ?? []).join(' '),
      GIVEN_BIN: o.bin ?? '',
    },
  });
  expect(r.status, r.stderr).toBe(0);
  const lines = r.stdout.split(/\n(?=bin=|localapi=|PROBLEM: )/);
  const value = (k: string) =>
    (lines.find((l) => l.startsWith(`${k}=`)) ?? '').slice(k.length + 1).trim();
  return {
    bin: value('bin'),
    localapi: value('localapi'),
    problems: lines.filter((l) => l.startsWith('PROBLEM: ')).map((l) => l.slice(9).trim()),
  };
}

describe('install.sh hands the signer a root-only tailscale to watch the approver address with', () => {
  for (const os of ['linux', 'macos'] as const) {
    describe(os, () => {
      it('names --tailscale-bin in its usage, parses it, and passes it to install-config', () => {
        const text = scripts[os];
        expect(text).toContain('--tailscale-bin PATH      the tailscale CLI the signer runs');
        expect(text).toMatch(/--tailscale-bin\) tailscale_bin=\$\{2:\?\}; shift 2 ;;/);
        expect(text).toMatch(/cfg_args.*--tailscale-bin "\$tailscale_bin"/);
        expect(text).toContain(`tailscale_candidates=${ROOT_ONLY_CANDIDATES}`);
        expect(text).toMatch(/^choose_tailscale$/m);
      });

      it('takes the first candidate the signer would run, not the first that exists', () => {
        const m = machine();
        const [usrBin, usrSbin, usrLocal] = m.candidates.map(m.file) as [string, string, string];
        expect(choose(os, m, { rootOnly: [usrSbin, usrLocal] })).toEqual({
          bin: usrSbin,
          localapi: '',
          problems: [],
        });
        expect(choose(os, m, { rootOnly: [usrLocal] }).bin).toBe(usrLocal);
        expect(choose(os, m, { rootOnly: [usrBin, usrLocal] }).bin).toBe(usrBin);
      });

      it('with none it can run, says why each one there was refused', () => {
        const m = machine();
        const usrLocal = m.file(m.candidates[2]);
        const r = choose(os, m);
        expect(r.problems).toHaveLength(1);
        expect(r.problems[0]).toMatch(
          os === 'macos'
            ? /^the signer can't read Tailscale's serve setting: no \S+\/Library\/Tailscale\/ipnport, and no\s+tailscale it can run in \/usr\/bin/
            : /^no tailscale the signer can run in \/usr\/bin/,
        );
        expect(r.problems[0]).toContain(`refused: ${usrLocal} is owned by uid 501, not root`);
      });

      it('checks a --tailscale-bin it is given, and looks for none for a non-Tailscale origin', () => {
        const m = machine();
        const given = m.file(join(m.root, 'home/me/tailscale'));
        expect(choose(os, m, { bin: given }).problems).toEqual([
          expect.stringMatching(/^the signer would refuse tailscale: .*owned by uid 501/),
        ]);
        expect(choose(os, m, { bin: given, rootOnly: [given] })).toMatchObject({
          bin: given,
          problems: [],
        });
        m.file(m.candidates[0]);
        expect(
          choose(os, m, { origin: 'https://approver.localhost:8766', rootOnly: [m.candidates[0]] }),
        ).toMatchObject({ bin: '', problems: [] });
      });
    });
  }

  describe('macOS: with the standalone Tailscale app the signer reads its tailscaled over loopback', () => {
    it('chooses the LocalAPI when the port link is there, ahead of any root-only tailscale', () => {
      const m = machine();
      m.standaloneApp();
      const usrLocal = m.file(m.candidates[2]);
      expect(choose('macos', m, { rootOnly: [m.tailscaleDir, usrLocal] })).toEqual({
        bin: '',
        localapi: m.tailscaleDir,
        problems: [],
      });
    });

    it('a --tailscale-bin it is given wins over the LocalAPI', () => {
      const m = machine();
      m.standaloneApp();
      const given = m.file(m.candidates[0]);
      expect(choose('macos', m, { bin: given, rootOnly: [given, m.tailscaleDir] })).toEqual({
        bin: given,
        localapi: '',
        problems: [],
      });
    });

    it('refuses a Tailscale directory someone other than root could change', () => {
      const m = machine();
      m.standaloneApp();
      expect(choose('macos', m).problems).toEqual([
        expect.stringMatching(
          /^the signer would refuse to read Tailscale's setting: \S+\/Library\/Tailscale \(owned by uid 501\)[\s\S]*standalone Tailscale app/,
        ),
      ]);
    });

    it('with only the App Store app (no port link) it says plainly what to install', () => {
      const m = machine();
      const [problem] = choose('macos', m).problems;
      expect(problem).toContain(
        "The App Store Tailscale app keeps\n    that setting where a background service can't read it",
      );
      expect(problem).toContain('Install the standalone Tailscale app');
      expect(problem).toContain('or pass --tailscale-bin PATH');
    });

    it('localapi_problem refuses a directory or port link someone other than root could change', () => {
      const m = machine();
      m.standaloneApp();
      const bin = join(m.root, 'bin');
      mkdirSync(bin);
      if (process.platform !== 'darwin') {
        writeFileSync(
          join(bin, 'stat'),
          '#!/bin/sh\n[ "$1" = -f ] || exit 2\nfmt=$(printf %s "$2" | sed "s/%Lp/%a/")\nexec /usr/bin/stat -c "$fmt" "$3"\n',
          { mode: 0o755 },
        );
      }
      const code = [
        'set -euo pipefail',
        shellFunction(scripts.macos, 'chain_problem'),
        shellFunction(scripts.macos, 'localapi_problem'),
        `localapi_problem ${m.tailscaleDir}`,
      ].join('\n');
      const r = spawnSync('bash', ['-c', code], {
        encoding: 'utf8',
        env: { PATH: `${bin}:/usr/bin:/bin` },
      });
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toMatch(
        /^\S+ \((owned by uid \d+|mode \d+: writable by group or others)\): someone other than root could change it\n$/,
      );
    });

    it('passes the directory to install-config and grants the token before writing the config', () => {
      const text = scripts.macos;
      expect(text).toContain('tailscale_dir=/Library/Tailscale');
      expect(text).toMatch(
        /cfg_args=\("\$\{cfg_args\[@\]\}" --tailscale-localapi "\$tailscale_localapi"\)/,
      );
      const order = [
        'signer_uid=$(service_user _keyflap-signer',
        'grant_tailscale_token "$tailscale_localapi"',
        'packages/cli/src/service/install-config.ts',
      ].map((x) => text.indexOf(x));
      expect(order.every((i) => i > 0)).toBe(true);
      expect([...order].sort((a, b) => a - b)).toEqual(order);
      for (const gone of ['Tailscale.app', 'codesign', 'ditto', 'W5364U7YZB', 'tools/tailscale']) {
        expect(text, gone).not.toContain(gone);
      }
    });
  });

  describe('macOS: the read access to the token is an ACL entry for _keyflap-signer and nothing else', () => {
    function aclMachine(acl: Record<string, string[]>) {
      const root = mkdtempSync(join(tmpdir(), 'kf-tailscale-acl-'));
      const bin = join(root, 'bin');
      mkdirSync(bin);
      const tsDir = join(root, 'Library/Tailscale');
      mkdirSync(tsDir, { recursive: true });
      symlinkSync('49152', join(tsDir, 'ipnport'));
      writeFileSync(join(tsDir, 'sameuserproof-49152'), 'token\n');
      writeFileSync(join(tsDir, 'sameuserproof-40000'), 'old\n');
      const log = join(root, 'calls');
      writeFileSync(log, '');
      const aclFile = (p: string) => join(root, `acl-${p.replaceAll('/', '_')}`);
      for (const [p, lines] of Object.entries(acl)) {
        writeFileSync(aclFile(join(tsDir, p)), lines.map((l) => `${l}\n`).join(''));
      }
      writeFileSync(
        join(bin, 'ls'),
        `#!/bin/sh\n[ "$1" = -led ] || exit 2\necho "-rw-r-----+ 1 root admin 21 Oct 30 10:00 $2"\nf=${root}/acl-$(printf %s "$2" | tr / _)\n[ -f "$f" ] && cat "$f"\nexit 0\n`,
        { mode: 0o755 },
      );
      writeFileSync(join(bin, 'chmod'), `#!/bin/sh\necho "chmod $*" >>${log}\n`, { mode: 0o755 });
      writeFileSync(join(bin, 'sudo'), `#!/bin/sh\necho "sudo $*" >>${log}\nexit 0\n`, {
        mode: 0o755,
      });
      const run = (text: string, body: string) => {
        const code = [
          'set -euo pipefail',
          `signer_token_ace='user:_keyflap-signer allow read'`,
          shellFunction(text, 'drop_signer_aces'),
          ...(text === scripts.macos ? [shellFunction(text, 'grant_tailscale_token')] : []),
          body,
        ].join('\n');
        const r = spawnSync('bash', ['-c', code], {
          encoding: 'utf8',
          env: { PATH: `${bin}:/usr/bin:/bin` },
        });
        expect(r.status, r.stderr).toBe(0);
        return readFileSync(log, 'utf8').split('\n').filter(Boolean);
      };
      return { tsDir, run };
    }

    it('install.sh replaces its own entries: an inheritable one on the directory, a direct one on the current token', () => {
      const m = aclMachine({
        '': [
          ' 0: group:everyone deny delete',
          ' 1: user:_keyflap-signer allow list,file_inherit,only_inherit',
        ],
        'sameuserproof-49152': [' 0: user:_keyflap-signer inherited allow read'],
      });
      expect(m.run(scripts.macos, `grant_tailscale_token ${m.tsDir}`)).toEqual([
        `chmod -a# 1 ${m.tsDir}`,
        `chmod +a user:_keyflap-signer allow read,file_inherit,only_inherit ${m.tsDir}`,
        `chmod -a# 0 ${m.tsDir}/sameuserproof-49152`,
        `chmod +a user:_keyflap-signer allow read ${m.tsDir}/sameuserproof-49152`,
        `sudo -u _keyflap-signer /bin/test -r ${m.tsDir}/sameuserproof-49152`,
      ]);
    });

    it('uninstall.sh removes them all, inherited ones on old token files too, highest index first, and leaves other entries', () => {
      const m = aclMachine({
        '': [
          ' 0: user:_keyflap-signer allow list,file_inherit,only_inherit',
          ' 1: group:everyone deny delete',
        ],
        'sameuserproof-49152': [
          ' 0: user:_keyflap-signer allow read',
          ' 1: user:someone-else allow read',
          ' 2: user:_keyflap-signer inherited allow read',
        ],
        'sameuserproof-40000': [' 0: user:_keyflap-signer inherited allow read'],
      });
      const loop = macUninstall
        .slice(macUninstall.indexOf('if [[ -d /Library/Tailscale ]]; then'))
        .split('\nfor label')[0]
        ?.replaceAll('/Library/Tailscale', m.tsDir);
      expect(m.run(macUninstall, loop ?? '')).toEqual([
        `chmod -a# 0 ${m.tsDir}`,
        `chmod -a# 0 ${m.tsDir}/sameuserproof-40000`,
        `chmod -a# 2 ${m.tsDir}/sameuserproof-49152`,
        `chmod -a# 0 ${m.tsDir}/sameuserproof-49152`,
      ]);
    });

    it('uninstall.sh drops the entries before --purge deletes the user they name', () => {
      expect(macUninstall.indexOf('drop_signer_aces /Library/Tailscale')).toBeGreaterThan(0);
      expect(macUninstall.indexOf('drop_signer_aces /Library/Tailscale')).toBeLessThan(
        macUninstall.indexOf('dscl . -delete "/Users/$u"'),
      );
    });
  });
});
