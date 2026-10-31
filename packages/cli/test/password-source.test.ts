import { spawn, spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fakeOp } from '@aab/sources/testing';
import { describe, expect, it } from 'vitest';
import {
  applyConnect,
  connectedSource,
  PasswordSourceError,
  SOURCES,
  type SourceHost,
} from '../src/service/password-source.ts';
import {
  type ConnectRequest,
  connectPasswordSource,
  disconnectPasswordSource,
} from '../src/setup/password-source-flow.ts';
import { realSystem } from '../src/setup/system.ts';
import { tmpDir } from './helpers.ts';
import { ScriptedPrompter } from './setup-fakes.ts';
import {
  MAC_SIGNER_UID,
  type Machine,
  machine,
  OP_BIN,
  OP_SHA,
  OP_TOKEN,
  PASS_BIN,
  PASS_SHA,
  PROTON_TOKEN,
  SIGNER_UID,
} from './source-machine.ts';

const DROP_INS = '/etc/systemd/system/keyflap-signer.service.d';
const NO_NETWORK = '[Service]\nRestrictAddressFamilies=\nRestrictAddressFamilies=AF_UNIX\n';

function host(mach: Machine): SourceHost {
  return { sys: mach.sys, paths: mach.paths, m: mach.m };
}

function request(over: Partial<ConnectRequest> & Pick<ConnectRequest, 'kind'>): ConnectRequest {
  return { interactive: true, yes: false, confirmConnect: true, ...over };
}

async function connect(
  mach: Machine,
  script: ConstructorParameters<typeof ScriptedPrompter>[0],
  req: ConnectRequest,
) {
  const prompt = new ScriptedPrompter(script);
  let out = '';
  const done = await connectPasswordSource(
    host(mach),
    {
      prompt,
      out: (t) => {
        out += t;
      },
    },
    req,
  );
  return { done, out, prompt };
}

const opAnswers = (vault: string, go = 'y') => [
  { q: /^1Password service account token/, a: OP_TOKEN, secret: true },
  { q: /^Vault to use/, a: vault },
  { q: /^(Connect|Update) 1Password/, a: go },
];

const protonAnswers = (vault: string, go = 'y') => [
  { q: /^Vault to use/, a: vault },
  { q: /^(Connect|Update) Proton Pass/, a: go },
];

function everyFileText(mach: Machine): string {
  return mach.sys
    .allText()
    .map(([p, t]) => `${p}\n${t}`)
    .join('\n');
}

function modeOf(mach: Machine, path: string): number | undefined {
  return mach.sys.nodes.get(path)?.mode;
}

describe('password-source add 1password (Linux)', () => {
  it('seals the token, switches the drop-ins, pins op, restarts signer then core', async () => {
    const mach = machine('linux');
    const r = await connect(mach, opAnswers('Agent'), request({ kind: '1password' }));
    expect(r.done).toBe(true);
    expect(mach.config('signer').sources).toEqual({
      onePassword: {
        bin: OP_BIN,
        env: { HOME: mach.paths.signerData },
        sha256: OP_SHA,
        vault: 'Agent',
      },
    });
    expect(mach.config('core').passwordSource).toEqual({ kind: '1password' });
    mach.assertValid();
    expect(mach.sys.text(`${DROP_INS}/1password.conf`)).toBe(
      `[Service]\nLoadCredentialEncrypted=op-service-account-token:${mach.paths.opToken}\n`,
    );
    expect(mach.sys.exists(`${DROP_INS}/no-network.conf`)).toBe(false);
    expect(mach.commands().filter((c) => c[0] === 'systemctl' && c[1] !== 'is-active')).toEqual([
      ['systemctl', 'daemon-reload'],
      ['systemctl', 'restart', 'keyflap-signer', 'keyflap-core'],
    ]);
    expect(r.out).toContain('✓ 1Password connected, vault Agent.');
  });

  it('puts the token on stdin and in the check environment, never on a command line or in a readable file', async () => {
    const mach = machine('linux');
    await connect(mach, opAnswers('Agent'), request({ kind: '1password' }));
    expect(mach.allArgv()).not.toContain(OP_TOKEN);
    const seal = mach.calls.find((c) => c.cmd === 'systemd-creds');
    expect(seal?.args.slice(0, 4)).toEqual([
      'encrypt',
      '--with-key=auto',
      '--name=op-service-account-token',
      '-',
    ]);
    expect(seal?.opts.input).toBe(OP_TOKEN);
    const check = mach.calls.find((c) => c.cmd === OP_BIN);
    expect(check?.opts).toMatchObject({
      cleanEnv: true,
      uid: SIGNER_UID,
      gid: SIGNER_UID,
      env: { OP_SERVICE_ACCOUNT_TOKEN: OP_TOKEN, OP_CACHE: 'false' },
    });
    expect(everyFileText(mach)).not.toContain(OP_TOKEN);
    expect(modeOf(mach, mach.paths.opToken)).toBe(0o600);
    expect(mach.sys.nodes.get(mach.paths.opToken)?.uid).toBe(0);
    expect(mach.sys.exists(`${mach.paths.opToken}.tmp`)).toBe(false);
    expect(mach.sys.rootWrites.map((w) => w.path).sort()).toEqual(
      [mach.paths.coreConfig, mach.paths.signerConfig, `${DROP_INS}/1password.conf`].sort(),
    );
  });

  it('a token op refuses changes nothing', async () => {
    const mach = machine('linux');
    const before = mach.snapshot();
    const prompt = new ScriptedPrompter([
      { q: /^1Password service account token/, a: 'ops_wrong', secret: true },
    ]);
    await expect(
      connectPasswordSource(host(mach), { prompt, out: () => {} }, request({ kind: '1password' })),
    ).rejects.toThrow(/did not accept that token/);
    expect(mach.snapshot()).toBe(before);
    expect(mach.commands().some((c) => c[0] === 'systemctl')).toBe(false);
  });

  it('a vault it cannot see is refused before anything changes', async () => {
    const mach = machine('linux');
    const before = mach.snapshot();
    const prompt = new ScriptedPrompter([
      { q: /^1Password service account token/, a: OP_TOKEN, secret: true },
    ]);
    await expect(
      connectPasswordSource(
        host(mach),
        { prompt, out: () => {} },
        request({ kind: '1password', vault: 'Nope', interactive: false }),
      ),
    ).rejects.toThrow(/No vault named Nope/);
    expect(mach.snapshot()).toBe(before);
  });

  it('answering no at the end changes nothing', async () => {
    const mach = machine('linux');
    const before = mach.snapshot();
    const r = await connect(mach, opAnswers('Agent', 'n'), request({ kind: '1password' }));
    expect(r.done).toBe(false);
    expect(r.out).toContain('Nothing changed.');
    expect(mach.snapshot()).toBe(before);
  });

  it('a blank token stops without a trace', async () => {
    const mach = machine('linux');
    const before = mach.snapshot();
    const prompt = new ScriptedPrompter([
      { q: /^1Password service account token/, a: '', secret: true },
    ]);
    const done = await connectPasswordSource(
      host(mach),
      { prompt, out: () => {} },
      request({ kind: '1password' }),
    );
    expect(done).toBe(false);
    expect(mach.snapshot()).toBe(before);
  });

  it('a vault left blank means every vault', async () => {
    const mach = machine('linux');
    await connect(mach, opAnswers(''), request({ kind: '1password' }));
    expect(
      (mach.config('signer').sources as { onePassword: object }).onePassword,
    ).not.toHaveProperty('vault');
  });

  it('refuses when not root', async () => {
    const mach = machine('linux');
    mach.sys.uid = 1000;
    await expect(connect(mach, opAnswers('Agent'), request({ kind: '1password' }))).rejects.toThrow(
      /as root/,
    );
  });

  it('a restart that fails says so and leaves the saved settings valid', async () => {
    const mach = machine('linux');
    mach.failRestart = true;
    await expect(connect(mach, opAnswers('Agent'), request({ kind: '1password' }))).rejects.toThrow(
      /The restart failed/,
    );
    mach.assertValid();
    expect(connectedSource(mach.sys, mach.paths)?.kind).toBe('1password');
  });

  it('a seal that fails leaves the old state and never echoes the token', async () => {
    const mach = machine('linux');
    const exec = mach.sys.exec_;
    mach.sys.exec_ = (cmd, args, opts) =>
      cmd === 'systemd-creds'
        ? { code: 1, stdout: '', stderr: `Failed to encrypt ${opts.input}` }
        : exec(cmd, args, opts);
    const before = mach.snapshot();
    const err = await connect(mach, opAnswers('Agent'), request({ kind: '1password' })).catch(
      (e: Error) => e,
    );
    expect(err).toBeInstanceOf(PasswordSourceError);
    expect((err as Error).message).toMatch(/could not seal/);
    expect((err as Error).message).not.toContain(OP_TOKEN);
    expect(mach.snapshot()).toBe(before);
  });
});

describe('password-source add proton-pass (Linux)', () => {
  it('uses the existing login, drops the network restriction, pins pass-cli', async () => {
    const mach = machine('linux');
    mach.protonLoggedIn = true;
    const r = await connect(mach, protonAnswers('Agent'), request({ kind: 'proton-pass' }));
    expect(r.done).toBe(true);
    expect(mach.config('signer').sources).toEqual({
      protonPass: {
        bin: PASS_BIN,
        env: {
          HOME: mach.paths.signerData,
          PROTON_PASS_SESSION_DIR: `${mach.paths.signerData}/proton-pass`,
          PROTON_PASS_KEY_PROVIDER: 'fs',
        },
        sha256: PASS_SHA,
        vault: 'Agent',
      },
    });
    expect(mach.config('core').passwordSource).toEqual({ kind: 'proton-pass' });
    mach.assertValid();
    expect(mach.sys.exists(`${DROP_INS}/no-network.conf`)).toBe(false);
    expect(mach.sys.exists(`${DROP_INS}/1password.conf`)).toBe(false);
    expect(mach.sys.exists(mach.paths.opToken)).toBe(false);
  });

  it('logs in with a personal access token in the environment, as the signer, never on a command line', async () => {
    const mach = machine('linux');
    const r = await connect(
      mach,
      [
        { q: /^Proton Pass personal access token/, a: PROTON_TOKEN, secret: true },
        ...protonAnswers('Agent'),
      ],
      request({ kind: 'proton-pass' }),
    );
    expect(r.done).toBe(true);
    expect(mach.allArgv()).not.toContain(PROTON_TOKEN);
    const login = mach.calls.find((c) => c.cmd === PASS_BIN && c.args[0] === 'login');
    expect(login?.opts).toMatchObject({
      cleanEnv: true,
      uid: SIGNER_UID,
      env: { PROTON_PASS_PERSONAL_ACCESS_TOKEN: PROTON_TOKEN },
    });
    expect(everyFileText(mach)).not.toContain(PROTON_TOKEN);
  });

  it('a token pass-cli refuses changes nothing', async () => {
    const mach = machine('linux');
    const before = mach.snapshot();
    const prompt = new ScriptedPrompter([
      { q: /^Proton Pass personal access token/, a: 'nope', secret: true },
    ]);
    await expect(
      connectPasswordSource(
        host(mach),
        { prompt, out: () => {} },
        request({ kind: 'proton-pass' }),
      ),
    ).rejects.toThrow(/could not log in/);
    expect(mach.snapshot()).toBe(before);
  });
});

describe('the Proton Pass bug: choosing Proton Pass while 1Password is connected', () => {
  it('walks into connecting it, asks before replacing, and ends with Proton Pass only', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    mach.protonLoggedIn = true;
    const r = await connect(
      mach,
      [{ q: /^Replace 1Password\?/, a: 'y' }, ...protonAnswers('Agent', 'y').slice(0, 1)],
      request({ kind: 'proton-pass' }),
    );
    expect(r.done).toBe(true);
    expect(r.out).not.toMatch(/install\.sh/);
    expect(connectedSource(mach.sys, mach.paths)).toMatchObject({
      kind: 'proton-pass',
      vault: 'Agent',
    });
    expect(mach.config('signer').sources).not.toHaveProperty('onePassword');
    expect(mach.sys.exists(mach.paths.opToken)).toBe(false);
    expect(mach.sys.exists(`${DROP_INS}/1password.conf`)).toBe(false);
    expect(mach.sys.exists(`${DROP_INS}/no-network.conf`)).toBe(false);
    mach.assertValid();
  });

  it('the question says what happens to the old logins, and no is the default', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    const before = mach.snapshot();
    const asked: string[] = [];
    const prompt = new ScriptedPrompter([{ q: /^Replace 1Password\?/, a: '' }]);
    const ask = prompt.ask.bind(prompt);
    prompt.ask = async (q, d) => {
      asked.push(q);
      return ask(q, d);
    };
    const r = await connectPasswordSource(
      host(mach),
      { prompt, out: () => {} },
      request({ kind: 'proton-pass' }),
    );
    expect(r).toBe(false);
    expect(asked[0]).toBe(
      'Replace 1Password? Agents stop using its logins. They stay in 1Password, and Keyflap deletes its copy of the token. [y/N]',
    );
    expect(mach.snapshot()).toBe(before);
  });

  it('replacing Proton Pass with 1Password deletes nothing in the vault and signs pass-cli out', async () => {
    const mach = machine('linux', { source: 'proton-pass', vault: 'Agent' });
    const r = await connect(
      mach,
      [{ q: /^Replace Proton Pass\?/, a: 'y' }, ...opAnswers('Agent').slice(0, 2)],
      request({ kind: '1password' }),
    );
    expect(r.done).toBe(true);
    expect(mach.protonLoggedIn).toBe(false);
    expect(mach.config('signer').sources).not.toHaveProperty('protonPass');
    expect(mach.sys.exists(mach.paths.opToken)).toBe(true);
    expect(mach.sys.exists(`${DROP_INS}/1password.conf`)).toBe(true);
  });

  it('a script without a terminal must pass --yes to replace', async () => {
    const mach = machine('linux', { source: '1password' });
    const before = mach.snapshot();
    const err = await connect(
      mach,
      [],
      request({ kind: 'proton-pass', interactive: false, confirmConnect: false }),
    ).catch((e: PasswordSourceError) => e);
    expect(err).toBeInstanceOf(PasswordSourceError);
    expect((err as PasswordSourceError).fix).toBe('add --yes to replace it');
    expect(mach.snapshot()).toBe(before);
    mach.protonLoggedIn = true;
    const ok = await connect(
      mach,
      [],
      request({ kind: 'proton-pass', interactive: false, confirmConnect: false, yes: true }),
    );
    expect(ok.done).toBe(true);
  });
});

describe('password-source remove', () => {
  it('1Password on Linux: no source, network closed again, token gone, then restarted', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    const out: string[] = [];
    expect(await disconnectPasswordSource(host(mach), (t) => out.push(t))).toBe(true);
    expect(mach.config('signer')).not.toHaveProperty('sources');
    expect(mach.config('core').passwordSource).toBeNull();
    mach.assertValid();
    expect(mach.sys.text(`${DROP_INS}/no-network.conf`)).toBe(NO_NETWORK);
    expect(mach.sys.exists(`${DROP_INS}/1password.conf`)).toBe(false);
    expect(mach.sys.exists(mach.paths.opToken)).toBe(false);
    expect(mach.commands().filter((c) => c[0] === 'systemctl' && c[1] !== 'is-active')).toEqual([
      ['systemctl', 'daemon-reload'],
      ['systemctl', 'restart', 'keyflap-signer', 'keyflap-core'],
    ]);
    expect(out.join('')).toContain('✓ 1Password disconnected.');
  });

  it('Proton Pass: back to no network, and pass-cli is signed out as the signer', async () => {
    const mach = machine('linux', { source: 'proton-pass' });
    await disconnectPasswordSource(host(mach), () => {});
    expect(mach.sys.text(`${DROP_INS}/no-network.conf`)).toBe(NO_NETWORK);
    expect(mach.protonLoggedIn).toBe(false);
    const logout = mach.calls.find((c) => c.args[0] === 'logout');
    expect(logout?.opts).toMatchObject({ uid: SIGNER_UID, cleanEnv: true });
  });

  it('add then remove returns the machine to where it began', async () => {
    const mach = machine('linux');
    const files = () =>
      mach.sys
        .allText()
        .map(([p]) => p)
        .sort();
    const before = files();
    await connect(mach, opAnswers('Agent'), request({ kind: '1password' }));
    expect(files()).not.toEqual(before);
    await disconnectPasswordSource(host(mach), () => {});
    expect(files()).toEqual(before);
    expect(mach.sys.text(`${DROP_INS}/no-network.conf`)).toBe(NO_NETWORK);
    expect(mach.config('signer')).not.toHaveProperty('sources');
  });

  it('with nothing connected it says so, repairs the drop-ins and restarts nothing', async () => {
    const mach = machine('linux');
    mach.sys.removeRootFile(`${DROP_INS}/no-network.conf`);
    const out: string[] = [];
    expect(await disconnectPasswordSource(host(mach), (t) => out.push(t))).toBe(false);
    expect(out.join('')).toContain('No password manager is connected.');
    expect(mach.sys.text(`${DROP_INS}/no-network.conf`)).toBe(NO_NETWORK);
    expect(mach.commands().some((c) => c[1] === 'restart')).toBe(false);
  });

  it('is idempotent after a half-finished run (config already cleared, token still there)', async () => {
    const mach = machine('linux', { source: '1password' });
    const core = mach.config('core');
    core.passwordSource = null;
    mach.sys.file(mach.paths.coreConfig, JSON.stringify(core), 0o644, 0);
    const signer = mach.config('signer');
    delete signer.sources;
    mach.sys.file(mach.paths.signerConfig, JSON.stringify(signer), 0o644, 0);
    await disconnectPasswordSource(host(mach), () => {});
    expect(mach.sys.exists(mach.paths.opToken)).toBe(false);
    expect(mach.sys.exists(`${DROP_INS}/1password.conf`)).toBe(false);
    expect(mach.sys.text(`${DROP_INS}/no-network.conf`)).toBe(NO_NETWORK);
  });
});

describe('a tool Keyflap would not trust', () => {
  it('outside the root-only places: refused with the fix, nothing changed', async () => {
    const mach = machine('linux');
    mach.sys.tools.delete(OP_BIN);
    const before = mach.snapshot();
    const err = await connect(mach, [], request({ kind: '1password' })).catch(
      (e: PasswordSourceError) => e,
    );
    expect(err).toBeInstanceOf(PasswordSourceError);
    expect((err as Error).message).toContain('not trusted');
    expect(mach.snapshot()).toBe(before);
    expect(mach.calls.filter((c) => c.cmd === OP_BIN)).toEqual([]);
  });

  it('a path given with --bin is checked the same way', async () => {
    const mach = machine('linux');
    mach.sys.file('/home/u/op', '#!/bin/sh\n', 0o755, 1000);
    mach.sys.tools.set('/home/u/op', {
      ok: false,
      problem: 'untrusted',
      detail: '/home/u/op is not in a system bin directory',
      fix: 'install op as root',
    } as never);
    const err = await connect(mach, [], request({ kind: '1password', bin: '/home/u/op' })).catch(
      (e: PasswordSourceError) => e,
    );
    expect((err as Error).message).toContain('not in a system bin directory');
    expect((err as PasswordSourceError).fix).toBe('install op as root');
  });

  it('missing everywhere: names the places, and the fix is the command, not install.sh', async () => {
    const mach = machine('linux');
    mach.sys.nodes.delete(OP_BIN);
    const err = await connect(mach, [], request({ kind: '1password' })).catch(
      (e: PasswordSourceError) => e,
    );
    expect((err as Error).message).toBe(
      'op is not installed where Keyflap trusts it: /opt/keyflap/tools/op/, /usr/local/bin or /usr/bin',
    );
    expect(`${(err as Error).message}${(err as PasswordSourceError).fix}`).not.toContain(
      'install.sh',
    );
  });

  it('takes the first root-only tool in the search order', async () => {
    const mach = machine('linux');
    mach.sys.dir('/usr/bin', 0o755, 0);
    mach.sys.file('/usr/bin/op', '#!/bin/sh\n', 0o755, 0);
    mach.sys.tools.set('/usr/bin/op', { ok: true, path: '/usr/bin/op', sha256: 'e'.repeat(64) });
    await connect(mach, opAnswers('Agent'), request({ kind: '1password' }));
    expect(
      (mach.config('signer').sources as { onePassword: { bin: string } }).onePassword.bin,
    ).toBe(OP_BIN);
  });
});

describe('password-source on macOS', () => {
  it('writes the token as a 0400 file owned by _keyflap-signer, touches no drop-ins, kickstarts signer then core', async () => {
    const mach = machine('darwin');
    const r = await connect(mach, opAnswers('Agent'), request({ kind: '1password' }));
    expect(r.done).toBe(true);
    expect(mach.sys.text(mach.paths.opToken)).toBe(OP_TOKEN);
    expect(mach.sys.rootWrites.find((w) => w.path === mach.paths.opToken)).toEqual({
      path: mach.paths.opToken,
      mode: 0o400,
      owner: { uid: MAC_SIGNER_UID, gid: MAC_SIGNER_UID },
    });
    expect(mach.allArgv()).not.toContain(OP_TOKEN);
    expect(mach.sys.exists(DROP_INS)).toBe(false);
    expect(mach.commands().filter((c) => c[0] === 'launchctl' && c[1] === 'kickstart')).toEqual([
      ['launchctl', 'kickstart', '-k', 'system/com.keyflap.signer'],
      ['launchctl', 'kickstart', '-k', 'system/com.keyflap.core'],
    ]);
    expect(mach.calls.find((c) => c.cmd === OP_BIN)?.opts).toMatchObject({
      uid: MAC_SIGNER_UID,
      cleanEnv: true,
    });
    mach.assertValid();
  });

  it('remove deletes the token file and clears both configs', async () => {
    const mach = machine('darwin', { source: '1password', vault: 'Agent' });
    await disconnectPasswordSource(host(mach), () => {});
    expect(mach.sys.exists(mach.paths.opToken)).toBe(false);
    expect(mach.config('core').passwordSource).toBeNull();
    expect(mach.config('signer')).not.toHaveProperty('sources');
    mach.assertValid();
  });

  it('Proton Pass logs in as _keyflap-signer with the Mac session folder', async () => {
    const mach = machine('darwin');
    await connect(
      mach,
      [
        { q: /^Proton Pass personal access token/, a: PROTON_TOKEN, secret: true },
        ...protonAnswers('Agent'),
      ],
      request({ kind: 'proton-pass' }),
    );
    const login = mach.calls.find((c) => c.cmd === PASS_BIN && c.args[0] === 'login');
    expect(login?.opts).toMatchObject({
      uid: MAC_SIGNER_UID,
      env: {
        HOME: '/Library/Keyflap/data/signer',
        PROTON_PASS_SESSION_DIR: '/Library/Keyflap/data/signer/proton-pass',
      },
    });
    expect(mach.sys.exists(mach.paths.opToken)).toBe(false);
  });
});

describe('the drop-ins are the ones install.sh writes', () => {
  const install = readFileSync(
    join(import.meta.dirname, '..', '..', 'install', 'linux', 'install.sh'),
    'utf8',
  );
  const heredoc = (name: string) => {
    const m = new RegExp(`${name} <<'EOF'\\n([\\s\\S]*?)\\nEOF`).exec(install);
    if (!m) throw new Error(`no heredoc for ${name}`);
    return `${m[1]}\n`;
  };

  it('no-network.conf', async () => {
    const mach = machine('linux', { source: '1password' });
    await disconnectPasswordSource(host(mach), () => {});
    expect(mach.sys.text(`${DROP_INS}/no-network.conf`)).toBe(heredoc('no-network.conf'));
  });

  it('1password.conf', async () => {
    const mach = machine('linux');
    await connect(mach, opAnswers('Agent'), request({ kind: '1password' }));
    expect(mach.sys.text(`${DROP_INS}/1password.conf`)).toBe(heredoc('1password.conf'));
  });
});

describe('against the fake op from @aab/sources/testing', () => {
  it('the token reaches op in its environment only, and a wrong one is refused', async () => {
    const op = fakeOp({
      token: OP_TOKEN,
      vaults: [{ id: 'a'.repeat(26), name: 'Agent', items: [] }],
    });
    const mach = machine('linux');
    const base = mach.sys.exec_;
    mach.sys.exec_ = (cmd, args, opts) => {
      if (cmd !== OP_BIN) return base(cmd, args, opts);
      const r = spawnSync(process.execPath, [op.bin, ...args], {
        env: { ...opts.env, KEYFLAP_FAKE_OP_DIR: op.dir },
        encoding: 'utf8',
      });
      return { code: r.status, stdout: r.stdout, stderr: r.stderr };
    };
    const ok = await connect(
      mach,
      [
        { q: /^1Password service account token/, a: OP_TOKEN, secret: true },
        { q: /^Vault to use/, a: 'Agent' },
        { q: /^Connect 1Password/, a: 'y' },
      ],
      request({ kind: '1password' }),
    ).catch((e: Error) => e);
    expect(ok).not.toBeInstanceOf(Error);
    expect(op.calls().map((c) => c.argv)).toEqual([['vault', 'list', '--format=json']]);
    expect(JSON.stringify(op.calls())).not.toContain(OP_TOKEN);
    const bad = machine('linux');
    bad.sys.exec_ = mach.sys.exec_;
    await expect(
      connect(
        bad,
        [{ q: /^1Password service account token/, a: 'ops_wrong', secret: true }],
        request({ kind: '1password' }),
      ),
    ).rejects.toThrow(/did not accept that token/);
  });
});

describe('the root file writes', () => {
  it('write a 0400 file atomically with no temporary left, and replace an existing one', () => {
    const dir = tmpDir();
    const sys = realSystem();
    const path = join(dir, 'op-service-account-token');
    const me = { uid: process.getuid?.() ?? 0, gid: process.getgid?.() ?? 0 };
    sys.writeRootFile(path, 'first', { mode: 0o400, owner: me });
    expect(readFileSync(path, 'utf8')).toBe('first');
    expect(statSync(path).mode & 0o7777).toBe(0o400);
    sys.writeRootFile(path, 'second', { mode: 0o400, owner: me });
    expect(readFileSync(path, 'utf8')).toBe('second');
    expect(statSync(path).mode & 0o7777).toBe(0o400);
    expect(sys.exists(`${path}.tmp-${process.pid}`)).toBe(false);
  });

  it('promote a sealed file to 0600 and remove one that is not there', () => {
    const dir = tmpDir();
    const sys = realSystem();
    const tmp = join(dir, 'x.cred.tmp');
    writeFileSync(tmp, 'sealed', { mode: 0o644 });
    sys.promoteRootFile(tmp, join(dir, 'x.cred'), 0o600);
    expect(statSync(join(dir, 'x.cred')).mode & 0o7777).toBe(0o600);
    expect(sys.exists(tmp)).toBe(false);
    sys.removeRootFile(join(dir, 'x.cred'));
    sys.removeRootFile(join(dir, 'x.cred'));
    expect(sys.exists(join(dir, 'x.cred'))).toBe(false);
  });

  it('do not follow a symbolic link planted where the temporary file goes', () => {
    const dir = tmpDir();
    const sys = realSystem();
    const victim = join(dir, 'victim');
    writeFileSync(victim, 'keep');
    const path = join(dir, 'f');
    symlinkSync(victim, `${path}.tmp-${process.pid}`);
    sys.writeRootFile(path, 'a', { mode: 0o600 });
    expect(readFileSync(victim, 'utf8')).toBe('keep');
    expect(readFileSync(path, 'utf8')).toBe('a');
    expect(lstatSync(path).isSymbolicLink()).toBe(false);
  });
});

describe('applyConnect checks its own input', () => {
  it('1Password without a token and a vault name that is too long are refused', async () => {
    const mach = machine('linux');
    const base = { kind: '1password' as const, bin: OP_BIN, sha256: OP_SHA, vault: null };
    await expect(applyConnect(host(mach), { ...base, token: null }, () => {})).rejects.toThrow(
      /needs its service account token/,
    );
    await expect(
      applyConnect(host(mach), { ...base, vault: 'x'.repeat(201), token: OP_TOKEN }, () => {}),
    ).rejects.toThrow(/1 to 200 characters/);
    expect(SOURCES['1password'].name).toBe('1Password');
  });
});

type Cfg = { sources: Record<string, { bin: string; sha256: string; vault?: string }> };
const sourceOf = (mach: Machine, key: 'onePassword' | 'protonPass') =>
  (mach.config('signer') as unknown as Cfg).sources[key];
const OTHER_SHA = 'e'.repeat(64);

describe('re-adding the connected manager keeps its vault limit', () => {
  it('without --vault and without a terminal, 1Password keeps the vault and says so', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    const r = await connect(
      mach,
      [{ q: /^1Password service account token/, a: OP_TOKEN, secret: true }],
      request({ kind: '1password', interactive: false, confirmConnect: false }),
    );
    expect(sourceOf(mach, 'onePassword')?.vault).toBe('Agent');
    expect(r.out).toContain('1Password connected, vault Agent.');
  });

  it('Proton Pass keeps it too', async () => {
    const mach = machine('linux', { source: 'proton-pass', vault: 'Agent' });
    const r = await connect(
      mach,
      [],
      request({ kind: 'proton-pass', interactive: false, confirmConnect: false }),
    );
    expect(sourceOf(mach, 'protonPass')?.vault).toBe('Agent');
    expect(r.out).toContain('vault Agent');
  });

  it('on a terminal the vault question offers the current vault, and blank keeps it', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    const prompt = new ScriptedPrompter([
      { q: /^1Password service account token/, a: OP_TOKEN, secret: true },
      { q: /^Vault to use \(blank: Agent/, a: '' },
    ]);
    const defaults: (string | undefined)[] = [];
    const ask = prompt.ask.bind(prompt);
    prompt.ask = async (q, d) => {
      defaults.push(d);
      return ask(q, d);
    };
    await connectPasswordSource(
      host(mach),
      { prompt, out: () => {} },
      request({ kind: '1password', confirmConnect: false }),
    );
    expect(defaults[0]).toBe('Agent');
    expect(sourceOf(mach, 'onePassword')?.vault).toBe('Agent');
  });

  it('"all" lifts the limit, and the success text says every vault', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    const r = await connect(
      mach,
      [
        { q: /^1Password service account token/, a: OP_TOKEN, secret: true },
        { q: /^Vault to use/, a: 'all' },
      ],
      request({ kind: '1password', confirmConnect: false }),
    );
    expect(sourceOf(mach, 'onePassword')).not.toHaveProperty('vault');
    expect(r.out).toContain('1Password connected, every vault.');
  });

  it('the confirmation names the scope, including every vault', async () => {
    const fresh = machine('linux');
    const asked: string[] = [];
    const prompt = new ScriptedPrompter([
      { q: /^1Password service account token/, a: OP_TOKEN, secret: true },
      { q: /^Vault to use/, a: '' },
      { q: /^Connect 1Password \(every vault\)\?/, a: 'n' },
    ]);
    const ask = prompt.ask.bind(prompt);
    prompt.ask = async (q, d) => {
      asked.push(q);
      return ask(q, d);
    };
    await connectPasswordSource(
      host(fresh),
      { prompt, out: () => {} },
      request({ kind: '1password' }),
    );
    expect(asked.at(-1)).toBe('Connect 1Password (every vault)? [y/N]');
  });

  it('a vault the credential can no longer see is an error, not a quiet widening', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Gone' });
    const before = mach.snapshot();
    const err = await connect(
      mach,
      [{ q: /^1Password service account token/, a: OP_TOKEN, secret: true }],
      request({ kind: '1password', interactive: false, confirmConnect: false }),
    ).catch((e: PasswordSourceError) => e);
    expect((err as Error).message).toContain('No vault named Gone');
    expect(mach.snapshot()).toBe(before);
  });

  it('a different manager does not inherit the old vault', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    mach.protonLoggedIn = true;
    await connect(
      mach,
      [
        { q: /^Replace 1Password\?/, a: 'y' },
        { q: /^Vault to use \(blank: every vault/, a: '' },
      ],
      request({ kind: 'proton-pass' }),
    );
    expect(sourceOf(mach, 'protonPass')).not.toHaveProperty('vault');
  });
});

describe('the signer network follows the saved settings, never ahead of them', () => {
  const failOn = (mach: Machine, path: string) => {
    const w = mach.sys.writeRootFile.bind(mach.sys);
    mach.sys.writeRootFile = (p, d, o) => {
      if (p === path) throw new Error('disk full');
      w(p, d, o);
    };
  };

  it('connect writes both configs before it opens the network', async () => {
    const mach = machine('linux');
    await connect(mach, opAnswers('Agent'), request({ kind: '1password' }));
    const order = mach.sys.rootWrites.map((w) => w.path);
    const opened = order.indexOf(`${DROP_INS}/1password.conf`);
    expect(opened).toBeGreaterThan(order.indexOf(mach.paths.signerConfig));
    expect(opened).toBeGreaterThan(order.indexOf(mach.paths.coreConfig));
  });

  it('a config write that fails during connect leaves the network closed', async () => {
    const mach = machine('linux');
    failOn(mach, mach.paths.signerConfig);
    await expect(connect(mach, opAnswers('Agent'), request({ kind: '1password' }))).rejects.toThrow(
      /disk full/,
    );
    expect(mach.sys.exists(`${DROP_INS}/no-network.conf`)).toBe(true);
    expect(mach.sys.exists(`${DROP_INS}/1password.conf`)).toBe(false);
  });

  it('remove closes the network before it clears the configs', async () => {
    const mach = machine('linux', { source: '1password' });
    await disconnectPasswordSource(host(mach), () => {});
    const order = mach.sys.rootWrites.map((w) => w.path);
    expect(order.indexOf(`${DROP_INS}/no-network.conf`)).toBeLessThan(
      order.indexOf(mach.paths.coreConfig),
    );
    expect(order.indexOf(`${DROP_INS}/no-network.conf`)).toBeLessThan(
      order.indexOf(mach.paths.signerConfig),
    );
  });

  it('a config write that fails during remove leaves the network closed', async () => {
    const mach = machine('linux', { source: '1password' });
    failOn(mach, mach.paths.signerConfig);
    await expect(disconnectPasswordSource(host(mach), () => {})).rejects.toThrow(/disk full/);
    expect(mach.sys.exists(`${DROP_INS}/no-network.conf`)).toBe(true);
    expect(mach.sys.exists(`${DROP_INS}/1password.conf`)).toBe(false);
  });
});

describe('not root: a person is told before anything is asked or run', () => {
  it('connect asks nothing, runs nothing and changes nothing', async () => {
    const mach = machine('linux');
    mach.sys.uid = 1000;
    const before = mach.snapshot();
    const prompt = new ScriptedPrompter([]);
    const err = await connectPasswordSource(
      host(mach),
      { prompt, out: () => {} },
      request({ kind: '1password' }),
    ).catch((e: Error) => e);
    expect(err).toBeInstanceOf(PasswordSourceError);
    expect((err as Error).message).toBe('Run this as root: sudo keyflap …');
    expect(prompt.asked).toEqual([]);
    expect(mach.calls).toEqual([]);
    expect(mach.snapshot()).toBe(before);
  });

  it('remove says the same and runs nothing', async () => {
    const mach = machine('linux', { source: '1password' });
    mach.sys.uid = 1000;
    await expect(disconnectPasswordSource(host(mach), () => {})).rejects.toThrow(/as root/);
    expect(mach.calls).toEqual([]);
  });
});

describe('Proton Pass sign-out is never silent', () => {
  const token = { q: /^Proton Pass personal access token/, a: PROTON_TOKEN, secret: true };

  it('answering no after the login signs the fresh session out again', async () => {
    const mach = machine('linux');
    const r = await connect(
      mach,
      [token, { q: /^Vault to use/, a: 'Agent' }, { q: /^Connect Proton Pass/, a: 'n' }],
      request({ kind: 'proton-pass' }),
    );
    expect(r.done).toBe(false);
    expect(mach.protonLoggedIn).toBe(false);
  });

  it('a session that was already there is left alone when the answer is no', async () => {
    const mach = machine('linux');
    mach.protonLoggedIn = true;
    await connect(
      mach,
      [
        { q: /^Vault to use/, a: 'Agent' },
        { q: /^Connect Proton Pass/, a: 'n' },
      ],
      request({ kind: 'proton-pass' }),
    );
    expect(mach.protonLoggedIn).toBe(true);
  });

  it('says so when the fresh session cannot be signed out', async () => {
    const mach = machine('linux');
    const exec = mach.sys.exec_;
    mach.sys.exec_ = (cmd, args, opts) =>
      cmd === PASS_BIN && args[0] === 'logout'
        ? { code: 1, stdout: '', stderr: 'no' }
        : exec(cmd, args, opts);
    const r = await connect(
      mach,
      [token, { q: /^Vault to use/, a: 'Agent' }, { q: /^Connect Proton Pass/, a: 'n' }],
      request({ kind: 'proton-pass' }),
    );
    expect(r.out).toContain('still signed in to Proton Pass');
  });

  it('switching away says so when pass-cli changed since it was trusted', async () => {
    const mach = machine('linux', { source: 'proton-pass', vault: 'Agent' });
    mach.sys.tools.set(PASS_BIN, { ok: true, path: PASS_BIN, sha256: OTHER_SHA });
    const r = await connect(
      mach,
      [{ q: /^Replace Proton Pass\?/, a: 'y' }, ...opAnswers('Agent').slice(0, 2)],
      request({ kind: '1password' }),
    );
    expect(r.done).toBe(true);
    expect(mach.protonLoggedIn).toBe(true);
    expect(r.out).toContain('still signed in to Proton Pass');
    expect(r.out).toContain('changed since it was trusted');
  });

  it('removing says so when the logout command cannot run', async () => {
    const mach = machine('linux', { source: 'proton-pass' });
    const exec = mach.sys.exec_;
    mach.sys.exec_ = (cmd, args, opts) => {
      if (cmd === PASS_BIN && args[0] === 'logout') throw new Error('spawn failed');
      return exec(cmd, args, opts);
    };
    let out = '';
    await disconnectPasswordSource(host(mach), (t) => {
      out += t;
    });
    expect(out).toContain('still signed in to Proton Pass');
  });
});

describe('re-adding the connected manager keeps its tool', () => {
  const ELSEWHERE = '/usr/local/bin/op';
  function connectedElsewhere() {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    mach.sys.dir('/usr/local/bin', 0o755, 0);
    mach.sys.file(ELSEWHERE, '#!/bin/sh\n', 0o755, 0);
    mach.sys.tools.set(ELSEWHERE, { ok: true, path: ELSEWHERE, sha256: OP_SHA });
    const cfg = mach.config('signer') as unknown as Cfg;
    (cfg.sources.onePassword as { bin: string }).bin = ELSEWHERE;
    const exec = mach.sys.exec_;
    mach.sys.exec_ = (cmd, args, opts) => exec(cmd === ELSEWHERE ? OP_BIN : cmd, args, opts);
    mach.sys.file(mach.paths.signerConfig, `${JSON.stringify(cfg, null, 2)}\n`, 0o644, 0);
    return mach;
  }
  const tokenOnly = [{ q: /^1Password service account token/, a: OP_TOKEN, secret: true }];

  it('stays on the configured binary even when a default location also has one', async () => {
    const mach = connectedElsewhere();
    await connect(
      mach,
      tokenOnly,
      request({ kind: '1password', interactive: false, confirmConnect: false }),
    );
    expect(sourceOf(mach, 'onePassword')?.bin).toBe(ELSEWHERE);
  });

  it('a changed binary is not re-pinned without the warning and a yes', async () => {
    const mach = connectedElsewhere();
    mach.sys.tools.set(ELSEWHERE, { ok: true, path: ELSEWHERE, sha256: OTHER_SHA });
    const before = mach.snapshot();
    const prompt = new ScriptedPrompter([{ q: /^op changed since it was trusted/, a: '' }]);
    let out = '';
    const r = await connectPasswordSource(
      host(mach),
      { prompt, out: (t) => (out += t) },
      request({ kind: '1password', confirmConnect: false }),
    );
    expect(r).toBe(false);
    expect(out).toContain('Make sure it is genuine');
    expect(out).toContain(OP_SHA);
    expect(out).toContain(OTHER_SHA);
    expect(mach.snapshot()).toBe(before);
  });

  it('without a terminal it needs --yes, and with it prints the same warning and re-pins', async () => {
    const mach = connectedElsewhere();
    mach.sys.tools.set(ELSEWHERE, { ok: true, path: ELSEWHERE, sha256: OTHER_SHA });
    const refused = await connect(
      mach,
      tokenOnly,
      request({ kind: '1password', interactive: false, confirmConnect: false }),
    ).catch((e: PasswordSourceError) => e);
    expect((refused as PasswordSourceError).fix).toContain('--yes');
    const ok = await connect(
      mach,
      tokenOnly,
      request({ kind: '1password', interactive: false, confirmConnect: false, yes: true }),
    );
    expect(ok.out).toContain('Make sure it is genuine');
    expect(sourceOf(mach, 'onePassword')?.sha256).toBe(OTHER_SHA);
  });

  it('an unchanged binary needs no extra question', async () => {
    const mach = connectedElsewhere();
    const r = await connect(
      mach,
      tokenOnly,
      request({ kind: '1password', interactive: false, confirmConnect: false }),
    );
    expect(r.out).not.toContain('Make sure it is genuine');
  });

  it('a configured binary that is gone falls back to the usual places', async () => {
    const mach = connectedElsewhere();
    mach.sys.removeRootFile(ELSEWHERE);
    await connect(
      mach,
      tokenOnly,
      request({ kind: '1password', interactive: false, confirmConnect: false }),
    );
    expect(sourceOf(mach, 'onePassword')?.bin).toBe(OP_BIN);
  });
});

describe('connecting what is already connected and working', () => {
  it('says so, and does not ask for the token unless the person wants to change it', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    const before = mach.snapshot();
    const r = await connect(mach, [{ q: /^Change it\?/, a: '' }], request({ kind: '1password' }));
    expect(r.done).toBe(false);
    expect(r.out).toContain('1Password is connected, vault Agent.');
    expect(r.out).toContain('Nothing changed.');
    expect(mach.snapshot()).toBe(before);
  });

  it('yes goes on to the token', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    const r = await connect(
      mach,
      [{ q: /^Change it\?/, a: 'y' }, ...opAnswers('all')],
      request({ kind: '1password' }),
    );
    expect(r.done).toBe(true);
    expect(sourceOf(mach, 'onePassword')).not.toHaveProperty('vault');
  });

  it('Proton Pass logged in and working is the same', async () => {
    const mach = machine('linux', { source: 'proton-pass', vault: 'Agent' });
    const r = await connect(mach, [{ q: /^Change it\?/, a: '' }], request({ kind: 'proton-pass' }));
    expect(r.done).toBe(false);
    expect(r.out).toContain('Proton Pass is connected, vault Agent.');
  });

  it('a connection that is not working goes straight on', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    mach.sys.removeRootFile(mach.paths.opToken);
    const r = await connect(mach, [...opAnswers('Agent', 'y')], request({ kind: '1password' }));
    expect(r.done).toBe(true);
  });

  it('the command (no console confirmation) is an explicit request and goes straight on', async () => {
    const mach = machine('linux', { source: '1password', vault: 'Agent' });
    const r = await connect(
      mach,
      [
        { q: /^1Password service account token/, a: OP_TOKEN, secret: true },
        { q: /^Vault to use/, a: '' },
      ],
      request({ kind: '1password', confirmConnect: false }),
    );
    expect(r.done).toBe(true);
  });
});

describe('the command line does not hang on an open stdin', () => {
  const script = (body: string) => {
    const dir = tmpDir();
    const file = join(dir, 'probe.ts');
    const flow = join(import.meta.dirname, '..', 'src', 'setup', 'password-source-flow.ts');
    writeFileSync(file, `import { cliPrompter } from '${flow}';\n${body}\n`);
    return file;
  };
  const exits = (file: string, feed: string | null) =>
    new Promise<{ code: number | null; out: string }>((resolve) => {
      const child = spawn(process.execPath, [file], { stdio: ['pipe', 'pipe', 'inherit'] });
      let out = '';
      child.stdout.on('data', (d) => (out += d));
      if (feed !== null) child.stdin.write(feed);
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        resolve({ code: null, out });
      }, 8_000);
      child.on('exit', (code) => {
        clearTimeout(timer);
        resolve({ code, out });
      });
    });

  it('a prompter nobody asks leaves the process free to exit', async () => {
    const r = await exits(script("cliPrompter();\nconsole.log('made');"), null);
    expect(r).toEqual({ code: 0, out: 'made\n' });
  }, 15_000);

  it('after the last answer, closing it lets the process exit', async () => {
    const r = await exits(
      script("const p = cliPrompter();\nconsole.log(await p.secret('token'));\np.close();"),
      'sekrit\n',
    );
    expect(r).toEqual({ code: 0, out: 'sekrit\n' });
  }, 15_000);
});
