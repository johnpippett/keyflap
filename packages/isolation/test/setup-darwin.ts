import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, openSync, rmSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { join } from 'node:path';
import type { DarwinRelease, IsolationEnv } from './global-setup.ts';
import {
  darwinHost,
  type Host,
  L,
  LABELS,
  REPO,
  servicePids,
  sha256,
  waitReady,
} from './platform.ts';

export const DARWIN_STAGE = '/var/root/keyflap-isolation';
const ORIGIN = 'http://approver.localhost:8766';
const VERSION = '0.0.0-isolation';
const NAME = `keyflap-${VERSION}-darwin-arm64`;
const KEYFLAP = '/usr/local/bin/keyflap';
const PLISTS = Object.values(LABELS).map((l) => `/Library/LaunchDaemons/${l}.plist`);
const NOTHING_INSTALLED = `test ! -e /opt/keyflap && test ! -e /Library/Keyflap && test ! -e ${KEYFLAP} && ${PLISTS.map((p) => `test ! -e ${p}`).join(' && ')}`;

const PROBE_USER_SCRIPT = `set -eu
u=$1
if ! dscl . -read /Users/$u UniqueID >/dev/null 2>&1; then
  used=$( { dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}')
  id=499
  while printf '%s\\n' $used | grep -qx "$id"; do id=$((id - 1)); done
  [ "$id" -ge 400 ] || { echo "no free uid for $u" >&2; exit 1; }
  dscl . -create /Users/$u
  dscl . -create /Users/$u UniqueID "$id"
fi
for pair in PrimaryGroupID=20 UserShell=/usr/bin/false NFSHomeDirectory=/var/empty IsHidden=1 'Password=*'; do
  if dscl . -read /Users/$u "\${pair%%=*}" 2>&1 | grep -q '^No such key'; then
    dscl . -create /Users/$u "\${pair%%=*}" "\${pair#*=}"
  fi
done
if dscl . -read /Users/$u RealName 2>&1 | grep -q '^No such key'; then
  dscl . -create /Users/$u RealName 'Keyflap isolation probe'
fi
dscacheutil -flushcache
[ "$(dscl . -read /Users/$u UserShell | sed -n 's/^UserShell: //p')" = /usr/bin/false ]
id -u $u
`;

function sh(h: Host, script: string, opts: { timeoutMs?: number } = {}) {
  return h.exec(['bash', '-c', script], { timeoutMs: opts.timeoutMs ?? 120_000 });
}

function must(h: Host, script: string, timeoutMs = 120_000): string {
  const r = sh(h, script, { timeoutMs });
  if (r.status !== 0)
    throw new Error(`${script.slice(0, 200)} failed (${r.status}):\n${r.stdout}\n${r.stderr}`);
  return r.stdout;
}

function waitFor(what: string, ok: () => boolean, ms: number) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (ok()) return;
    spawnSync('sleep', ['0.5']);
  }
  throw new Error(`timed out waiting for ${what}`);
}

function installArgs(extra: string[] = []): string[] {
  return [
    '--user',
    L.agentUser,
    '--approver-origin',
    ORIGIN,
    '--high-risk',
    'rp.localhost',
    ...extra,
  ];
}

function snapshot(h: Host) {
  const p = servicePids(h);
  return {
    kek: sha256(h, L.kek),
    channelKey: sha256(h, L.channelKey),
    corePid: p.core,
    signerPid: p.signer,
  };
}

export function purgeDarwin(h: Host): { stdout: string; leftover: string } {
  const uninstall = `${DARWIN_STAGE}/release/${NAME}/uninstall.sh`;
  const r = h.exec(['bash', uninstall, '--purge'], { timeoutMs: 180_000 });
  const left = sh(
    h,
    `for p in /opt/keyflap /Library/Keyflap ${KEYFLAP} ${PLISTS.join(' ')}; do [ -e "$p" ] && echo "$p"; done
     for l in ${Object.values(LABELS).join(' ')}; do launchctl print system/$l >/dev/null 2>&1 && echo "job $l"; done
     for u in ${Object.values(L.users).join(' ')}; do pgrep -u $u >/dev/null 2>&1 && echo "processes of $u"; done; true`,
  ).stdout.trim();
  return {
    stdout: r.stdout + r.stderr,
    leftover: r.status === 0 ? left : `exit ${r.status}\n${left}`,
  };
}

export async function setupDarwin(
  provide: (env: IsolationEnv) => void,
  skip: (reason: string) => void,
): Promise<(() => void) | undefined> {
  if (spawnSync('sudo', ['-n', 'true']).status !== 0) {
    return void skip('needs passwordless sudo (sudo -n) on the Mac');
  }
  const artifacts = process.env.KEYFLAP_ISOLATION_ARTIFACTS;
  if (!artifacts || !existsSync(join(artifacts, 'release', `${NAME}.tar.xz`))) {
    return void skip(
      'needs KEYFLAP_ISOLATION_ARTIFACTS with the darwin release and a source bundle: run packages/isolation/darwin/run-on-mac.sh from Linux',
    );
  }
  const h = darwinHost();
  const me = userInfo().username;
  const work = mkdtempSync('/private/tmp/keyflap-isolation-');
  const phoneLog = join(work, 'phone.log');
  const children: ChildProcess[] = [];
  const background = (name: string, args: string[]) => {
    const out = openSync(join(work, `${name}.out`), 'a');
    const c = spawn(process.execPath, args, {
      cwd: REPO,
      stdio: ['ignore', out, out],
      detached: true,
    });
    children.push(c);
    return c;
  };
  const teardown = () => {
    for (const c of children) {
      try {
        if (c.pid) process.kill(-c.pid, 'SIGTERM');
      } catch {}
    }
    if (process.env.KEYFLAP_ISOLATION_KEEP === '1') return;
    const purge = purgeDarwin(h);
    h.exec(['rm', '-rf', DARWIN_STAGE, '/Users/Shared/keyflap-isolation-probe']);
    h.exec(['rmdir', '/usr/local/bin']);
    rmSync(work, { recursive: true, force: true });
    if (purge.leftover) {
      throw new Error(`uninstall.sh --purge left:\n${purge.leftover}\n${purge.stdout}`);
    }
    process.stderr.write(`isolation: purged the install; kept the hidden users\n${purge.stdout}\n`);
  };

  try {
    const created = h.exec(['bash', '-c', PROBE_USER_SCRIPT, 'probe-user', L.agentUser], {
      check: true,
    });
    const probeUid = Number(created.stdout.trim().split('\n').pop());
    if (h.as(L.agentUser, ['test', '-r', `${L.probeDir}/attempt.ts`]).status !== 0) {
      throw new Error(
        `${L.agentUser} cannot read ${L.probeDir}: put the checkout where every user can read it`,
      );
    }

    must(
      h,
      `rm -rf ${DARWIN_STAGE} && install -d -m 0700 -o root -g wheel ${DARWIN_STAGE} ${DARWIN_STAGE}/release
       cp ${artifacts}/release/${NAME}.tar.xz ${artifacts}/release/SHA256SUMS ${DARWIN_STAGE}/release/
       cp -R ${artifacts}/bundle ${DARWIN_STAGE}/bundle
       cp -R ${REPO}/packages/install ${DARWIN_STAGE}/install
       install -d -m 0700 ${DARWIN_STAGE}/browsers
       cp -R ${JSON.stringify(join(homedir(), 'Library/Caches/ms-playwright/chromium-1248'))} ${DARWIN_STAGE}/browsers/
       chown -R root:wheel ${DARWIN_STAGE} && chmod -R go-w ${DARWIN_STAGE}`,
      10 * 60_000,
    );
    const sums = must(h, `cd ${DARWIN_STAGE}/release && shasum -a 256 -c SHA256SUMS`);
    must(h, `cd ${DARWIN_STAGE}/release && tar -xJf ${NAME}.tar.xz`, 5 * 60_000);
    const rel = `${DARWIN_STAGE}/release/${NAME}`;

    if (sh(h, NOTHING_INSTALLED).status !== 0) {
      const p = purgeDarwin(h);
      if (p.leftover) throw new Error(`could not remove the previous install:\n${p.leftover}`);
    }
    const untouched = () => sh(h, NOTHING_INSTALLED).status === 0;

    const fromDir = '/Users/Shared/keyflap-isolation-probe';
    must(
      h,
      `rm -rf ${fromDir} && install -d -m 0755 -o ${L.agentUser} ${fromDir} && cp -R ${rel} ${fromDir}/rel && chown -R ${L.agentUser} ${fromDir}/rel`,
    );
    const fromHome = h.exec(
      [`${fromDir}/rel/install.sh`, ...installArgs(['--browsers-dir', `${DARWIN_STAGE}/browsers`])],
      { timeoutMs: 60_000 },
    );
    const fromHomeUntouched = untouched();
    h.exec(['rm', '-rf', `${fromDir}/rel`]);

    const linuxOnly = h.exec([`${rel}/install.sh`, ...installArgs(['--xvfb'])], {
      timeoutMs: 60_000,
    });
    const linuxOnlyUntouched = untouched();

    const releaseInstall = [
      `${rel}/install.sh`,
      ...installArgs(['--browsers-dir', `${DARWIN_STAGE}/browsers`]),
    ];
    const install = h.exec(releaseInstall, { timeoutMs: 15 * 60_000 });
    if (install.status !== 0) {
      throw new Error(`release install.sh failed:\n${install.stdout}\n${install.stderr}`);
    }
    waitReady(h, 180_000);
    const installedVersion = h.exec(['cat', '/opt/keyflap/app/VERSION'], { check: true }).stdout;

    background('rp', [`${L.probeDir}/rp.ts`]);
    waitFor(
      'the test RP',
      () => spawnSync('curl', ['-fsS', '-o', '/dev/null', 'http://127.0.0.1:3000/']).status === 0,
      30_000,
    );
    const pair = h.exec([KEYFLAP, 'approver', 'pair'], { check: true }).stdout;
    const pairingUrl = /(http:\/\/approver\.localhost:8766\/pair#[A-Za-z0-9_-]+)/.exec(pair)?.[1];
    if (!pairingUrl) throw new Error(`no pairing URL in: ${pair}`);
    background('phone', [`${L.probeDir}/phone.ts`, pairingUrl, phoneLog]);
    waitFor(
      'phone pairing',
      () => existsSync(phoneLog) && h.exec(['cat', phoneLog]).stdout.includes('"paired"'),
      90_000,
    );

    const added = h.exec([KEYFLAP, 'agent', 'add', 'isolation-agent'], { check: true }).stdout;
    const agentId = /\(id ([0-9a-f-]{36})\)/.exec(added)?.[1];
    const agentToken = /(aab_agent_[A-Za-z0-9_-]{43})/.exec(added)?.[1];
    if (!agentId || !agentToken) throw new Error('agent add printed no id/token');
    h.exec([KEYFLAP, 'sessions', 'keep', 'rp.localhost', '--agent', agentId], { check: true });

    const tokenFile = `${L.hookDir}/agent-${agentId}.token`;
    h.as(L.agentUser, ['sh', '-c', `umask 077; cat >${tokenFile}`], { input: `${agentToken}\n` });
    h.as(L.agentUser, [
      'ln',
      '-s',
      L.kek,
      `${L.hookDir}/agent-00000000-0000-4000-8000-000000000001.token`,
    ]);
    h.as(L.agentUser, [
      'sh',
      '-c',
      `echo not-a-token >${L.hookDir}/agent-00000000-0000-4000-8000-000000000002.token`,
    ]);

    const launcher = `${rel}/keyflap-launch`;
    const nodeTarball = `${rel}/${must(h, `ls ${rel} | grep '^node-v22.*-darwin-arm64.tar.xz$'`).trim()}`;
    const before = snapshot(h);
    const upgrade = h.exec(
      [
        'bash',
        `${DARWIN_STAGE}/install/macos/install.sh`,
        '--bundle',
        `${DARWIN_STAGE}/bundle`,
        '--launcher',
        launcher,
        '--node-tarball',
        nodeTarball,
        ...installArgs(),
      ],
      { timeoutMs: 15 * 60_000 },
    );
    if (upgrade.status !== 0) {
      throw new Error(`upgrade install.sh failed:\n${upgrade.stdout}\n${upgrade.stderr}`);
    }
    waitReady(h, 180_000);
    const after = snapshot(h);
    const list = (what: string) => h.exec([KEYFLAP, what, 'list'], { check: true }).stdout;
    const stat = (p: string) => h.exec(['stat', '-f', '%Lp %Su', p]).stdout.trim().split(' ');
    const [tokenMode, tokenOwner] = stat(tokenFile);
    const upgradeFacts = {
      stdout: upgrade.stdout,
      before,
      after,
      agents: list('agent'),
      approvers: list('approver'),
      agentToken: {
        kept: h.exec(['cat', tokenFile]).stdout === `${agentToken}\n`,
        mode: tokenMode ?? '',
        owner: tokenOwner ?? '',
      },
      plantedGone: sh(h, `ls ${L.hookDir} | grep -c 00000000-0000-4000-8000`).stdout.trim() === '0',
      versionGone: h.exec(['test', '-e', '/opt/keyflap/app/VERSION']).status !== 0,
    };

    const kekBefore = sha256(h, L.kek);
    const uninstall = h.exec(['bash', `${rel}/uninstall.sh`], { timeoutMs: 180_000 });
    const gone = sh(
      h,
      `for l in ${Object.values(LABELS).join(' ')}; do launchctl print system/$l >/dev/null 2>&1 && echo "job $l"; done
       for p in ${KEYFLAP} /opt/keyflap/app /opt/keyflap/node /Library/Keyflap/run /Library/Keyflap/etc ${PLISTS.join(' ')}; do [ -e "$p" ] && echo "$p"; done
       for u in ${Object.values(L.users).join(' ')}; do pgrep -u $u >/dev/null && echo "processes of $u"; done; true`,
    ).stdout.trim();
    const keptAfterUninstall = sh(
      h,
      `for p in ${L.kek} ${L.channelKey} ${L.keyStore} ${L.brokerDb} ${tokenFile}; do [ -s "$p" ] || echo "missing $p"; done; true`,
    ).stdout.trim();
    const reinstall = h.exec(releaseInstall, { timeoutMs: 15 * 60_000 });
    if (reinstall.status !== 0) {
      throw new Error(`reinstall failed:\n${reinstall.stdout}\n${reinstall.stderr}`);
    }
    waitReady(h, 180_000);
    const reinstallFacts = {
      uninstall: uninstall.stdout + uninstall.stderr,
      uninstallStatus: uninstall.status,
      gone,
      kept: keptAfterUninstall,
      reinstall: reinstall.stdout,
      kekKept: sha256(h, L.kek) === kekBefore,
      agents: list('agent'),
      approvers: list('approver'),
      tokenKept: h.exec(['cat', tokenFile]).stdout === `${agentToken}\n`,
    };

    const status = JSON.parse(h.exec([KEYFLAP, 'status', '--json'], { check: true }).stdout) as {
      service: { core: { mcpUrl: string } };
    };
    const release: DarwinRelease = {
      name: NAME,
      dir: rel,
      sums,
      installedVersion: installedVersion.trim(),
      install: install.stdout,
      linuxOnly: {
        status: linuxOnly.status,
        stderr: linuxOnly.stderr,
        untouched: linuxOnlyUntouched,
      },
      fromHome: {
        dir: `${fromDir}/rel`,
        status: fromHome.status,
        stderr: fromHome.stderr,
        untouched: fromHomeUntouched,
      },
      upgrade: upgradeFacts,
      reinstall: reinstallFacts,
    };
    provide({
      skip: null,
      runtime: 'darwin',
      os: 'darwin',
      agentId,
      agentToken,
      mcpUrl: status.service.core.mcpUrl,
      rpUrl: 'http://rp.localhost:3000/',
      phoneLog,
      probeUid,
      otherUser: me,
      stage: DARWIN_STAGE,
      darwin: release,
    });
  } catch (err) {
    const logs = sh(
      h,
      'tail -n 40 /Library/Keyflap/log/core/core.log /Library/Keyflap/log/signer/signer.log /Library/Keyflap/log/approver/approver.log 2>&1; true',
    ).stdout;
    try {
      teardown();
    } catch (e) {
      process.stderr.write(`${(e as Error).message}\n`);
    }
    throw new Error(`${(err as Error).message}\n--- logs ---\n${logs}`);
  }
  return teardown;
}
