import { dirname, join } from 'node:path';
import type { System } from './setup/system.ts';

export const SIMPLE_LABEL = 'com.keyflap.simple';

export const PROTECTS_LESS =
  "The simple install protects less: an agent that can run commands as you can read Keyflap's files and change its code. The full install stops that.";

export const FULL_INSTALL_COMMAND =
  'curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | sudo bash';

export const SIMPLE_INSTALL_COMMAND =
  'curl -fsSL https://github.com/johnpippett/keyflap/releases/latest/download/install-keyflap.sh | bash -s -- --simple';

export function simpleNotice(): string {
  return [
    PROTECTS_LESS,
    'To switch: run the uninstaller, then the full install (it needs your admin password once):',
    `  ${FULL_INSTALL_COMMAND}`,
  ].join('\n');
}

export interface SimpleInstall {
  app: string;
  node: string;
  main: string;
  browsers: string;
  wrapper: string;
  uninstaller: string;
  plist: string;
  log: string;
  dataDir: string;
}

export function simpleInstall(home: string): SimpleInstall {
  const app = join(home, 'Library', 'Application Support', 'Keyflap');
  return {
    app,
    node: join(app, 'node', 'bin', 'node'),
    main: join(app, 'app', 'packages', 'cli', 'src', 'main.ts'),
    browsers: join(app, 'browsers'),
    wrapper: join(app, 'bin', 'keyflap'),
    uninstaller: join(app, 'uninstall.sh'),
    plist: join(home, 'Library', 'LaunchAgents', `${SIMPLE_LABEL}.plist`),
    log: join(home, 'Library', 'Logs', 'Keyflap', 'daemon.log'),
    dataDir: join(home, '.keyflap'),
  };
}

export function isSimpleMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.KEYFLAP_MODE === 'simple';
}

export const SIMPLE_PATH = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin';

const xml = (s: string) =>
  s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

export function launchAgentPlist(install: SimpleInstall, daemonArgs: readonly string[]): string {
  const args = [install.node, '--disable-warning=ExperimentalWarning', install.main, ...daemonArgs];
  if (args.some((a) => [...a].some((ch) => ch.charCodeAt(0) < 0x20))) {
    throw new Error('a LaunchAgent argument contains a control character');
  }
  const env: [string, string][] = [
    ['KEYFLAP_MODE', 'simple'],
    ['PATH', SIMPLE_PATH],
    ['PLAYWRIGHT_BROWSERS_PATH', install.browsers],
  ];
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<dict>',
    '  <key>Label</key>',
    `  <string>${SIMPLE_LABEL}</string>`,
    '  <key>ProgramArguments</key>',
    '  <array>',
    ...args.map((a) => `    <string>${xml(a)}</string>`),
    '  </array>',
    '  <key>EnvironmentVariables</key>',
    '  <dict>',
    ...env.flatMap(([k, v]) => [`    <key>${k}</key>`, `    <string>${xml(v)}</string>`]),
    '  </dict>',
    '  <key>WorkingDirectory</key>',
    `  <string>${xml(install.app)}</string>`,
    '  <key>RunAtLoad</key>',
    '  <true/>',
    '  <key>KeepAlive</key>',
    '  <dict>',
    '    <key>SuccessfulExit</key>',
    '    <false/>',
    '  </dict>',
    '  <key>ThrottleInterval</key>',
    '  <integer>10</integer>',
    '  <key>ExitTimeOut</key>',
    '  <integer>30</integer>',
    '  <key>ProcessType</key>',
    '  <string>Background</string>',
    '  <key>Umask</key>',
    '  <integer>63</integer>',
    '  <key>StandardOutPath</key>',
    `  <string>${xml(install.log)}</string>`,
    '  <key>StandardErrorPath</key>',
    `  <string>${xml(install.log)}</string>`,
    '</dict>',
    '</plist>',
    '',
  ].join('\n');
}

const LAUNCHCTL = '/bin/launchctl';
const target = (uid: number) => `gui/${uid}/${SIMPLE_LABEL}`;

export function launchAgentTarget(uid: number): string {
  return target(uid);
}

export function simpleStopHint(uid: number, home: string): string {
  return (
    `It runs in the background. To stop it until you next log in: launchctl bootout ${target(uid)}. ` +
    `To remove Keyflap: "${simpleInstall(home).uninstaller}".`
  );
}

export async function launchAgentLoaded(sys: System): Promise<boolean> {
  const r = await sys.exec(LAUNCHCTL, ['print', target(sys.uid)], { timeoutMs: 10_000 });
  return r.code === 0;
}

export async function stopLaunchAgent(sys: System): Promise<void> {
  if (!(await launchAgentLoaded(sys))) return;
  await sys.exec(LAUNCHCTL, ['bootout', target(sys.uid)], { timeoutMs: 40_000 });
  const deadline = sys.now() + 40_000;
  while (await launchAgentLoaded(sys)) {
    if (sys.now() > deadline)
      throw new Error(`launchctl bootout ${target(sys.uid)} did not stop it`);
    await sys.sleep(500);
  }
}

async function bootstrapLaunchAgent(sys: System, plist: string): Promise<void> {
  const r = await sys.exec(LAUNCHCTL, ['bootstrap', `gui/${sys.uid}`, plist], {
    timeoutMs: 30_000,
  });
  if (r.code !== 0) {
    const why = (r.stderr || r.stdout || r.error || '').trim().split('\n')[0];
    throw new Error(
      `launchctl bootstrap gui/${sys.uid} failed (${why}). Are you logged in to this Mac's desktop? The background broker needs your login session.`,
    );
  }
}

export async function startLaunchAgent(
  sys: System,
  install: SimpleInstall,
  plist: string,
): Promise<void> {
  await stopLaunchAgent(sys);
  const owner = { uid: sys.uid, gid: sys.gid };
  sys.mkdirUser(dirname(install.plist), 0o755, owner);
  sys.mkdirUser(dirname(install.log), 0o700, owner);
  sys.writeUserFile(install.plist, plist, 0o644, owner);
  await bootstrapLaunchAgent(sys, install.plist);
}

export async function resumeLaunchAgent(sys: System, install: SimpleInstall): Promise<void> {
  if (await launchAgentLoaded(sys)) return;
  if (!sys.exists(install.plist)) throw new Error(`${install.plist} is missing`);
  await bootstrapLaunchAgent(sys, install.plist);
}
