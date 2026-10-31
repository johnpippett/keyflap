import { homedir } from 'node:os';
import { join } from 'node:path';
import type { TermStyle } from '@aab/approver';
import { DEFAULT_MCP_PORT, defaultDataDir } from '../args.ts';
import { TtyPrompter } from '../setup/prompt.ts';
import { passphraseAsker, setupContext } from '../setup/run.ts';
import { daemonCommand } from '../setup/state.ts';
import { commandLine } from '../setup/steps.ts';
import { realSystem, type System } from '../setup/system.ts';
import { ttyKeys, ttyScreen } from '../setup/tty-screen.ts';
import { ScreenUi, SetupLog, useScreen } from '../setup/ui.ts';
import { DaemonKeeper } from './daemon-keeper.ts';
import { devDispatch, devSnapshot } from './dev-commands.ts';
import { type DevInstall, devInstallAt } from './dev-install.ts';
import { devSections } from './dev-menu.ts';
import { KeyStoreUnlock } from './key-store-unlock.ts';
import { runConsole } from './run.ts';
import { showUnprotected, UNPROTECTED_FLAP } from './unprotected.ts';

export type DevConsoleStart = 'closed' | 'declined' | 'no-terminal' | 'no-install' | 'root';

export interface DevConsoleOptions {
  dataDir: string;
  install: DevInstall;
  home: string;
  sys: System;
  ui: ScreenUi;
  style: TermStyle;
}

export const devModeName = (install: DevInstall) =>
  install === 'simple' ? 'simple install' : 'dev mode';

export async function runDevConsole(o: DevConsoleOptions): Promise<'closed' | 'declined'> {
  const { sys, ui, style, dataDir, home } = o;
  const simple = o.install === 'simple';
  const unlock = new KeyStoreUnlock(
    passphraseAsker(ui.prompt, ui.out, dataDir, simple),
    () => !sys.exists(join(dataDir, 'signer', 'keys.enc.json')),
  );
  try {
    const ctx = await setupContext(
      { dataDir, mcpPort: DEFAULT_MCP_PORT, service: false, simple, host: null, home, quiet: true },
      { sys, ui, style, passphrase: unlock.ask },
    );
    const keeper = new DaemonKeeper({
      sys,
      prompt: ui.prompt,
      out: ui.out,
      wait: (label, work) => ui.wait(label, work),
      running: () => ctx.backend.daemonRunning(),
      simple: ctx.simple ?? null,
      startCommand: () =>
        commandLine(
          daemonCommand(ctx.state, {
            dataDir,
            defaultDataDir: ctx.defaults.dataDir,
            defaultMcpPort: ctx.defaults.mcpPort,
          }),
        ),
    });
    ctx.daemonStop = async (what) => {
      const stopped = await keeper.stopped(what);
      if (!stopped) ui.out('Nothing changed: Keyflap is still running.');
      return stopped;
    };
    if (!(await showUnprotected(ui, { style, simple, home }))) return 'declined';
    await runConsole(
      {
        ui,
        ctx,
        dispatch: devDispatch({ dataDir, simple, unlock, keeper, sys }),
        style,
        snapshot: async () =>
          devSnapshot({ sys, dataDir, passwordSource: ctx.state.passwordSource?.kind ?? null }),
        settle: () => keeper.settle(),
      },
      devSections(),
    );
    return 'closed';
  } finally {
    ui.leave();
  }
}

export async function openDevConsole(sys: System = realSystem()): Promise<DevConsoleStart> {
  if (sys.uid === 0) return 'root';
  const dataDir = defaultDataDir();
  const install = devInstallAt(dataDir);
  if (install === null) return 'no-install';
  if (!useScreen(process, process.env)) return 'no-terminal';
  const { styleFor } = await import('@aab/approver');
  const style = styleFor(process.stdout);
  const ui = new ScreenUi({
    screen: ttyScreen(process.stdout, process.stdin),
    keys: ttyKeys(process.stdin),
    style,
    mode: devModeName(install),
    app: 'console',
    alert: UNPROTECTED_FLAP,
    log: new SetupLog(new Date(sys.now()).toISOString()),
    afterLeave: (text) => {
      process.stdout.write(text);
    },
    fallbackPrompt: new TtyPrompter(process.stdin, process.stdout),
  });
  return runDevConsole({ dataDir, install, home: homedir(), sys, ui, style });
}
