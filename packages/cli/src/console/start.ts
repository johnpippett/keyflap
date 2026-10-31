import { DEFAULT_MCP_PORT, defaultDataDir } from '../args.ts';
import { serviceAddressWords } from '../service/address.ts';
import { runServiceCommand } from '../service/cli.ts';
import { requireServiceManager } from '../service/manager.ts';
import { SERVICE_PATHS } from '../service/paths.ts';
import { TtyPrompter } from '../setup/prompt.ts';
import { setupContext } from '../setup/run.ts';
import { realSystem } from '../setup/system.ts';
import { ttyKeys, ttyScreen } from '../setup/tty-screen.ts';
import { ScreenUi, SetupLog, useScreen } from '../setup/ui.ts';
import { type Dispatch, runConsole, statusSnapshot } from './run.ts';

export type ConsoleStart = 'closed' | 'no-terminal' | 'not-root';

export async function openServiceConsole(): Promise<ConsoleStart> {
  if (!useScreen(process, process.env)) return 'no-terminal';
  const sys = realSystem();
  if (sys.uid !== 0) return 'not-root';
  const { styleFor } = await import('@aab/approver');
  const style = styleFor(process.stdout);
  const ui = new ScreenUi({
    screen: ttyScreen(process.stdout, process.stdin),
    keys: ttyKeys(process.stdin),
    style,
    mode: 'service mode',
    app: 'console',
    log: new SetupLog(new Date(sys.now()).toISOString()),
    afterLeave: (text) => {
      process.stdout.write(text);
    },
    fallbackPrompt: new TtyPrompter(process.stdin, process.stdout),
  });
  const ctx = await setupContext(
    {
      dataDir: defaultDataDir(),
      mcpPort: DEFAULT_MCP_PORT,
      service: true,
      simple: false,
      host: null,
    },
    { sys, ui, style },
  );
  const m = requireServiceManager();
  const paths = SERVICE_PATHS;
  const dispatch: Dispatch = (cmd, out) => runServiceCommand(cmd, out, paths, m, sys);
  await runConsole({
    ui,
    ctx,
    dispatch,
    style,
    snapshot: () =>
      statusSnapshot(dispatch, (state) => serviceAddressWords(state, { sys, m, paths })),
  });
  return 'closed';
}
