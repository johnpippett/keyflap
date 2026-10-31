import { confirm, type Prompter } from '../setup/prompt.ts';
import type { System } from '../setup/system.ts';
import {
  launchAgentLoaded,
  resumeLaunchAgent,
  type SimpleInstall,
  stopLaunchAgent,
} from '../simple-install.ts';

export class StillRunning extends Error {
  constructor() {
    super('Keyflap is still running, so nothing was changed.');
  }
}

export interface KeeperDeps {
  sys: System;
  prompt: Prompter;
  out: (text: string) => void;
  wait: <T>(label: string, work: () => Promise<T>) => Promise<T>;
  running: () => Promise<boolean>;
  simple: SimpleInstall | null;
  startCommand: () => string;
}

export class DaemonKeeper {
  private readonly d: KeeperDeps;
  private stoppedAgent = false;
  private stoppedTerminal = false;

  constructor(deps: KeeperDeps) {
    this.d = deps;
  }

  readonly stopped = async (what: string): Promise<boolean> => {
    const { sys, prompt, out, simple } = this.d;
    if (simple && (await launchAgentLoaded(sys))) {
      out(
        `Keyflap is running in the background and holds the key store; ${what} needs it stopped.`,
      );
      if (!(await confirm(prompt, 'Stop it for now? It starts again when you go back', false))) {
        return false;
      }
      await this.d.wait('Stopping Keyflap', () => stopLaunchAgent(sys));
      this.stoppedAgent = true;
      out('✓ Stopped. It starts again when you go back.');
    }
    while (await this.d.running()) {
      this.stoppedTerminal = true;
      out(
        `Keyflap is running in another terminal and holds the key store; ${what} needs it stopped.`,
      );
      const answer = (
        await prompt.ask('Stop it there (Ctrl-C), then press Enter. Type skip to leave it running')
      )
        .trim()
        .toLowerCase();
      if (answer === 'skip') return false;
    }
    return true;
  };

  async settle(): Promise<void> {
    const { sys, out, simple } = this.d;
    if (this.stoppedAgent && simple) {
      await this.d.wait('Starting Keyflap again', () => resumeLaunchAgent(sys, simple));
      this.stoppedAgent = false;
      out('✓ Keyflap is running in the background again.');
    }
    if (this.stoppedTerminal) {
      this.stoppedTerminal = false;
      if (!(await this.d.running())) {
        out(`! The daemon you stopped is not running. Start it again: ${this.d.startCommand()}`);
      }
    }
  }
}
