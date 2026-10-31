import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { dirname, join } from 'node:path';
import type { TermStyle } from '@aab/approver';
import { type AgentListing, CredentialRepo, openDb } from '@aab/core';
import { createAgent, listAgents } from '../src/agent.ts';
import { runDevConsole } from '../src/console/dev-start.ts';
import { createKeyFile } from '../src/key-file.ts';
import { storePassword } from '../src/password.ts';
import { realSystem, type System } from '../src/setup/system.ts';
import type { ScreenUi } from '../src/setup/ui.ts';
import { SIMPLE_LABEL, simpleInstall } from '../src/simple-install.ts';
import { tmpDir } from './helpers.ts';

export type Install = 'dev' | 'simple';

export const DEV_PASSPHRASE = 'dev-world-passphrase-Zq7!';

export interface DevWorld {
  install: Install;
  home: string;
  dataDir: string;
  sys: System;
  secrets: string[];
  passphrase: string;
  passwords(): { id: string; domain: string; username: string | null }[];
  agents(): AgentListing[];
  daemon: { start(): Promise<void>; stop(): Promise<void> };
  launchctl: { loaded: boolean; calls: string[] };
  run(ui: ScreenUi, style: TermStyle): ReturnType<typeof runDevConsole>;
  close(): Promise<void>;
}

const SEEDS = [
  { site: 'github.com', username: 'sam', password: 'devworld-gh-pw-3Kd' },
  { site: 'linear.app', username: 'sam@example.com', password: 'devworld-linear-pw-9Fw' },
];

export async function devConsoleWorld(install: Install = 'dev'): Promise<DevWorld> {
  const home = join(tmpDir(), 'home');
  const dataDir = join(home, '.keyflap');
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const passphrase = install === 'simple' ? createKeyFile(dataDir) : DEV_PASSPHRASE;
  for (const s of SEEDS) {
    await storePassword(dataDir, passphrase, { ...s, totp: null });
  }
  createAgent(dataDir, 'claude-code', 'test');
  createAgent(dataDir, 'codex', 'test');

  const launchctl = { loaded: install === 'simple', calls: [] as string[] };
  const plist = simpleInstall(home).plist;
  if (install === 'simple') {
    mkdirSync(dirname(plist), { recursive: true });
    writeFileSync(plist, '<plist/>');
  }
  const base = realSystem();
  const sys: System = {
    ...base,
    platform: install === 'simple' ? 'darwin' : base.platform,
    async exec(cmd, args, opts) {
      if (cmd !== '/bin/launchctl') return base.exec(cmd, args, opts);
      launchctl.calls.push(args.join(' '));
      if (args[0] === 'print') {
        return { code: launchctl.loaded ? 0 : 113, stdout: SIMPLE_LABEL, stderr: '' };
      }
      launchctl.loaded = args[0] === 'bootstrap';
      return { code: 0, stdout: '', stderr: '' };
    },
  };

  let server: Server | null = null;
  const socket = join(dataDir, 'run', 'intent.sock');
  const daemon = {
    async start() {
      mkdirSync(dirname(socket), { recursive: true });
      const s = createServer();
      await new Promise<void>((resolve) => s.listen(socket, resolve));
      server = s;
    },
    async stop() {
      const s = server;
      server = null;
      if (s) await new Promise((resolve) => s.close(resolve));
    },
  };

  return {
    install,
    home,
    dataDir,
    sys,
    passphrase,
    secrets: [passphrase, ...SEEDS.map((s) => s.password)],
    passwords() {
      const db = openDb(join(dataDir, 'broker.sqlite'));
      try {
        return new CredentialRepo(db)
          .allPasswords()
          .map((r) => ({ id: r.id, domain: r.registrable_domain, username: r.username }));
      } finally {
        db.close();
      }
    },
    agents: () => listAgents(dataDir),
    daemon,
    launchctl,
    run: (ui, style) => runDevConsole({ dataDir, install, home, sys, ui, style }),
    async close() {
      await daemon.stop();
      rmSync(dirname(home), { recursive: true, force: true });
    },
  };
}
