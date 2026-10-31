import { join } from 'node:path';
import type { FileOwner, System } from './system.ts';

export type ApproverChoice =
  | { kind: 'terminal' }
  | {
      kind: 'phone';
      origin: string;
      listen: { host: string; port: number };
      tlsCert: string | null;
      tlsKey: string | null;
      via: 'tailscale' | 'own-tls' | 'proxy';
    };

export interface ClaudeTarget {
  agentId: string;
  scope: 'project' | 'user';
  project: string | null;
}

export interface SetupState {
  version: 1;
  approver: ApproverChoice | null;
  headed: boolean | null;
  passwordSource: {
    kind: 'proton-pass' | '1password';
    vault: string | null;
    bin: string | null;
  } | null;
  mcpPort: number;
  claudeCode: ClaudeTarget[];
  agentHosts?: { host: 'hermes' | 'codex'; agentId: string; dir: string }[];
}

export const STATE_FILE = 'setup.json';

export function emptyState(mcpPort: number): SetupState {
  return {
    version: 1,
    approver: null,
    headed: null,
    passwordSource: null,
    mcpPort,
    claudeCode: [],
  };
}

export function loadState(sys: System, dir: string, mcpPort: number, owner: FileOwner): SetupState {
  const text = sys.readUserFile(join(dir, STATE_FILE), owner);
  if (text === null) return emptyState(mcpPort);
  try {
    const s = JSON.parse(text) as Partial<SetupState>;
    if (s.version !== 1) return emptyState(mcpPort);
    return {
      ...emptyState(mcpPort),
      ...s,
      claudeCode: Array.isArray(s.claudeCode) ? s.claudeCode : [],
    } as SetupState;
  } catch {
    return emptyState(mcpPort);
  }
}

export function saveState(sys: System, dir: string, state: SetupState, owner: FileOwner): void {
  sys.mkdirUser(dir, 0o700, owner);
  sys.writeUserFile(join(dir, STATE_FILE), `${JSON.stringify(state, null, 2)}\n`, 0o600, owner);
}

export function daemonCommand(
  state: SetupState,
  o: { dataDir: string; defaultDataDir: string; defaultMcpPort: number; keyflap?: string },
): string[] {
  const args = [o.keyflap ?? 'keyflap', 'daemon', '--unprotected'];
  if (o.dataDir !== o.defaultDataDir) args.push('--data-dir', o.dataDir);
  if (state.mcpPort !== o.defaultMcpPort) args.push('--mcp-port', String(state.mcpPort));
  if (state.headed) args.push('--headed');
  const a = state.approver;
  if (a?.kind === 'phone') {
    args.push('--approver', 'phone', '--approver-origin', a.origin);
    if (a.listen.host !== '127.0.0.1' || a.listen.port !== 8766) {
      const host = a.listen.host.includes(':') ? `[${a.listen.host}]` : a.listen.host;
      args.push('--approver-listen', `${host}:${a.listen.port}`);
    }
    if (a.tlsCert && a.tlsKey) args.push('--tls-cert', a.tlsCert, '--tls-key', a.tlsKey);
  }
  const p = state.passwordSource;
  if (p) {
    args.push('--password-source', p.kind);
    if (p.kind === '1password') {
      if (p.vault) args.push('--1password-vault', p.vault);
      if (p.bin) args.push('--op-bin', p.bin);
    } else {
      if (p.vault) args.push('--proton-pass-vault', p.vault);
      if (p.bin) args.push('--proton-pass-bin', p.bin);
    }
  }
  return args;
}
