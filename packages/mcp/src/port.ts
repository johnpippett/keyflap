export type Locator =
  | { role: string; name?: string; exact?: boolean }
  | { text: string; exact?: boolean }
  | { label: string; exact?: boolean }
  | { placeholder: string; exact?: boolean }
  | { css: string };

export interface PageInfo {
  url: string;
  title: string;
}

export interface SnapshotResult extends PageInfo {
  snapshot: string;
  humanCheck: boolean;
}

export interface AuthStatus {
  origin: string | null;
  credentials: { type: 'passkey' | 'password' | 'totp' }[];
  humanCheck: boolean;
}

export type AuthOutcome =
  | { status: 'success' }
  | { status: 'denied' }
  | { status: 'failed' }
  | { status: 'challenge' }
  | { status: 'unsupported'; reason: 'no_credential' | 'not_eligible' | 'not_implemented' }
  | { status: 'timeout' };

export type HandoffOutcome =
  | { status: 'done' | 'cancelled' | 'expired' | 'pending' | 'denied' }
  | { status: 'unsupported'; reason: 'not_available' | 'not_eligible' | 'no_human_check' };

export interface AgentBrowserPort {
  open(url: string): Promise<PageInfo>;
  click(target: Locator): Promise<PageInfo>;
  type(target: Locator, text: string, opts?: { submit?: boolean }): Promise<PageInfo>;
  snapshot(): Promise<SnapshotResult>;
  authStatus(): Promise<AuthStatus>;
  authLogin(opts?: { timeoutMs?: number }): Promise<AuthOutcome>;
  authEnrollPasskey(opts?: { timeoutMs?: number }): Promise<AuthOutcome>;
  handoff(opts?: { timeoutMs?: number }): Promise<HandoffOutcome>;
}

export class ToolError extends Error {}

export interface AuthenticatedAgent {
  agentId: string;
  port: AgentBrowserPort;
}

export type AgentResolver = (bearerToken: string) => AuthenticatedAgent | null;

export type ToolCallObserver = (event: { agentId: string; tool: string; ok: boolean }) => void;
