import { ALL_AGENTS, ALL_AGENTS_OPTIN, printable } from '@aab/core';
import { formatDuration } from '../format.ts';
import { isSourceKind, SOURCES, type SourceKind } from '../service/password-source.ts';

export interface Listing<T> {
  argv: readonly string[];
  none: string;
  parse(json: unknown): T[];
  label(t: T): string;
}

export class ListingError extends Error {}

type Row = Record<string, unknown>;

function rows(json: unknown, key?: string): Row[] {
  const list = key === undefined ? json : (json as Row | null)?.[key];
  if (!Array.isArray(list) || list.some((r) => typeof r !== 'object' || r === null)) {
    throw new ListingError('unexpected output from the list command');
  }
  return list as Row[];
}

function str(r: Row, k: string): string {
  const v = r[k];
  if (typeof v !== 'string') throw new ListingError(`unexpected ${k} in the list output`);
  return printable(v);
}

function optStr(r: Row, k: string): string | null {
  return r[k] === null || r[k] === undefined ? null : str(r, k);
}

function num(r: Row, k: string): number | null {
  const v = r[k];
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

const day = (ms: number | null) => (ms === null ? '?' : new Date(ms).toISOString().slice(0, 10));

export const everyAgent = (id: string) => id === '' || id === ALL_AGENTS || id === ALL_AGENTS_OPTIN;

export const scopeArgs = (agentId: string): string[] =>
  everyAgent(agentId) ? [] : ['--agent', agentId];

export interface Password {
  id: string;
  domain: string;
  username: string | null;
  totp: boolean;
  source: string;
}

export const passwordWords = (p: Password) =>
  `${p.domain}${p.username === null ? '' : ` (${p.username})`}`;

export const PASSWORDS: Listing<Password> = {
  argv: ['password', 'list', '--json'],
  none: 'No passwords stored.',
  parse: (json) =>
    rows(json).map((r) => ({
      id: str(r, 'id'),
      domain: str(r, 'domain'),
      username: optStr(r, 'username'),
      totp: r.totp === true,
      source: str(r, 'source'),
    })),
  label: (p) =>
    `${passwordWords(p)}${p.totp ? ' + TOTP' : ''}${p.source === 'native' ? '' : `, from ${p.source}`}`,
};

export interface Agent {
  id: string;
  name: string;
  createdAt: number | null;
  revokedAt: number | null;
}

export const agentWords = (a: Agent) => `"${a.name}"`;

export const AGENTS: Listing<Agent> = {
  argv: ['agent', 'list', '--json'],
  none: 'No agents.',
  parse: (json) =>
    rows(json).map((r) => ({
      id: str(r, 'id'),
      name: str(r, 'name'),
      createdAt: num(r, 'createdAt'),
      revokedAt: num(r, 'revokedAt'),
    })),
  label: (a) => `${a.name}, added ${day(a.createdAt)}`,
};

export interface Phone {
  id: string;
  type: string;
  createdAt: number | null;
}

export const phoneWords = (p: Phone) =>
  `${p.type === 'ios-app' ? 'iOS app' : 'phone'} paired ${day(p.createdAt)}`;

export const PHONES: Listing<Phone> = {
  argv: ['approver', 'list', '--json'],
  none: 'No phone paired.',
  parse: (json) =>
    rows(json).map((r) => ({
      id: str(r, 'id'),
      type: str(r, 'type'),
      createdAt: num(r, 'createdAt'),
    })),
  label: (p) =>
    `${p.type === 'ios-app' ? 'iOS app' : 'Phone (web page)'}, paired ${day(p.createdAt)}`,
};

export interface Rule {
  site: string;
  agentId: string;
  agentName: string | null;
  mode: string;
  allowForMs: number | null;
  sessionTtlMs: number | null;
}

function modeWords(r: Rule): string {
  switch (r.mode) {
    case 'deny':
      return 'never signs in';
    case 'ask':
      return 'asks every time';
    case 'ask-strong':
      return 'asks with Face ID or a PIN';
    case 'allow-for':
      return `no prompt for ${formatDuration(r.allowForMs ?? 0)} after an approval`;
    default:
      return 'no mode of its own';
  }
}

const ruleAgent = (r: Rule) =>
  everyAgent(r.agentId) ? 'every agent' : `"${r.agentName ?? 'a revoked agent'}"`;

export const ruleWords = (r: Rule) => `for ${r.site} (${ruleAgent(r)})`;

export const RULES: Listing<Rule> = {
  argv: ['policy', 'list', '--json'],
  none: 'No rules: every sign-in asks.',
  parse: (json) =>
    rows(json).map((r) => ({
      site: str(r, 'site'),
      agentId: str(r, 'agentId'),
      agentName: optStr(r, 'agentName'),
      mode: str(r, 'mode'),
      allowForMs: num(r, 'allowForMs'),
      sessionTtlMs: num(r, 'sessionTtlMs'),
    })),
  label: (r) =>
    `${r.site}: ${modeWords(r)}${r.sessionTtlMs === null ? '' : `, signed out after ${formatDuration(r.sessionTtlMs)}`} (${ruleAgent(r)})`,
};

export interface Saved {
  site: string;
  agentName: string;
  savedAt: number | null;
}

export const SESSIONS: Listing<Saved> = {
  argv: ['sessions', 'list', '--json'],
  none: 'No saved sessions.',
  parse: (json) =>
    rows(json, 'sessions').map((r) => ({
      site: str(r, 'site'),
      agentName: str(r, 'agentName'),
      savedAt: num(r, 'savedAt'),
    })),
  label: (s) => `${s.site}, ${s.agentName}, saved ${day(s.savedAt)}`,
};

export interface Kept {
  site: string;
  agentId: string;
}

export const KEPT: Listing<Kept> = {
  argv: ['sessions', 'list', '--json'],
  none: 'No high-risk site is kept signed in.',
  parse: (json) =>
    rows(json, 'kept').map((r) => ({ site: str(r, 'site'), agentId: str(r, 'agentId') })),
  label: (k) => `${k.site} (${everyAgent(k.agentId) ? 'every agent' : `agent ${k.agentId}`})`,
};

export const CONNECTED: Listing<SourceKind> = {
  argv: ['status', '--json'],
  none: 'No password manager is connected.',
  parse: (json) => {
    const kind = (json as { service?: { core?: { passwordSource?: unknown } } } | null)?.service
      ?.core?.passwordSource;
    return isSourceKind(kind) ? [kind] : [];
  },
  label: (k) => SOURCES[k].name,
};
