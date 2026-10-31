import { relative, sep } from 'node:path';

export const SERVER_NAME = 'keyflap';

export interface KeyflapClaudeConfig {
  mcpUrl: string;
  headersCommand: string;
  hookCommand: string;
  denyDir: string;
  home: string;
}

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
type Obj = { [k: string]: Json };

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

export class ConfigShapeError extends Error {}

export function mcpEntry(c: Pick<KeyflapClaudeConfig, 'mcpUrl' | 'headersCommand'>): Obj {
  return { type: 'http', url: c.mcpUrl, headersHelper: c.headersCommand };
}

export function denyPaths(dir: string, home: string): { sandbox: string; rule: string } {
  const rel = relative(home, dir);
  const inHome = rel !== '' && !rel.startsWith('..') && !rel.startsWith(sep);
  const p = inHome ? `~/${rel.split(sep).join('/')}` : dir;
  return { sandbox: `${p}/**`, rule: p.startsWith('~') ? `${p}/**` : `/${p}/**` };
}

function clone<T extends Json>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function objAt(o: Obj, key: string, where: string): Obj {
  const v = o[key];
  if (v === undefined) {
    const fresh: Obj = {};
    o[key] = fresh;
    return fresh;
  }
  if (!isObj(v)) throw new ConfigShapeError(`${where}.${key} is not an object`);
  return v;
}

function arrAt(o: Obj, key: string, where: string): Json[] {
  const v = o[key];
  if (v === undefined) {
    const fresh: Json[] = [];
    o[key] = fresh;
    return fresh;
  }
  if (!Array.isArray(v)) throw new ConfigShapeError(`${where}.${key} is not an array`);
  return v;
}

export function mergeMcp(
  docIn: Json | undefined,
  entry: Obj,
  opts: { project?: string } = {},
): { doc: Obj; notes: string[] } {
  if (docIn !== undefined && !isObj(docIn)) throw new ConfigShapeError('not a JSON object');
  const doc = clone((docIn ?? {}) as Obj);
  const notes: string[] = [];
  let base = doc;
  if (opts.project !== undefined) {
    const projects = objAt(doc, 'projects', '');
    base = objAt(projects, opts.project, 'projects');
  }
  const servers = objAt(base, 'mcpServers', '');
  const old = servers[SERVER_NAME];
  if (old !== undefined && JSON.stringify(old) !== JSON.stringify(entry)) {
    notes.push(`replaces the existing "${SERVER_NAME}" MCP server entry`);
  }
  servers[SERVER_NAME] = entry;
  return { doc, notes };
}

const OUR_HOOK = /\bhook claude-code\b/;

export function mergeSettings(
  docIn: Json | undefined,
  c: Pick<KeyflapClaudeConfig, 'hookCommand' | 'denyDir' | 'home'>,
): { doc: Obj; notes: string[] } {
  if (docIn !== undefined && !isObj(docIn)) throw new ConfigShapeError('not a JSON object');
  const doc = clone((docIn ?? {}) as Obj);
  const notes: string[] = [];

  const hooks = objAt(doc, 'hooks', '');
  const ups = arrAt(hooks, 'UserPromptSubmit', 'hooks');
  let found = false;
  for (const group of ups) {
    if (!isObj(group) || !Array.isArray(group.hooks)) continue;
    for (const h of group.hooks) {
      if (isObj(h) && typeof h.command === 'string' && OUR_HOOK.test(h.command)) {
        if (found) continue;
        found = true;
        if (h.command !== c.hookCommand) {
          notes.push('replaces the earlier keyflap hook command');
          h.command = c.hookCommand;
          h.type = 'command';
        }
      }
    }
  }
  if (!found) ups.push({ hooks: [{ type: 'command', command: c.hookCommand }] });

  const paths = denyPaths(c.denyDir, c.home);
  const sandbox = objAt(doc, 'sandbox', '');
  const required: [string, boolean][] = [
    ['enabled', true],
    ['failIfUnavailable', true],
    ['allowUnsandboxedCommands', false],
  ];
  for (const [k, v] of required) {
    if (sandbox[k] !== undefined && sandbox[k] !== v) {
      notes.push(`sets sandbox.${k} to ${v} (was ${JSON.stringify(sandbox[k])})`);
    }
    sandbox[k] = v;
  }
  const fsys = objAt(sandbox, 'filesystem', 'sandbox');
  for (const k of ['denyRead', 'denyWrite']) {
    const list = arrAt(fsys, k, 'sandbox.filesystem');
    if (!list.includes(paths.sandbox)) list.push(paths.sandbox);
  }
  const perms = objAt(doc, 'permissions', '');
  const deny = arrAt(perms, 'deny', 'permissions');
  for (const rule of [`Read(${paths.rule})`, `Edit(${paths.rule})`]) {
    if (!deny.includes(rule)) deny.push(rule);
  }
  return { doc, notes };
}

export function stringify(doc: Json): string {
  return `${JSON.stringify(doc, null, 2)}\n`;
}

export function lineDiff(a: string[], b: string[], context = 2): string[] {
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      (lcs[i] as number[])[j] =
        a[i] === b[j]
          ? ((lcs[i + 1] as number[])[j + 1] as number) + 1
          : Math.max((lcs[i + 1] as number[])[j] as number, (lcs[i] as number[])[j + 1] as number);
    }
  }
  const ops: { k: ' ' | '+' | '-'; t: string }[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      ops.push({ k: ' ', t: a[i] as string });
      i++;
      j++;
    } else if (
      i < n &&
      (j >= m || ((lcs[i + 1] as number[])[j] as number) >= ((lcs[i] as number[])[j + 1] as number))
    ) {
      ops.push({ k: '-', t: a[i] as string });
      i++;
    } else {
      ops.push({ k: '+', t: b[j] as string });
      j++;
    }
  }
  const keep = ops.map(() => false);
  ops.forEach((o, idx) => {
    if (o.k === ' ') return;
    for (let d = -context; d <= context; d++) {
      if (idx + d >= 0 && idx + d < ops.length) keep[idx + d] = true;
    }
  });
  const lines: string[] = [];
  let skipped = false;
  ops.forEach((o, idx) => {
    if (keep[idx]) {
      lines.push(`${o.k} ${o.t}`);
      skipped = false;
    } else if (!skipped) {
      lines.push('  …');
      skipped = true;
    }
  });
  return lines;
}

export function jsonDiff(before: Json | undefined, after: Obj): string[] {
  const b = isObj(before) ? before : {};
  const lines: string[] = [];
  for (const key of Object.keys(after)) {
    const x = b[key];
    const y = after[key] as Json;
    if (JSON.stringify(x) === JSON.stringify(y)) continue;
    const show = (v: Json | undefined) =>
      v === undefined ? [] : `"${key}": ${JSON.stringify(v, null, 2)}`.split('\n');
    lines.push(...lineDiff(show(x), show(y)));
  }
  return lines;
}

export interface ClaudeFiles {
  userSettings: Json | undefined | null;
  projectSettings: Json | undefined | null;
  localSettings: Json | undefined | null;
  userState: Json | undefined | null;
  projectMcp: Json | undefined | null;
}

export interface ClaudeInspection {
  mcp: { where: string; auth: 'headersHelper' | 'header' | 'none' } | null;
  hookAgents: string[];
  hookViaPnpm: boolean;
  denyRead: boolean;
  denyWrite: boolean;
  permissionDeny: boolean;
  sandboxEnabled: boolean;
  failIfUnavailable: boolean;
  allowUnsandboxedCommands: boolean;
  unreadable: string[];
}

function mcpMatch(servers: Json | undefined, port: number): Obj | null {
  if (!isObj(servers)) return null;
  for (const v of Object.values(servers)) {
    if (!isObj(v) || typeof v.url !== 'string') continue;
    try {
      const u = new URL(v.url);
      if (
        (u.hostname === '127.0.0.1' || u.hostname === 'localhost') &&
        Number(u.port) === port &&
        u.pathname.replace(/\/$/, '') === '/mcp'
      ) {
        return v;
      }
    } catch {}
  }
  return null;
}

export function inspectClaude(
  files: ClaudeFiles,
  opts: { project: string; mcpPort: number; denyDir: string; home: string },
): ClaudeInspection {
  const unreadable = Object.entries(files)
    .filter(([, v]) => v === null)
    .map(([k]) => k);
  const val = (v: Json | undefined | null): Json | undefined => (v === null ? undefined : v);

  let mcp: ClaudeInspection['mcp'] = null;
  const state = val(files.userState);
  const candidates: [string, Json | undefined][] = [
    [
      '.mcp.json',
      isObj(val(files.projectMcp)) ? (val(files.projectMcp) as Obj).mcpServers : undefined,
    ],
    [
      '~/.claude.json (this project)',
      isObj(state) && isObj(state.projects) && isObj(state.projects[opts.project])
        ? (state.projects[opts.project] as Obj).mcpServers
        : undefined,
    ],
    ['~/.claude.json (user)', isObj(state) ? state.mcpServers : undefined],
  ];
  for (const [where, servers] of candidates) {
    const e = mcpMatch(servers, opts.mcpPort);
    if (!e) continue;
    const headers = isObj(e.headers) ? e.headers : {};
    const auth =
      typeof e.headersHelper === 'string'
        ? 'headersHelper'
        : typeof headers.Authorization === 'string' || typeof headers.authorization === 'string'
          ? 'header'
          : 'none';
    mcp = { where, auth };
    break;
  }

  const layers = [files.userSettings, files.projectSettings, files.localSettings]
    .map(val)
    .filter(isObj);
  const hookAgents: string[] = [];
  let hookViaPnpm = false;
  const denyRead = new Set<string>();
  const denyWrite = new Set<string>();
  const permDeny = new Set<string>();
  const scalar: Record<string, Json> = {};
  for (const s of layers) {
    const hooks = isObj(s.hooks) ? s.hooks.UserPromptSubmit : undefined;
    if (Array.isArray(hooks)) {
      for (const g of hooks) {
        if (!isObj(g) || !Array.isArray(g.hooks)) continue;
        for (const h of g.hooks) {
          if (!isObj(h) || typeof h.command !== 'string' || !OUR_HOOK.test(h.command)) continue;
          const m = /--agent\s+'?([0-9a-f-]{36})'?/.exec(h.command);
          if (m) hookAgents.push(m[1] as string);
          if (/\b(pnpm|npm|npx|yarn)\b/.test(h.command)) hookViaPnpm = true;
        }
      }
    }
    if (isObj(s.sandbox)) {
      for (const k of ['enabled', 'failIfUnavailable', 'allowUnsandboxedCommands']) {
        if (s.sandbox[k] !== undefined) scalar[k] = s.sandbox[k] as Json;
      }
      const f = s.sandbox.filesystem;
      if (isObj(f)) {
        for (const p of Array.isArray(f.denyRead) ? f.denyRead : []) denyRead.add(String(p));
        for (const p of Array.isArray(f.denyWrite) ? f.denyWrite : []) denyWrite.add(String(p));
      }
    }
    if (isObj(s.permissions) && Array.isArray(s.permissions.deny)) {
      for (const r of s.permissions.deny) permDeny.add(String(r));
    }
  }
  const paths = denyPaths(opts.denyDir, opts.home);
  const covers = (set: Set<string>, wanted: string, wrap: (p: string) => string) => {
    if (set.has(wrap(wanted))) return true;
    const base = wanted.replace(/\/\*\*$/, '');
    const parts = base.split('/');
    for (let i = parts.length - 1; i > 0; i--) {
      if (set.has(wrap(`${parts.slice(0, i).join('/')}/**`))) return true;
    }
    return false;
  };
  return {
    mcp,
    hookAgents,
    hookViaPnpm,
    denyRead: covers(denyRead, paths.sandbox, (p) => p),
    denyWrite: covers(denyWrite, paths.sandbox, (p) => p),
    permissionDeny:
      covers(permDeny, paths.rule, (p) => `Read(${p})`) &&
      covers(permDeny, paths.rule, (p) => `Edit(${p})`),
    sandboxEnabled: scalar.enabled === true,
    failIfUnavailable: scalar.failIfUnavailable === true,
    allowUnsandboxedCommands: scalar.allowUnsandboxedCommands !== false,
    unreadable,
  };
}

export function parseJsonFile(text: string | null): Json | undefined | null {
  if (text === null) return undefined;
  try {
    return JSON.parse(text) as Json;
  } catch {
    return null;
  }
}
