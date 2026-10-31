import { dirname } from 'node:path';
import { siteDomain } from '@aab/core';
import type { ToolCheck, ToolSpec } from '@aab/sources';
import type { Backend, PairOptions, PairResult, PasswordItem } from '../src/setup/backend.ts';
import type { Prompter } from '../src/setup/prompt.ts';
import type {
  ExecOptions,
  ExecResult,
  FileOwner,
  FileStat,
  HttpProbe,
  System,
} from '../src/setup/system.ts';
import { UnsafePathError } from '../src/setup/user-files.ts';

interface Node {
  kind: 'file' | 'dir' | 'socket';
  data: string;
  mode: number;
  uid: number;
  gid: number;
}

export class FakeSystem implements System {
  nodes = new Map<string, Node>();
  live = new Set<string>();
  execs: { cmd: string; args: string[]; opts: ExecOptions }[] = [];
  reads: string[] = [];
  bins = new Map<string, string>();
  exec_: (cmd: string, args: string[], opts: ExecOptions) => ExecResult = () => ({
    code: null,
    stdout: '',
    stderr: '',
    error: 'ENOENT',
  });
  http_: (url: string, opts: { method?: string }) => HttpProbe = () => ({
    status: null,
    error: 'ECONNREFUSED',
  });
  env: NodeJS.ProcessEnv = {};
  platform = 'linux';
  uid = 1000;
  gid = 1000;
  userAccess: { op: string; path: string; owner: FileOwner }[] = [];
  cwd = '/home/u/proj';
  t = Date.UTC(2026, 9, 22, 9, 0, 0);

  constructor() {
    this.dir('/home/u', 0o755);
    this.dir('/home/u/proj', 0o755);
  }

  dir(path: string, mode = 0o700, uid = this.uid): this {
    this.nodes.set(path, { kind: 'dir', data: '', mode, uid, gid: uid });
    return this;
  }

  file(path: string, data: string, mode = 0o644, uid = this.uid): this {
    this.nodes.set(path, { kind: 'file', data, mode, uid, gid: uid });
    return this;
  }

  socket(path: string, o: { mode?: number; uid?: number; live?: boolean } = {}): this {
    this.nodes.set(path, {
      kind: 'socket',
      data: '',
      mode: o.mode ?? 0o600,
      uid: o.uid ?? this.uid,
      gid: o.uid ?? this.uid,
    });
    if (o.live !== false) this.live.add(path);
    return this;
  }

  text(path: string): string | undefined {
    const n = this.nodes.get(path);
    return n?.kind === 'file' ? n.data : undefined;
  }

  async exec(cmd: string, args: string[], opts: ExecOptions = {}): Promise<ExecResult> {
    this.execs.push({ cmd, args, opts });
    return this.exec_(cmd, args, opts);
  }
  which(cmd: string): string | null {
    return this.bins.get(cmd) ?? null;
  }
  readFile(path: string): string | null {
    this.reads.push(path);
    const n = this.nodes.get(path);
    return n?.kind === 'file' ? n.data : null;
  }
  writeFile(path: string, data: string, mode: number): void {
    if (!this.nodes.get(dirname(path))) throw new Error(`ENOENT: ${dirname(path)}`);
    const old = this.nodes.get(path);
    this.nodes.set(path, {
      kind: 'file',
      data,
      mode,
      uid: old?.uid ?? this.uid,
      gid: old?.gid ?? this.uid,
    });
  }
  readUserFile(path: string, owner: FileOwner): string | null {
    this.userAccess.push({ op: 'read', path, owner });
    const n = this.nodes.get(path);
    if (!n) return null;
    if (n.kind !== 'file') throw new UnsafePathError(`${path} is not a regular file`);
    if (n.uid !== owner.uid) throw new UnsafePathError(`${path} is owned by uid ${n.uid}`);
    this.reads.push(path);
    return n.data;
  }
  userFileMode(path: string, owner: FileOwner): number | null {
    const n = this.nodes.get(path);
    if (!n) return null;
    if (n.kind !== 'file') throw new UnsafePathError(`${path} is not a regular file`);
    if (n.uid !== owner.uid) throw new UnsafePathError(`${path} is owned by uid ${n.uid}`);
    return n.mode;
  }
  writeUserFile(
    path: string,
    data: string,
    mode: number,
    owner: FileOwner,
    opts: { exclusive?: boolean } = {},
  ): void {
    this.userAccess.push({ op: 'write', path, owner });
    const old = this.nodes.get(path);
    if (old && opts.exclusive) throw new Error(`EEXIST: ${path}`);
    if (old && (old.kind !== 'file' || old.uid !== owner.uid)) {
      throw new UnsafePathError(`${path} is not a regular file of yours`);
    }
    if (!this.nodes.get(dirname(path))) throw new Error(`ENOENT: ${dirname(path)}`);
    this.nodes.set(path, { kind: 'file', data, mode, uid: owner.uid, gid: owner.gid });
  }
  mkdirUser(path: string, mode: number, owner: FileOwner): void {
    this.userAccess.push({ op: 'mkdir', path, owner });
    let p = path;
    const missing: string[] = [];
    while (p !== '/' && !this.nodes.has(p)) {
      missing.push(p);
      p = dirname(p);
    }
    for (const m of missing.reverse()) this.dir(m, mode, owner.uid);
  }
  writeRootFile(
    path: string,
    data: string,
    o: { mode: number; owner?: { uid: number; gid: number } },
  ): void {
    if (this.nodes.get(dirname(path))?.kind !== 'dir') throw new Error(`ENOENT: ${dirname(path)}`);
    this.rootWrites.push({ path, mode: o.mode, ...(o.owner ? { owner: o.owner } : {}) });
    this.nodes.set(path, {
      kind: 'file',
      data,
      mode: o.mode,
      uid: o.owner?.uid ?? 0,
      gid: o.owner?.gid ?? 0,
    });
  }
  promoteRootFile(tmp: string, path: string, mode: number): void {
    const n = this.nodes.get(tmp);
    if (n?.kind !== 'file') throw new Error(`ENOENT: ${tmp}`);
    this.nodes.delete(tmp);
    this.nodes.set(path, { ...n, mode });
  }
  removeRootFile(path: string): void {
    this.nodes.delete(path);
  }
  mkdirRoot(path: string, mode: number): void {
    this.mkdir(path, mode);
  }
  rootWrites: { path: string; mode: number; owner?: { uid: number; gid: number } }[] = [];
  tools = new Map<string, ToolCheck>();
  checkTool(path: string, _spec: ToolSpec, pin?: string): ToolCheck {
    const r = this.tools.get(path);
    if (!r)
      return { ok: false, problem: 'untrusted', detail: `${path}: not trusted`, fix: 'fix it' };
    if (r.ok && pin !== undefined && pin !== r.sha256) {
      return { ok: false, problem: 'changed', detail: `${path} changed`, fix: 'trust it' };
    }
    return r;
  }
  exists(path: string): boolean {
    return this.nodes.has(path);
  }
  stat(path: string): FileStat | null {
    const n = this.nodes.get(path);
    if (!n) return null;
    return {
      uid: n.uid,
      gid: n.gid,
      mode: n.mode,
      isFile: n.kind === 'file',
      isDirectory: n.kind === 'dir',
      isSocket: n.kind === 'socket',
    };
  }
  mkdir(path: string, mode: number): void {
    let p = path;
    const missing: string[] = [];
    while (p !== '/' && !this.nodes.has(p)) {
      missing.push(p);
      p = dirname(p);
    }
    for (const m of missing.reverse()) this.dir(m, mode);
  }
  async http(url: string, opts: { method?: string } = {}): Promise<HttpProbe> {
    return this.http_(url, opts);
  }
  async connectUnix(path: string): Promise<boolean> {
    return this.live.has(path);
  }
  async sleep(ms: number): Promise<void> {
    this.t += ms;
  }
  now(): number {
    return this.t;
  }

  allText(): [string, string][] {
    return [...this.nodes.entries()]
      .filter(([, n]) => n.kind === 'file')
      .map(([p, n]) => [p, n.data]);
  }
}

export class ScriptedPrompter implements Prompter {
  readonly asked: string[] = [];
  private readonly script: { q: RegExp; a: string; secret?: boolean }[];

  constructor(script: { q: RegExp; a: string; secret?: boolean }[]) {
    this.script = [...script];
  }

  private next(question: string, secret: boolean): string {
    this.asked.push(question);
    const s = this.script.shift();
    if (!s) throw new Error(`unexpected question: ${question}`);
    if (!s.q.test(question)) throw new Error(`expected ${s.q}, got question: ${question}`);
    if ((s.secret ?? false) !== secret) {
      throw new Error(`${question}: expected a ${s.secret ? 'secret' : 'visible'} prompt`);
    }
    return s.a;
  }

  async ask(question: string, def?: string): Promise<string> {
    const a = this.next(question, false);
    return a === '' && def !== undefined ? def : a;
  }

  async secret(question: string): Promise<string> {
    return this.next(question, true);
  }

  get remaining(): number {
    return this.script.length;
  }
}

export const AGENT_ID = '0b9d6c1e-2f4a-4c3b-9e8d-7a6b5c4d3e2f';
export const AGENT_TOKEN = `aab_agent_${'T'.repeat(43)}`;

export class FakeBackend implements Backend {
  kind: 'dev' | 'service' = 'dev';
  stateDir = '/home/u/.keyflap';
  fileOwner: FileOwner = { uid: 1000, gid: 1000 };
  denyDir = '/home/u/.keyflap';
  user = { uid: 1000, gid: 1000, name: 'u', home: '/home/u' };
  running = false;
  agents: { id: string; name: string; revoked: boolean }[] = [];
  tokens = new Set<string>();
  paired = 0;
  pairResult: PairResult = 'paired';
  pairCalls: PairOptions[] = [];
  passwords: PasswordItem[] = [];
  readonly sys: FakeSystem;

  constructor(sys: FakeSystem) {
    this.sys = sys;
    sys.mkdir(this.stateDir, 0o700);
  }

  daemonRunning = async () => this.running;
  mcpPort = async () => 8765;
  listAgents = async () => this.agents;
  createAgent = async (name: string) => {
    const n = this.agents.length;
    const a = {
      id: n === 0 ? AGENT_ID : `${n}${AGENT_ID.slice(1)}`,
      name,
      token: n === 0 ? AGENT_TOKEN : `aab_agent_${String(n).repeat(43)}`,
    };
    this.agents.push({ id: a.id, name, revoked: false });
    return a;
  };
  storeAgentToken = (agentId: string, token: string) => {
    const path = `${this.stateDir}/agents/${agentId}.token`;
    this.sys.mkdir(`${this.stateDir}/agents`, 0o700);
    this.sys.writeFile(path, `${token}\n`, 0o600);
    this.tokens.add(agentId);
    return path;
  };
  hasAgentToken = (id: string) => this.tokens.has(id);
  hookCommand = (id: string) =>
    `/usr/bin/node /repo/packages/cli/src/main.ts hook claude-code --agent ${id}`;
  headersCommand = (id: string) =>
    `/usr/bin/node /repo/packages/cli/src/main.ts mcp-headers --agent ${id}`;
  phonesPaired = async () => this.paired;
  pair = async (o: PairOptions) => {
    this.pairCalls.push(o);
    await o.onOpen('https://broker.tail1234.ts.net:8766/pair#CODE');
    if (this.pairResult === 'paired') this.paired++;
    return this.pairResult;
  };
  storedLogins = async () =>
    this.passwords.map((p) => ({
      domain: siteDomain(p.site) ?? p.site,
      username: p.username,
      native: true,
    }));
  addPassword = async (item: PasswordItem) => {
    this.passwords.push(item);
    return { id: 'pw_1', domain: item.site };
  };
}
