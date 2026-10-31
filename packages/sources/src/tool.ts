import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  type Stats,
} from 'node:fs';
import { dirname, isAbsolute, join, normalize } from 'node:path';
import { SourceError } from './source.ts';

export interface ToolSpec {
  command: string;
  installHint: string;
  reinstallFlag?: string;
  connect?: string;
}

export const KEYFLAP_TOOLS_DIR = '/opt/keyflap/tools';
export const SYSTEM_BIN_DIRS: readonly string[] = [
  '/usr/bin',
  '/usr/local/bin',
  '/usr/sbin',
  '/usr/local/sbin',
  '/bin',
  '/sbin',
];

export function toolDir(spec: ToolSpec): string {
  return `${KEYFLAP_TOOLS_DIR}/${spec.command}`;
}

export function toolCandidates(spec: ToolSpec): string[] {
  return [
    `${toolDir(spec)}/${spec.command}`,
    `/usr/local/bin/${spec.command}`,
    `/usr/bin/${spec.command}`,
  ];
}

export type ToolTrust =
  | {
      mode: 'system';
      sha256?: string;
      currentPin?: () => string | undefined;
    }
  | { mode: 'same-user' };

export type ToolProblem = 'untrusted' | 'changed';

export type ToolCheck =
  | { ok: true; path: string; sha256: string }
  | { ok: false; problem: ToolProblem; detail: string; fix: string };

const SHA256_RE = /^[0-9a-f]{64}$/;

export function isSha256(v: unknown): v is string {
  return typeof v === 'string' && SHA256_RE.test(v);
}

function mode(st: Stats): string {
  return (st.mode & 0o7777).toString(8).padStart(4, '0');
}

export function rootOnlyProblem(
  path: string,
  want: 'executable' | 'directory' = 'executable',
): { detail: string; dir?: string } | null {
  if (typeof path !== 'string' || !isAbsolute(path) || normalize(path) !== path) {
    return { detail: `${path}: not an absolute path` };
  }
  let real: string;
  try {
    real = realpathSync(path);
  } catch {
    return { detail: `${path} does not exist` };
  }
  if (real !== path)
    return { detail: `${path} is a symbolic link (or has one on the way) to ${real}` };
  const parts = path.split('/').filter(Boolean);
  let p = '/';
  for (let i = 0; i <= parts.length; i++) {
    if (i > 0) p = join(p, parts[i - 1] as string);
    let st: Stats;
    try {
      st = lstatSync(p);
    } catch {
      return { detail: `${p} cannot be read` };
    }
    const last = i === parts.length;
    const file = last && want === 'executable';
    if (st.isSymbolicLink()) return { detail: `${p} is a symbolic link` };
    if (file ? !st.isFile() : !st.isDirectory()) {
      return { detail: `${p} is not a ${file ? 'regular file' : 'directory'}` };
    }
    if (st.uid !== 0) {
      return { detail: `${p} is owned by uid ${st.uid}, not root: its owner can replace it` };
    }
    if ((st.mode & 0o022) !== 0) {
      return {
        detail: `${p} is mode ${mode(st)}: writable by ${st.mode & 0o002 ? 'every user' : `group ${st.gid}`}, who could replace it`,
        ...(file ? {} : { dir: p }),
      };
    }
    if (file && (st.mode & 0o6000) !== 0) return { detail: `${p} has a setuid/setgid bit` };
    if (file && (st.mode & 0o111) === 0) return { detail: `${p} is not executable` };
  }
  return null;
}

export function checkToolLocation(
  path: string,
  spec: ToolSpec,
): { ok: true } | { ok: false; detail: string; fix: string } {
  const flag = spec.reinstallFlag ?? '--proton-pass-bin';
  const then = spec.connect
    ? `run: ${spec.connect}`
    : `re-run install.sh with ${flag} ${toolDir(spec)}/${spec.command}`;
  const reinstall = `install ${spec.command} as root into ${toolDir(spec)}/ (${spec.installHint}), then ${then}`;
  if (typeof path !== 'string' || !isAbsolute(path) || normalize(path) !== path) {
    return { ok: false, detail: `${path}: not an absolute path`, fix: reinstall };
  }
  const tools = toolDir(spec);
  if (!SYSTEM_BIN_DIRS.includes(dirname(path)) && !path.startsWith(`${tools}/`)) {
    return {
      ok: false,
      detail: `${path} is not in a system bin directory or ${tools}/`,
      fix: reinstall,
    };
  }
  const bad = rootOnlyProblem(path);
  if (!bad) return { ok: true };
  let real: string | null = null;
  try {
    real = realpathSync(path);
  } catch {
    real = null;
  }
  const fix =
    real !== null && real !== path
      ? `use the real path ${real} if it passes these checks, else ${reinstall}`
      : bad.dir
        ? `sudo chmod go-w ${bad.dir}, or ${reinstall}`
        : reinstall;
  return { ok: false, detail: bad.detail, fix };
}

const hashCache = new Map<string, { key: string; sha256: string }>();
const TIMESTAMP_GRANULARITY_BOUND_MS = 3_000;

export function toolSha256(path: string): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const statedAt = Date.now();
    const st = fstatSync(fd);
    const key = `${st.dev}:${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}`;
    const hit = hashCache.get(path);
    if (hit?.key === key) return hit.sha256;
    const sha256 = createHash('sha256').update(readFileSync(fd)).digest('hex');
    const settled = statedAt - Math.max(st.mtimeMs, st.ctimeMs) > TIMESTAMP_GRANULARITY_BOUND_MS;
    if (settled) hashCache.set(path, { key, sha256 });
    else hashCache.delete(path);
    return sha256;
  } finally {
    closeSync(fd);
  }
}

export function checkTool(path: string, spec: ToolSpec, pin?: string): ToolCheck {
  const loc = checkToolLocation(path, spec);
  if (!loc.ok) return { ok: false, problem: 'untrusted', detail: loc.detail, fix: loc.fix };
  let sha256: string;
  try {
    sha256 = toolSha256(path);
  } catch {
    return {
      ok: false,
      problem: 'untrusted',
      detail: `${path} cannot be read`,
      fix: `check ${path}`,
    };
  }
  if (pin !== undefined && sha256 !== pin) {
    return {
      ok: false,
      problem: 'changed',
      detail: `${path} changed since it was trusted (SHA-256 ${sha256.slice(0, 16)}…, trusted ${pin.slice(0, 16)}…)`,
      fix: `make sure the new ${spec.command} is genuine, then: sudo keyflap password-source trust ${spec.command}`,
    };
  }
  return { ok: true, path, sha256 };
}

export class ToolLauncher {
  readonly spec: ToolSpec;
  private readonly bin: string;
  private readonly trust: ToolTrust;
  private readonly onRefused:
    | ((e: { tool: string; path: string; problem: ToolProblem; detail: string }) => void)
    | undefined;
  private lastRefusal: string | null = null;

  constructor(
    spec: ToolSpec,
    bin: string,
    trust: ToolTrust,
    onRefused?: (e: { tool: string; path: string; problem: ToolProblem; detail: string }) => void,
  ) {
    if (trust.mode === 'system' && trust.sha256 !== undefined && !isSha256(trust.sha256)) {
      throw new Error(`${spec.command}: the pinned SHA-256 must be 64 hex digits`);
    }
    this.spec = spec;
    this.bin = bin;
    this.trust = trust;
    this.onRefused = onRefused;
  }

  path(): string {
    if (this.trust.mode === 'same-user') return this.bin;
    let r = checkTool(this.bin, this.spec, this.trust.sha256);
    if (!r.ok && r.problem === 'changed' && this.trust.currentPin) {
      let pin: string | undefined;
      try {
        pin = this.trust.currentPin();
      } catch {
        pin = undefined;
      }
      if (isSha256(pin)) r = checkTool(this.bin, this.spec, pin);
      if (r.ok) this.trust.sha256 = pin;
    }
    if (r.ok) {
      this.lastRefusal = null;
      return r.path;
    }
    if (this.lastRefusal !== r.detail) {
      this.lastRefusal = r.detail;
      this.onRefused?.({
        tool: this.spec.command,
        path: this.bin,
        problem: r.problem,
        detail: r.detail,
      });
    }
    throw new SourceError(
      r.problem === 'changed' ? 'source_tool_changed' : 'source_tool_untrusted',
    );
  }
}
