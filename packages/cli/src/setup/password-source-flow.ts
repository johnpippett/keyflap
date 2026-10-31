import { createInterface, type Interface } from 'node:readline';
import {
  applyConnect,
  applyDisconnect,
  assertRoot,
  type Connected,
  connectedSource,
  findTool,
  opVaults,
  PasswordSourceError,
  protonLogin,
  protonSignOut,
  protonVaults,
  SOURCES,
  type SourceHost,
  type SourceKind,
  signerAccount,
  toolRun,
} from '../service/password-source.ts';
import { confirm, type Prompter, TtyPrompter } from './prompt.ts';

type Out = (text: string) => void;

export interface ConnectIo {
  prompt: Prompter;
  out: Out;
  wait?: <T>(label: string, work: () => Promise<T>) => Promise<T>;
}

export interface ConnectRequest {
  kind: SourceKind;
  vault?: string;
  bin?: string;
  interactive: boolean;
  yes: boolean;
  confirmConnect: boolean;
}

interface Proof {
  vaults: string[];
  token: string | null;
  loggedInHere: boolean;
}

const NOTHING = 'Nothing changed.\n';

export type CliPrompter = Prompter & { close(): void };

function linesPrompter(): CliPrompter {
  let rl: Interface | null = null;
  const lines: string[] = [];
  const waiting: ((l: string | null) => void)[] = [];
  let closed = false;
  const open = () => {
    if (rl) return;
    rl = createInterface({ input: process.stdin, terminal: false });
    rl.on('line', (l) => {
      const w = waiting.shift();
      if (w) w(l);
      else lines.push(l);
    });
    rl.on('close', () => {
      closed = true;
      for (const w of waiting.splice(0)) w(null);
    });
  };
  const next = async (): Promise<string> => {
    open();
    const l =
      lines.length > 0
        ? (lines.shift() as string)
        : closed
          ? null
          : await new Promise<string | null>((r) => waiting.push(r));
    if (l === null) throw new PasswordSourceError('Stdin ended before all answers were read.');
    return l;
  };
  return {
    ask: async (_question, def) => {
      const a = await next();
      return a === '' && def !== undefined ? def : a;
    },
    secret: next,
    close: () => rl?.close(),
  };
}

export function cliPrompter(): CliPrompter {
  if (process.stdin.isTTY === true) {
    return Object.assign(new TtyPrompter(process.stdin, process.stderr), { close: () => {} });
  }
  return linesPrompter();
}

async function busy<T>(io: ConnectIo, label: string, work: () => Promise<T>): Promise<T> {
  return io.wait ? io.wait(label, work) : work();
}

const scope = (vault: string | null): string => (vault === null ? 'every vault' : `vault ${vault}`);

async function pickVault(
  io: ConnectIo,
  vaults: string[],
  req: ConnectRequest,
  current: string | null,
): Promise<string | null> {
  if (req.vault !== undefined) {
    if (!vaults.includes(req.vault)) {
      throw new PasswordSourceError(
        `No vault named ${req.vault}`,
        `it sees: ${vaults.join(', ') || 'no vaults'}`,
      );
    }
    return req.vault;
  }
  const kept = current !== null && vaults.includes(current) ? current : null;
  if (current !== null && kept === null) {
    if (!req.interactive) {
      throw new PasswordSourceError(
        `No vault named ${current}`,
        `it is the vault in use now, and the login sees: ${vaults.join(', ') || 'no vaults'}`,
      );
    }
    io.out(`The vault in use now, ${current}, is not visible any more.\n`);
  }
  if (!req.interactive) return kept;
  io.out(
    `Vaults: ${vaults.length === 0 ? '(none)' : vaults.join(', ')}. A vault of its own for your agents is safest.\n`,
  );
  const question =
    kept === null
      ? 'Vault to use (blank: every vault)'
      : `Vault to use (blank: ${kept}, all: every vault)`;
  const fallback = kept ?? (vaults.length === 1 ? (vaults[0] as string) : '');
  for (;;) {
    const a = (await io.prompt.ask(question, fallback)).trim();
    if (a === '') return null;
    if (vaults.includes(a)) return a;
    if (kept !== null && a === 'all') return null;
    io.out('No such vault.\n');
  }
}

async function confirmReplace(
  io: ConnectIo,
  cur: Connected,
  req: ConnectRequest,
): Promise<boolean> {
  const theirs = SOURCES[cur.kind];
  const words = `Replace ${theirs.name}? Agents stop using its logins. ${theirs.keepsLogins}`;
  if (req.yes) return true;
  if (!req.interactive) {
    throw new PasswordSourceError(`${theirs.name} is connected.`, 'add --yes to replace it');
  }
  if (await confirm(io.prompt, words, false)) return true;
  io.out(NOTHING);
  return false;
}

async function isWorking(host: SourceHost, cur: Connected): Promise<boolean> {
  if (cur.bin === null) return false;
  const def = SOURCES[cur.kind];
  if (!host.sys.checkTool(cur.bin, def.spec, cur.sha256 ?? undefined).ok) return false;
  if (cur.kind === '1password') return host.sys.exists(host.paths.opToken);
  const run = toolRun(def, host.paths, cur.bin, await signerAccount(host.sys, host.m));
  return (await protonVaults(host.sys, run)) !== null;
}

async function confirmChangedTool(
  io: ConnectIo,
  def: (typeof SOURCES)[SourceKind],
  was: string,
  now: string,
  req: ConnectRequest,
): Promise<boolean> {
  const cmd = def.spec.command;
  io.out(
    `${cmd} changed since it was trusted.\n  was ${was}\n  now ${now}\nMake sure it is genuine: the vendor's own download or your distribution's package.\n`,
  );
  if (req.yes) return true;
  if (!req.interactive) {
    throw new PasswordSourceError(
      `${cmd} changed since it was trusted.`,
      `check it is genuine, then add --yes (or run: sudo keyflap password-source trust ${cmd})`,
    );
  }
  if (await confirm(io.prompt, `${cmd} changed since it was trusted. Trust the new one?`, false)) {
    return true;
  }
  io.out(NOTHING);
  return false;
}

async function proveProton(io: ConnectIo, host: SourceHost, bin: string): Promise<Proof | null> {
  const { sys, paths, m } = host;
  const run = toolRun(SOURCES['proton-pass'], paths, bin, await signerAccount(sys, m));
  let vaults = await busy(io, 'Asking Proton Pass', () => protonVaults(sys, run));
  if (vaults !== null) return { vaults, token: null, loggedInHere: false };
  const token = (await io.prompt.secret('Proton Pass personal access token (not shown)')).trim();
  if (token === '') {
    io.out(NOTHING);
    return null;
  }
  const ok = await busy(io, 'Logging in', () => protonLogin(sys, run, token));
  if (!ok) throw new PasswordSourceError('pass-cli could not log in with that token.');
  vaults = await busy(io, 'Asking Proton Pass', () => protonVaults(sys, run));
  if (vaults === null) {
    await protonSignOut(host, bin, null, io.out);
    throw new PasswordSourceError('pass-cli is logged in but lists no vaults.');
  }
  return { vaults, token: null, loggedInHere: true };
}

async function proveOnePassword(
  io: ConnectIo,
  host: SourceHost,
  bin: string,
): Promise<Proof | null> {
  const { sys, paths, m } = host;
  const token = (await io.prompt.secret('1Password service account token (not shown)')).trim();
  if (token === '') {
    io.out(NOTHING);
    return null;
  }
  const run = toolRun(SOURCES['1password'], paths, bin, await signerAccount(sys, m), token);
  const vaults = await busy(io, 'Asking 1Password', () => opVaults(sys, run));
  if (vaults === null) {
    throw new PasswordSourceError(
      'op did not accept that token.',
      'check it is a service account token that has not expired, and that this computer is online',
    );
  }
  return { vaults, token, loggedInHere: false };
}

export async function connectPasswordSource(
  host: SourceHost,
  io: ConnectIo,
  req: ConnectRequest,
): Promise<boolean> {
  assertRoot(host.sys);
  const def = SOURCES[req.kind];
  const cur = connectedSource(host.sys, host.paths);
  const replacing = cur !== null && cur.kind !== req.kind;
  const same = cur !== null && cur.kind === req.kind ? cur : null;
  if (replacing && !(await confirmReplace(io, cur, req))) return false;
  if (
    same !== null &&
    req.confirmConnect &&
    req.interactive &&
    !req.yes &&
    req.bin === undefined &&
    req.vault === undefined &&
    (await isWorking(host, same))
  ) {
    io.out(`✓ ${def.name} is connected, ${scope(same.vault)}.\n`);
    if (!(await confirm(io.prompt, 'Change it?', false))) {
      io.out(NOTHING);
      return false;
    }
  }
  const configured =
    same?.bin && req.bin === undefined && host.sys.exists(same.bin) ? same.bin : req.bin;
  const tool = findTool(host.sys, def, configured);
  io.out(`✓ ${def.spec.command} found.\n`);
  if (
    same?.sha256 &&
    tool.bin === same.bin &&
    tool.sha256 !== same.sha256 &&
    !(await confirmChangedTool(io, def, same.sha256, tool.sha256, req))
  ) {
    return false;
  }
  const proof =
    req.kind === 'proton-pass'
      ? await proveProton(io, host, tool.bin)
      : await proveOnePassword(io, host, tool.bin);
  if (proof === null) return false;
  let applied = false;
  try {
    const vault = await pickVault(io, proof.vaults, req, same?.vault ?? null);
    if (
      !replacing &&
      req.confirmConnect &&
      !(await confirm(
        io.prompt,
        `${same !== null ? 'Update' : 'Connect'} ${def.name} (${scope(vault)})?`,
        false,
      ))
    ) {
      io.out(NOTHING);
      return false;
    }
    await busy(io, `Connecting ${def.name}`, () =>
      applyConnect(
        host,
        { kind: req.kind, bin: tool.bin, sha256: tool.sha256, vault, token: proof.token },
        io.out,
      ),
    );
    applied = true;
    io.out(`✓ ${def.name} connected, ${scope(vault)}. Agents can use its logins.\n`);
    return true;
  } finally {
    if (!applied && proof.loggedInHere) await protonSignOut(host, tool.bin, tool.sha256, io.out);
  }
}

export async function disconnectPasswordSource(host: SourceHost, out: Out): Promise<boolean> {
  assertRoot(host.sys);
  const before = await applyDisconnect(host, out);
  if (before === null) {
    out('No password manager is connected.\n');
    return false;
  }
  out(`✓ ${SOURCES[before.kind].name} disconnected. Agents use the passwords in Keyflap only.\n`);
  return true;
}
