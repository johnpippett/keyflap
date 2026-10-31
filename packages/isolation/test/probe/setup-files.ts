import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';

const APP = '/opt/keyflap/app/packages/cli/src/setup';
const { realSystem } = (await import(
  `${APP}/system.ts`
)) as typeof import('../../../cli/src/setup/system.ts');
const { applyPlan } = (await import(
  `${APP}/steps.ts`
)) as typeof import('../../../cli/src/setup/steps.ts');
const { emptyState, saveState } = (await import(
  `${APP}/state.ts`
)) as typeof import('../../../cli/src/setup/state.ts');

const args = JSON.parse(process.argv[2] ?? '{}') as {
  home: string;
  uid: number;
  gid: number;
  signerConfig: string;
  coreConfig: string;
  keyStore: string;
  hookDir: string;
};
const owner = { uid: args.uid, gid: args.gid };
const sys = realSystem();
const sha = (p: string) => createHash('sha256').update(readFileSync(p)).digest('hex');
const ids = () => ({
  euid: process.geteuid?.(),
  egid: process.getegid?.(),
  groups: process.getgroups?.(),
});
const start = ids();

function attempt(fn: () => unknown): string {
  try {
    const v = fn();
    return typeof v === 'string' ? `read ${v.length} bytes` : 'ok';
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    return err.code ?? err.constructor.name;
  }
}

async function write(path: string, after: string, before: string | null = null) {
  const out: string[] = [];
  const ok = await applyPlan(
    sys,
    [{ kind: 'file', path, before, after, diff: ['+ keyflap'], notes: [] }],
    { stamp: 'isolation', owner, out: (t) => out.push(t) },
  );
  return { ok, out: out.join('') };
}

const signerCfg = args.signerConfig;
const coreCfg = args.coreConfig;
const before = { signer: sha(signerCfg), core: sha(coreCfg) };
const h = args.home;

const r = {
  readLinkToKeyStore: attempt(() => sys.readUserFile(`${h}/.claude/settings.json`, owner)),
  readKeyStoreDirect: attempt(() => sys.readUserFile(args.keyStore, owner)),
  readRootFile: attempt(() => sys.readUserFile(coreCfg, owner)),
  writeLinkToCoreCfg: await write(`${h}/.claude.json`, '{"mcpServers":{}}\n'),
  writeThroughLinkedDir: await write(`${h}/linked-dir/settings.json`, '{}\n'),
  saveStateLinked: attempt(() => saveState(sys, args.hookDir, emptyState(8765), owner)),
  writeNormal: await write(`${h}/proj/.mcp.json`, '{"mcpServers":{}}\n'),
  normalOwner: statSync(`${h}/proj/.mcp.json`).uid,
  normalDirOwner: statSync(`${h}/proj`).uid,
  rewriteNormal: await write(
    `${h}/proj/.mcp.json`,
    '{"mcpServers":{"k":{}}}\n',
    '{"mcpServers":{}}\n',
  ),
  backupOwner: statSync(`${h}/proj/.mcp.json.keyflap-backup-isolation`).uid,
  unchanged: { signer: sha(signerCfg) === before.signer, core: sha(coreCfg) === before.core },
  idsRestored: JSON.stringify(ids()) === JSON.stringify(start),
  euid: process.geteuid?.(),
};
process.stdout.write(`${JSON.stringify(r)}\n`);
