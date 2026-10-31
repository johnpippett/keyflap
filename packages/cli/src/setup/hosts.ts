import { join } from 'node:path';
import type { AgentHost } from '../args.ts';
import { parseOwner } from '../hook-hermes.ts';
import {
  CODEX_HOOK_TIMEOUT,
  CODEX_PROFILE,
  codexConfigToml,
  codexHookCommand,
  HERMES_PLUGIN_DIR,
  HERMES_PLUGIN_NAME,
  hermesConfigYaml,
  hermesPluginConfig,
  type ServiceHost,
} from '../host-config.ts';
import { type Json, jsonDiff, lineDiff, parseJsonFile, stringify } from './claude-config.ts';
import type { ClaudeAction, SetupContext } from './steps.ts';
import type { FileOwner, System } from './system.ts';

export type OtherHost = Exclude<AgentHost, 'claude-code'>;

export function serviceHost(ctx: SetupContext): ServiceHost | undefined {
  return ctx.paths ? { wrapper: ctx.paths.wrapper, hookDir: ctx.paths.hookDir } : undefined;
}

export function hermesHome(sys: System, home: string): string {
  return sys.env.HERMES_HOME || join(home, '.hermes');
}

export function codexHome(sys: System, home: string): string {
  return sys.env.CODEX_HOME || join(home, '.codex');
}

function textAction(sys: System, path: string, owner: FileOwner, after: string): ClaudeAction {
  const before = sys.readUserFile(path, owner);
  const diff =
    before === after
      ? []
      : before === null
        ? [`+ new file, ${after.split('\n').length} lines`]
        : lineDiff(before.split('\n'), after.split('\n')).slice(0, 40);
  return { kind: 'file', path, before, after, diff, notes: [] };
}

export function planHermes(
  sys: System,
  o: {
    hermesHome: string;
    agentId: string;
    dataDir: string;
    owners: string[];
    service?: ServiceHost;
    owner: FileOwner;
  },
): ClaudeAction[] {
  const dir = join(o.hermesHome, 'plugins', HERMES_PLUGIN_NAME);
  const actions: ClaudeAction[] = [];
  for (const name of ['plugin.yaml', '__init__.py']) {
    const src = sys.readFile(join(HERMES_PLUGIN_DIR, name));
    if (src === null)
      throw new Error(`the plugin source is missing: ${join(HERMES_PLUGIN_DIR, name)}`);
    actions.push(textAction(sys, join(dir, name), o.owner, src));
  }
  const cfg = hermesPluginConfig(o.agentId, o.dataDir, o.owners, o.service);
  actions.push(
    textAction(sys, join(dir, 'config.json'), o.owner, stringify(cfg as unknown as Json)),
  );
  return actions;
}

export function mergeCodexHooks(
  doc: Json | undefined,
  command: string,
): { doc: Json; notes: string[] } {
  const group: Json = { hooks: [{ type: 'command', command, timeout: CODEX_HOOK_TIMEOUT }] };
  const isObj = (v: unknown): v is { [k: string]: Json } =>
    typeof v === 'object' && v !== null && !Array.isArray(v);
  const root = isObj(doc) ? { ...doc } : {};
  const hooks = isObj(root.hooks) ? { ...root.hooks } : {};
  const list = Array.isArray(hooks.UserPromptSubmit) ? hooks.UserPromptSubmit : [];
  const kept = list.filter((g) => !/ hook codex --agent /.test(JSON.stringify(g)));
  const notes = kept.length < list.length ? ['replaces the earlier keyflap hook'] : [];
  hooks.UserPromptSubmit = [...kept, group];
  root.hooks = hooks;
  return { doc: root, notes };
}

function codexHooksAction(
  sys: System,
  path: string,
  owner: FileOwner,
  command: string,
): ClaudeAction {
  const text = sys.readUserFile(path, owner);
  const parsed = parseJsonFile(text);
  if (parsed === null) throw new Error(`${path} is not plain JSON; merge it by hand`);
  const { doc, notes } = mergeCodexHooks(parsed, command);
  return {
    kind: 'file',
    path,
    before: text,
    after: stringify(doc),
    diff: jsonDiff(parsed, doc as { [k: string]: Json }),
    notes,
  };
}

async function askOwners(ctx: SetupContext): Promise<string[] | null> {
  for (;;) {
    const a = (
      await ctx.prompt.ask(
        'Your chat id(s) as platform:user_id, comma-separated (e.g. telegram:123456789; - to skip)',
        '',
      )
    ).trim();
    if (a === '-' || a === '') return null;
    try {
      return a.split(',').map((s) => {
        const o = parseOwner(s.trim());
        return `${o.platform}:${o.userId}`;
      });
    } catch (err) {
      ctx.out(`  ${(err as Error).message}\n`);
    }
  }
}

export async function configureOtherHost(
  ctx: SetupContext,
  host: OtherHost,
  agent: { id: string; name: string },
  tokenPath: string,
  apply: (actions: ClaudeAction[], what: string) => Promise<boolean | null>,
): Promise<{ ok: boolean; dir: string } | null> {
  const home = ctx.backend.user.home;
  const service = serviceHost(ctx);
  const dataDir = service ? service.hookDir : ctx.dataDir;
  const mcpPort = await ctx.backend.mcpPort();
  if (host === 'hermes') {
    const hh = hermesHome(ctx.sys, home);
    const owners = await askOwners(ctx);
    if (owners === null) {
      ctx.out(
        '  Skipped. `keyflap agent add <name> --host hermes` prints the config to merge by hand.\n',
      );
      return null;
    }
    let actions: ClaudeAction[];
    try {
      actions = planHermes(ctx.sys, {
        hermesHome: hh,
        agentId: agent.id,
        dataDir,
        owners,
        service,
        owner: ctx.backend.fileOwner,
      });
    } catch (err) {
      ctx.out(`  ✗ ${(err as Error).message}\n`);
      return null;
    }
    const ok = await apply(
      actions,
      `Hermes record ${owners.join(', ')}'s DMs for agent "${agent.name}"`,
    );
    if (ok === null) return null;
    ctx.ui.brief(
      'Two things are left for you: the agent token into Hermes, and its config.yaml. terminal.backend must be docker, or the model can read the host token. Tab shows both.',
      [
        '',
        '  Two things setup does not edit (do them yourself, then restart the gateway):',
        '',
        `  1. The agent token into ${hh}/.env (read from its file; nothing is printed):`,
        `       printf 'KEYFLAP_AGENT_TOKEN=%s\\n' "$(cat ${tokenPath})" >> ${hh}/.env`,
        '',
        `  2. Merge into ${hh}/config.yaml:`,
        '',
        hermesConfigYaml(mcpPort)
          .split('\n')
          .map((l) => (l ? `     ${l}` : l))
          .join('\n'),
        '  terminal.backend MUST be docker: with the default local backend the model can read the',
        `  host token in ${dataDir} and forge intents (docs/integrations/hermes.md).`,
        '',
        '  Then: hermes gateway restart. Only your direct messages to the gateway are recorded,',
        '  never `hermes chat` turns, groups, webhooks or messages sent while Hermes is busy.',
        '',
      ].join('\n'),
    );
    return { ok, dir: hh };
  }
  const ch = codexHome(ctx.sys, home);
  const command = codexHookCommand(agent.id, dataDir, service);
  let actions: ClaudeAction[];
  try {
    actions = [codexHooksAction(ctx.sys, join(ch, 'hooks.json'), ctx.backend.fileOwner, command)];
  } catch (err) {
    ctx.out(`  ✗ ${(err as Error).message}\n`);
    return null;
  }
  const ok = await apply(actions, `Codex use agent "${agent.name}"`);
  if (ok === null) return null;
  ctx.ui.brief(
    `Two things are left for you. Merge the config.toml part: its "${CODEX_PROFILE}" profile keeps the model away from the host token. Then start Codex with the agent token, and trust the hook in /hooks. Tab shows both.`,
    [
      '',
      `  Setup does not edit ${ch}/config.toml (TOML). Merge this (top-level keys above every table):`,
      '',
      codexConfigToml({ dataDir, mcpPort, ...(service ? { service } : {}) })
        .split('\n')
        .map((l) => (l ? `     ${l}` : l))
        .join('\n'),
      `  The "${CODEX_PROFILE}" profile keeps sandboxed commands out of ${dataDir}; without it the`,
      '  model can read the host token and forge intents (docs/integrations/codex.md).',
      '',
      '  Start Codex with the agent token in its environment (read from its file):',
      `       export KEYFLAP_AGENT_TOKEN="$(cat ${tokenPath})"`,
      '  then run /hooks in Codex and trust the keyflap hook, and /mcp to check the connection.',
      '',
    ].join('\n'),
  );
  return { ok, dir: ch };
}

export function detectHosts(sys: System, home: string): AgentHost[] {
  const found: Record<AgentHost, boolean> = {
    'claude-code': sys.exists(join(home, '.claude')) || sys.exists(join(home, '.claude.json')),
    codex: sys.exists(codexHome(sys, home)),
    hermes: sys.exists(hermesHome(sys, home)),
  };
  return (Object.keys(found) as AgentHost[]).filter((h) => found[h]);
}
