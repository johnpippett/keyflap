import { join } from 'node:path';
import type { Check } from './doctor.ts';
import { HERMES_PLUGIN_NAME } from './host-config.ts';
import type { AgentInfo } from './setup/backend.ts';
import { parseJsonFile } from './setup/claude-config.ts';
import type { System } from './setup/system.ts';

const CONTAINER_BACKENDS = ['docker', 'singularity', 'modal', 'daytona', 'vercel_sandbox'];

export function hermesTerminalBackend(yaml: string): string | null {
  const lines = yaml.split('\n');
  const start = lines.findIndex((l) => /^terminal:\s*(#.*)?$/.test(l));
  if (start < 0) return null;
  for (const l of lines.slice(start + 1)) {
    if (/^\S/.test(l)) break;
    const m = /^\s+backend:\s*["']?([A-Za-z0-9_-]+)["']?\s*(#.*)?$/.exec(l);
    if (m) return m[1] as string;
  }
  return null;
}

function activeAgent(agents: AgentInfo[] | null, id: unknown): Check['status'] | 'unknown' {
  if (agents === null) return 'unknown';
  return agents.some((a) => a.id === id && !a.revoked) ? 'ok' : 'fail';
}

export function hostChecks(o: {
  sys: System;
  read: (path: string) => string | null;
  home: string;
  denyDir: string;
  agents: AgentInfo[] | null;
}): Check[] {
  const { sys } = o;
  const checks: Check[] = [];
  const hermes = sys.env.HERMES_HOME || join(o.home, '.hermes');
  const pluginCfg = join(hermes, 'plugins', HERMES_PLUGIN_NAME, 'config.json');
  const cfgText = o.read(pluginCfg);
  if (cfgText !== null) {
    const cfg = parseJsonFile(cfgText) as { agent?: unknown; owners?: unknown } | null | undefined;
    const ownersOk = Array.isArray(cfg?.owners) && cfg.owners.length > 0;
    const agent = activeAgent(o.agents, cfg?.agent);
    const pluginOk =
      sys.exists(join(hermes, 'plugins', HERMES_PLUGIN_NAME, '__init__.py')) && ownersOk;
    checks.push(
      !pluginOk || agent === 'fail'
        ? {
            id: 'hermes-plugin',
            status: 'fail',
            detail: !pluginOk
              ? `${pluginCfg}: plugin files or owners missing`
              : 'the keyflap-intent plugin points at an unknown or revoked agent',
            fix: 'keyflap setup --host hermes (or keyflap agent add <name> --host hermes)',
          }
        : {
            id: 'hermes-plugin',
            status: 'ok',
            detail: `keyflap-intent plugin in ${hermes}/plugins`,
          },
    );
    const yaml = o.read(join(hermes, 'config.yaml')) ?? '';
    const enabled = new RegExp(`^\\s*-\\s*["']?${HERMES_PLUGIN_NAME}["']?\\s*(#.*)?$`, 'm').test(
      yaml,
    );
    const backend = hermesTerminalBackend(yaml) ?? 'local';
    checks.push(
      CONTAINER_BACKENDS.includes(backend)
        ? { id: 'hermes-backend', status: 'ok', detail: `terminal.backend: ${backend}` }
        : {
            id: 'hermes-backend',
            status: 'fail',
            detail: `terminal.backend is ${backend}: the model's tools can read the host token`,
            fix: `set terminal.backend: docker in ${hermes}/config.yaml (docs/integrations/hermes.md)`,
          },
    );
    checks.push(
      enabled
        ? { id: 'hermes-enabled', status: 'ok', detail: 'plugins.enabled lists keyflap-intent' }
        : {
            id: 'hermes-enabled',
            status: 'warn',
            detail: 'keyflap-intent is not in plugins.enabled: no intents are recorded',
            fix: `add "- ${HERMES_PLUGIN_NAME}" under plugins.enabled in ${hermes}/config.yaml`,
          },
    );
  }
  const codex = sys.env.CODEX_HOME || join(o.home, '.codex');
  const hooks = o.read(join(codex, 'hooks.json'));
  if (hooks !== null && / hook codex --agent /.test(hooks)) {
    const id = / hook codex --agent '?([0-9a-f-]{36})/.exec(hooks)?.[1];
    const agent = activeAgent(o.agents, id);
    checks.push(
      agent === 'fail'
        ? {
            id: 'codex-hook',
            status: 'fail',
            detail: 'the Codex hook points at an unknown or revoked agent',
            fix: 'keyflap setup --host codex',
          }
        : {
            id: 'codex-hook',
            status: 'ok',
            detail: `UserPromptSubmit hook in ${codex}/hooks.json`,
          },
    );
    const toml = o.read(join(codex, 'config.toml')) ?? '';
    const rel = o.denyDir.startsWith(`${o.home}/`) ? `~${o.denyDir.slice(o.home.length)}` : null;
    const denied = [o.denyDir, rel]
      .filter((p): p is string => p !== null)
      .some((p) => toml.includes(`${JSON.stringify(p)} = "deny"`));
    const profile = /^default_permissions\s*=/m.test(toml);
    checks.push(
      denied && profile
        ? { id: 'codex-deny', status: 'ok', detail: 'a permission profile denies the data dir' }
        : {
            id: 'codex-deny',
            status: 'fail',
            detail: `${codex}/config.toml does not deny ${o.denyDir} to the model's commands`,
            fix: 'merge the config.toml lines keyflap agent add --host codex prints (docs/integrations/codex.md)',
          },
    );
  }
  return checks;
}
