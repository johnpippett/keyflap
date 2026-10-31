import { join } from 'node:path';
import { homeRelative, shellQuote } from './agent.ts';
import { defaultDataDir } from './args.ts';

export const HERMES_PLUGIN_DIR = join(
  import.meta.dirname,
  'integrations',
  'hermes',
  'keyflap-intent',
);
export const HERMES_PLUGIN_NAME = 'keyflap-intent';
export const AGENT_TOKEN_ENV = 'KEYFLAP_AGENT_TOKEN';

export interface ServiceHost {
  wrapper: string;
  hookDir: string;
}

const MAIN = join(import.meta.dirname, 'main.ts');

export function keyflapArgv(service?: ServiceHost): string[] {
  return service ? [service.wrapper] : [process.execPath, MAIN];
}

function dataDirArgs(dataDir: string, service?: ServiceHost): string[] {
  if (service) return ['--service'];
  return dataDir !== defaultDataDir() ? ['--data-dir', dataDir] : [];
}

export interface HermesPluginConfig {
  command: string[];
  agent: string;
  owners: string[];
  profile: string | null;
  dataDir: string | null;
  service: boolean;
}

export function hermesPluginConfig(
  agentId: string,
  dataDir: string,
  owners: string[],
  service?: ServiceHost,
): HermesPluginConfig {
  return {
    command: keyflapArgv(service),
    agent: agentId,
    owners,
    profile: null,
    dataDir: service || dataDir === defaultDataDir() ? null : dataDir,
    service: service !== undefined,
  };
}

export function hermesConfigYaml(mcpPort: number): string {
  return [
    'mcp_servers:',
    '  keyflap:',
    `    url: "http://127.0.0.1:${mcpPort}/mcp"`,
    '    headers:',
    `      Authorization: "Bearer \${${AGENT_TOKEN_ENV}}"`,
    'plugins:',
    '  enabled:',
    `    - ${HERMES_PLUGIN_NAME}         # add to your existing list`,
    'terminal:',
    '  backend: docker               # REQUIRED (see below): shell, file tools and code run in a container',
    '  docker_forward_env: []        # forward nothing from your environment',
    '  docker_volumes: []            # never mount your home, the Keyflap data dir or ~/.hermes',
    '  docker_mount_cwd_to_workspace: false',
    'gateway:',
    '  strict: true                  # attachments only from the Hermes cache / allowlisted dirs',
    '',
  ].join('\n');
}

export function hermesInstallCommands(cfg: HermesPluginConfig, hermesHome = '~/.hermes'): string {
  return [
    `mkdir -p ${hermesHome}/plugins`,
    `cp -r ${shellQuote(HERMES_PLUGIN_DIR)} ${hermesHome}/plugins/${HERMES_PLUGIN_NAME}`,
    `cat > ${hermesHome}/plugins/${HERMES_PLUGIN_NAME}/config.json <<'EOF'`,
    JSON.stringify(cfg, null, 2),
    'EOF',
    '',
  ].join('\n');
}

export function hermesText(o: {
  agent: { id: string; name: string; token: string };
  dataDir: string;
  mcpPort: number;
  owners: string[];
  service?: ServiceHost;
}): string {
  const owners = o.owners.length > 0 ? o.owners : ['telegram:<your numeric Telegram user id>'];
  const cfg = hermesPluginConfig(o.agent.id, o.dataDir, owners, o.service);
  const tokenDir = o.service ? o.service.hookDir : homeRelative(o.dataDir);
  return [
    `── Hermes Agent ── (details and the security requirements: docs/integrations/hermes.md)`,
    '',
    `1. ~/.hermes/.env (the agent token; Hermes expands \${${AGENT_TOKEN_ENV}} in config.yaml):`,
    '',
    `  ${AGENT_TOKEN_ENV}=${o.agent.token}`,
    '',
    '2. ~/.hermes/config.yaml (merge into your config):',
    '',
    hermesConfigYaml(o.mcpPort),
    'WARNING: terminal.backend MUST be docker (or another container backend). With the default',
    "`local` backend the model's terminal and file tools run as you and can read the host token",
    `in ${tokenDir}; a prompt-injected agent could then record its own "intent" and the`,
    "approval prompt would show words you never sent. Hermes's own SECURITY.md says its",
    'command denylists do not contain a hostile model. Never mount your home directory,',
    `${tokenDir} or ~/.hermes into the container.`,
    '',
    `3. The plugin (records your own DMs to Hermes as the intent of agent "${o.agent.name}"):`,
    '',
    hermesInstallCommands(cfg),
    o.owners.length > 0
      ? 'owners: the platform:user_id pairs whose direct messages count as yours.'
      : 'Replace the owner with your own platform:user_id (telegram, discord, slack, signal, whatsapp,\n' +
        'matrix, mattermost, bluebubbles). Only direct messages from an owner are recorded.',
    '',
    'Then restart the gateway (hermes gateway restart); `hermes plugins list` should show',
    `${HERMES_PLUGIN_NAME} enabled. Send your bot a DM, then check \`keyflap audit tail\` for intent.recorded.`,
    '',
    'Known limits: only gateway direct messages are recorded, never `hermes chat` (CLI) turns,',
    'group chats, webhooks or API clients; a message you send while Hermes is busy goes to',
    'its steering lane and is not recorded (send it again when the turn ends); one Keyflap',
    'agent per Hermes profile.',
    '',
  ].join('\n');
}

export function codexHookCommand(agentId: string, dataDir: string, service?: ServiceHost): string {
  return [
    ...keyflapArgv(service),
    'hook',
    'codex',
    '--agent',
    agentId,
    ...dataDirArgs(dataDir, service),
  ]
    .map(shellQuote)
    .join(' ');
}

export function codexDenyPath(dataDir: string, service?: ServiceHost): string {
  return service ? service.hookDir : dataDir;
}

export const CODEX_PROFILE = 'keyflap-protected';
export const CODEX_HOOK_TIMEOUT = 15;

const tq = (s: string) => JSON.stringify(s);

export function codexConfigToml(o: { dataDir: string; mcpPort: number; service?: ServiceHost }) {
  return [
    `default_permissions = ${tq(CODEX_PROFILE)}`,
    'approval_policy = { granular = { sandbox_approval = false, request_permissions = false, rules = true, skill_approval = true, mcp_elicitations = true } }',
    '',
    `[permissions.${CODEX_PROFILE}]`,
    `description = "Workspace editing; the Keyflap data dir is denied to commands"`,
    'extends = ":workspace"',
    '',
    `[permissions.${CODEX_PROFILE}.filesystem]`,
    `${tq(codexDenyPath(o.dataDir, o.service))} = "deny"`,
    '',
    '[mcp_servers.keyflap]',
    `url = ${tq(`http://127.0.0.1:${o.mcpPort}/mcp`)}`,
    `bearer_token_env_var = ${tq(AGENT_TOKEN_ENV)}`,
    '',
  ].join('\n');
}

export function codexHooksJson(agentId: string, dataDir: string, service?: ServiceHost) {
  return {
    hooks: {
      UserPromptSubmit: [
        {
          hooks: [
            {
              type: 'command',
              command: codexHookCommand(agentId, dataDir, service),
              timeout: CODEX_HOOK_TIMEOUT,
            },
          ],
        },
      ],
    },
  };
}

export function codexText(o: {
  agent: { id: string; name: string; token: string };
  dataDir: string;
  mcpPort: number;
  service?: ServiceHost;
}): string {
  return [
    '── Codex CLI ── (details and the security requirements: docs/integrations/codex.md)',
    '',
    `1. Start Codex with the agent token in its environment (it reads ${AGENT_TOKEN_ENV} for the`,
    '   MCP connection; keep it out of committed files):',
    '',
    `  export ${AGENT_TOKEN_ENV}=${shellQuote(o.agent.token)}`,
    '',
    '2. ~/.codex/config.toml (merge; the two top-level keys must stay above every [table]):',
    '',
    codexConfigToml(o),
    `The permission profile denies ${codexDenyPath(o.dataDir, o.service)} to every sandboxed command, so the`,
    "model can't read the host token; sandbox_approval = false means it can't ask to run a",
    "command outside the sandbox either. Don't run Codex with --dangerously-bypass-approvals-and-sandbox",
    '(--yolo) or --sandbox danger-full-access in sessions that use Keyflap.',
    '',
    '3. ~/.codex/hooks.json (merge; or the same as [[hooks.UserPromptSubmit]] tables in config.toml):',
    '',
    JSON.stringify(codexHooksJson(o.agent.id, o.dataDir, o.service), null, 2),
    '',
    '4. Start Codex, run /hooks and trust the keyflap hook (Codex runs no new or changed hook',
    '   until you do), and /mcp to check the "keyflap" server is connected.',
    '',
  ].join('\n');
}
