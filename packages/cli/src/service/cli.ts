import type { AgentListing, PasswordRow } from '@aab/core';
import { AdminCallError, adminCall } from '@aab/signer/admin-wire';
import type { AddressState } from '@aab/signer/approver-address';
import { claudeCodeSnippet, formatAgents, shellQuote } from '../agent.ts';
import type { Command } from '../args.ts';
import { formatPasswords, secretReader } from '../password.ts';
import { formatPreview, planImport, readExport, runImport } from '../password-import.ts';
import { realSystem, type System } from '../setup/system.ts';
import { addressRefusalText, clearApproverAddress, serviceAddressWords } from './address.ts';
import { requireServiceManager, type ServiceManager } from './manager.ts';
import { SERVICE_PATHS, type ServicePaths } from './paths.ts';

type Out = (text: string) => void;

export class ServiceCliError extends Error {}

function explain(err: unknown, socket: string, m: ServiceManager): never {
  if (err instanceof AdminCallError) {
    if (err.code === 'permission') {
      throw new ServiceCliError(
        `${socket} is root-only: run this with sudo (sudo keyflap …). Admin commands are not ` +
          'available to your user or its agents (docs/ISOLATION_PLAN.md D3).',
      );
    }
    if (err.code === 'unreachable') {
      throw new ServiceCliError(
        `the broker service isn't running (${err.message}). Check: ${m.statusCommand(['core', 'signer'], false)}`,
      );
    }
    throw new ServiceCliError(err.message);
  }
  throw err;
}

const adminCaller =
  (m: ServiceManager) =>
  async <T>(socket: string, op: string, params: Record<string, unknown> = {}) => {
    try {
      return await adminCall<T>(socket, op, params);
    } catch (err) {
      explain(err, socket, m);
    }
  };

interface CoreStatus {
  mode: string;
  mcpUrl: string | null;
  intentSocket: string;
  agents: number;
  passwords: number;
  passwordSource: string | null;
  signer: string;
}

function mcpPortOf(status: CoreStatus): number {
  const port = status.mcpUrl ? Number(new URL(status.mcpUrl).port) : Number.NaN;
  return Number.isInteger(port) && port > 0 ? port : 8765;
}

export async function runServiceCommand(
  cmd: Command,
  out: Out,
  paths: ServicePaths = SERVICE_PATHS,
  m: ServiceManager = requireServiceManager(),
  sys: System = realSystem(),
): Promise<void> {
  const call = adminCaller(m);
  switch (cmd.kind) {
    case 'daemon':
      throw new ServiceCliError(
        `the broker runs as a system service here (${m.unit('core')}, ${m.unit('signer')}): ` +
          `use ${m.daemonHint}. \`keyflap daemon --unprotected\` is for a dev checkout.`,
      );
    case 'status': {
      const core = await call<CoreStatus>(paths.adminSocket, 'status');
      const signer = await call<{
        approvers: number;
        phoneLatched: boolean;
        sources: string[];
        address: AddressState;
      }>(paths.signerAdminSocket, 'status');
      const address = serviceAddressWords(signer.address ?? { kind: 'unwatched' }, {
        sys,
        m,
        paths,
      });
      const report = await call<{ text: string }>(paths.adminSocket, 'status.report', {
        json: cmd.json,
      });
      if (cmd.json) {
        out(
          `${JSON.stringify({ service: { core, signer }, ...JSON.parse(report.text) }, null, 2)}\n`,
        );
        return;
      }
      out(
        [
          `Mode:        service (${m.unit('core')}, ${m.unit('signer')} under ${m.kind})`,
          `MCP:         ${core.mcpUrl}`,
          `Intents:     ${core.intentSocket}`,
          `Signer:      ${core.signer}`,
          `Phones:      ${signer.approvers} paired${signer.approvers === 0 ? ' (run: sudo keyflap approver pair)' : ''}`,
          `Address:     ${address.line}`,
          ...(address.fix ? [`             fix: ${address.fix}`] : []),
          '',
        ].join('\n'),
      );
      out(report.text);
      return;
    }
    case 'password-source-add': {
      const { connectPasswordSource, cliPrompter } = await import(
        '../setup/password-source-flow.ts'
      );
      const { PasswordSourceError } = await import('./password-source.ts');
      const interactive = process.stdin.isTTY === true;
      const prompt = cliPrompter();
      try {
        await connectPasswordSource(
          { sys, paths, m },
          { prompt, out },
          {
            kind: cmd.source,
            ...(cmd.vault !== undefined ? { vault: cmd.vault } : {}),
            ...(cmd.bin !== undefined ? { bin: cmd.bin } : {}),
            interactive,
            yes: cmd.yes,
            confirmConnect: false,
          },
        );
      } catch (err) {
        if (err instanceof PasswordSourceError) {
          throw new ServiceCliError(err.fix ? `${err.message}\n  fix: ${err.fix}` : err.message);
        }
        throw err;
      } finally {
        prompt.close();
      }
      return;
    }
    case 'password-source-remove': {
      const { disconnectPasswordSource } = await import('../setup/password-source-flow.ts');
      const { PasswordSourceError } = await import('./password-source.ts');
      try {
        await disconnectPasswordSource({ sys, paths, m }, out);
      } catch (err) {
        if (err instanceof PasswordSourceError) {
          throw new ServiceCliError(err.fix ? `${err.message}\n  fix: ${err.fix}` : err.message);
        }
        throw err;
      }
      return;
    }
    case 'password-source-trust': {
      const { trustTool } = await import('./tool-trust.ts');
      trustTool(cmd.tool, out, { paths });
      return;
    }
    case 'policy-set': {
      const { text } = await call<{ text: string }>(paths.adminSocket, 'policy.set', {
        site: cmd.site,
        agent: cmd.agent,
        mode: cmd.mode,
        allowForMs: cmd.allowForMs,
        ...(cmd.sessionTtlMs !== undefined ? { sessionTtlMs: cmd.sessionTtlMs } : {}),
      });
      out(text);
      return;
    }
    case 'policy-list': {
      const { text } = await call<{ text: string }>(paths.adminSocket, 'policy.list', {
        agent: cmd.agent,
        json: cmd.json,
      });
      out(text);
      return;
    }
    case 'policy-remove': {
      const { text } = await call<{ text: string }>(paths.adminSocket, 'policy.remove', {
        site: cmd.site,
        agent: cmd.agent,
      });
      out(text);
      return;
    }
    case 'audit-verify': {
      const r = await call<{ text: string; intact: boolean }>(paths.adminSocket, 'audit.verify');
      out(r.text);
      if (!r.intact) throw new ServiceCliError('the audit hash chain is broken');
      return;
    }
    case 'audit-tail': {
      const { text } = await call<{ text: string }>(paths.adminSocket, 'audit.tail', {
        limit: cmd.limit,
        json: cmd.json,
      });
      out(text);
      return;
    }
    case 'agent-add': {
      const agent = await call<{ id: string; name: string; token: string }>(
        paths.adminSocket,
        'agent.add',
        { name: cmd.name },
      );
      const status = await call<CoreStatus>(paths.adminSocket, 'status');
      if (cmd.host !== undefined && cmd.host !== 'claude-code') {
        const { agentAddedText } = await import('../agent.ts');
        const { codexText, hermesText } = await import('../host-config.ts');
        const service = { wrapper: paths.wrapper, hookDir: paths.hookDir };
        const o = { agent, dataDir: paths.hookDir, mcpPort: mcpPortOf(status), service };
        const body =
          cmd.host === 'hermes' ? hermesText({ ...o, owners: cmd.owners ?? [] }) : codexText(o);
        out([...agentAddedText(agent), body].join('\n'));
        return;
      }
      const hook = `${paths.wrapper} hook claude-code --agent ${shellQuote(agent.id)} --service`;
      const { mcp, settings } = claudeCodeSnippet(agent, paths.hookDir, mcpPortOf(status), {
        hookCommand: hook,
      });
      out(
        [
          `Added agent "${agent.name}" (id ${agent.id}).`,
          '',
          'Agent token (shown once; the broker keeps only its hash):',
          '',
          `  ${agent.token}`,
          '',
          "The token is the agent's own identity for the MCP endpoint. It is NOT the host token,",
          'and it is fine for the agent to know it. Keep it out of committed files:',
          '',
          `  export KEYFLAP_AGENT_TOKEN=${shellQuote(agent.token)}`,
          '',
          '── Claude Code ── (details: docs/integrations/claude-code.md, service mode: docs/integrations/service-mode.md)',
          '',
          '.mcp.json (project root):',
          JSON.stringify(mcp, null, 2),
          '',
          `.claude/settings.json (merge into your settings). The hook reads your copy of the host token in ${paths.hookDir};`,
          'the sandbox and deny rules keep the model from reading it:',
          JSON.stringify(settings, null, 2),
          '',
        ].join('\n'),
      );
      return;
    }
    case 'agent-list': {
      const { agents } = await call<{ agents: AgentListing[] }>(paths.adminSocket, 'agent.list');
      out(formatAgents(agents, cmd.json));
      return;
    }
    case 'agent-revoke': {
      const { revoked } = await call<{ revoked: boolean }>(paths.adminSocket, 'agent.revoke', {
        id: cmd.id,
      });
      if (!revoked) throw new ServiceCliError(`no active agent with id ${cmd.id}`);
      out(`Revoked agent ${cmd.id}. Its token and browser session stop now.\n`);
      return;
    }
    case 'password-add': {
      const read = secretReader();
      const password = await read('Password: ');
      if (password.length === 0) throw new ServiceCliError('empty password');
      const totp = cmd.totp ? await read('TOTP secret or otpauth:// URI: ') : null;
      const added = await call<{ id: string; domain: string }>(paths.adminSocket, 'password.add', {
        site: cmd.site,
        username: cmd.username,
        password,
        ...(totp !== null ? { totp } : {}),
      });
      out(
        `Added a password${totp !== null ? ' + TOTP' : ''} for ${added.domain}` +
          `${cmd.username ? ` (username ${cmd.username})` : ''}, id ${added.id}. Usable now.\n`,
      );
      return;
    }
    case 'password-list': {
      const { passwords } = await call<{ passwords: PasswordRow[] }>(
        paths.adminSocket,
        'password.list',
      );
      out(formatPasswords(passwords, cmd.json));
      return;
    }
    case 'password-import': {
      const parsed = readExport(cmd.file);
      const { passwords } = await call<{ passwords: PasswordRow[] }>(
        paths.adminSocket,
        'password.list',
      );
      const existing = passwords
        .filter((r) => r.source === 'signer')
        .map((r) => ({ domain: r.registrable_domain, username: r.username }));
      const plan = planImport(parsed, cmd, existing);
      if (plan.preview) {
        out(formatPreview(plan, cmd.file));
        return;
      }
      const r = await runImport(
        plan,
        (l) =>
          adminCall<{ id: string; domain: string }>(paths.adminSocket, 'password.add', {
            site: l.url,
            username: l.username,
            password: l.password,
            ...(l.totpText !== null ? { totp: l.totpText } : {}),
          }),
        out,
        cmd.file,
      );
      if (r.stored > 0) out('Usable now.\n');
      if (r.failed > 0) throw new ServiceCliError(`${r.failed} login(s) not stored`);
      return;
    }
    case 'password-remove': {
      const { removed } = await call<{ removed: boolean }>(paths.adminSocket, 'password.remove', {
        id: cmd.id,
      });
      if (!removed) throw new ServiceCliError(`no password with id ${cmd.id}`);
      out(`Removed password ${cmd.id}.\n`);
      return;
    }
    case 'approver-pair': {
      const state = await clearApproverAddress(call, paths);
      if (state.kind === 'latched' || state.kind === 'paused') {
        throw new ServiceCliError(addressRefusalText(state, { sys, m, paths }));
      }
      const r = await call<{ url: string; origin: string; validMinutes: number }>(
        paths.adminSocket,
        'approver.pair',
      );
      out(
        [
          `Open this one-time link on your phone (valid ${r.validMinutes} minutes, single use):`,
          '',
          `  ${r.url}`,
          '',
          'Whoever opens it first becomes an approver (or, if a phone is already paired, asks',
          'that phone to approve). Never paste it into an agent session.',
          '',
        ].join('\n'),
      );
      if (process.stdout.isTTY) {
        const { encodeQr, renderQrTerminal } = await import('@aab/approver');
        out(`${renderQrTerminal(encodeQr(r.url), process.stdout)}\n\n`);
      }
      out(
        'On an iPhone, pair in Safari first, then Share > Add to Home Screen: iOS copies the\n' +
          'pairing into the home-screen app only when you add it.\n',
      );
      return;
    }
    case 'approver-list': {
      const { approvers, native = [] } = await call<{
        approvers: { credentialId: string; origin: string; createdAt: number }[];
        native?: { keyId: string; origin: string; createdAt: number }[];
      }>(paths.signerAdminSocket, 'approver.list');
      const items = [
        ...approvers.map((a) => ({
          id: a.credentialId,
          type: 'passkey',
          origin: a.origin,
          createdAt: a.createdAt,
        })),
        ...native.map((a) => ({
          id: a.keyId,
          type: 'ios-app',
          origin: a.origin,
          createdAt: a.createdAt,
        })),
      ];
      if (cmd.json) {
        out(`${JSON.stringify(items, null, 2)}\n`);
      } else if (items.length === 0) {
        out('No phone approvers. Pair one with: sudo keyflap approver pair\n');
      } else {
        for (const a of items) {
          out(
            `${a.id}  ${a.type.padEnd(7)}  ${a.origin}  ${new Date(a.createdAt).toISOString()}\n`,
          );
        }
      }
      return;
    }
    case 'approver-qr':
      throw new ServiceCliError(
        `in service mode, \`sudo keyflap approver pair\` opens a pairing link and shows its QR code`,
      );
    case 'approver-remove': {
      const { removed } = await call<{ removed: boolean }>(
        paths.signerAdminSocket,
        'approver.remove',
        { credentialId: cmd.id },
      );
      if (!removed) throw new ServiceCliError(`no phone approver with id ${cmd.id}`);
      out(
        `Removed phone approver ${cmd.id}. Its device can no longer approve.` +
          ` With no phone left, \`sudo keyflap approver pair\` offers first-use pairing again.\n`,
      );
      return;
    }
    case 'sessions-list': {
      const { text } = await call<{ text: string }>(paths.adminSocket, 'sessions.list', {
        agent: cmd.agent,
        json: cmd.json,
      });
      out(text);
      return;
    }
    case 'sessions-clear': {
      const r = await call<{ agents: number; site: string | null; cookies: number; pages: number }>(
        paths.adminSocket,
        'sessions.clear',
        {
          ...(cmd.all ? { all: true } : { agent: cmd.agent }),
          ...(cmd.site ? { site: cmd.site } : {}),
        },
      );
      out(
        `Cleared ${r.site ?? 'every site'} for ${r.agents} agent(s): ${r.cookies} cookies, ${r.pages} pages closed.\n`,
      );
      return;
    }
    case 'sessions-keep': {
      const r = await call<{ site: string; added: boolean }>(paths.adminSocket, 'sessions.keep', {
        site: cmd.site,
        ...(cmd.agent ? { agent: cmd.agent } : {}),
      });
      out(
        `${r.added ? 'Keeping' : 'Already keeping'} ${r.site} signed in across restarts for ${cmd.agent ? `agent ${cmd.agent}` : 'every agent'}.\n`,
      );
      return;
    }
    case 'sessions-unkeep': {
      const r = await call<{ site: string; removed: boolean }>(
        paths.adminSocket,
        'sessions.unkeep',
        {
          site: cmd.site,
          ...(cmd.agent ? { agent: cmd.agent } : {}),
        },
      );
      out(
        r.removed
          ? `No longer keeping ${r.site}; it was dropped from the saved state.\n`
          : `${r.site} was not kept.\n`,
      );
      return;
    }
    case 'help':
    case 'hook-claude-code':
    case 'hook-codex':
    case 'hook-hermes':
    case 'mcp-headers':
    case 'setup':
    case 'doctor':
      return;
    default: {
      const unhandled: never = cmd;
      throw new ServiceCliError(`not available in service mode: ${(unhandled as Command).kind}`);
    }
  }
}
