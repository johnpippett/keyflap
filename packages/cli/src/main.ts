#!/usr/bin/env node
import { dirname } from 'node:path';
import { parseCli, USAGE, UsageError } from './args.ts';

const argv = process.argv.slice(2);

if (argv[0] === 'hook') {
  await runHook(argv);
} else if (argv[0] === 'mcp-headers') {
  await runMcpHeaders(argv);
} else {
  await runAdmin(argv);
}

async function runHook(args: string[]): Promise<void> {
  process.stdout.write = (() => true) as typeof process.stdout.write;
  const bail = () => process.exit(0);
  process.on('uncaughtException', bail);
  process.on('unhandledRejection', bail);
  setTimeout(bail, 10_000).unref();
  try {
    const cmd = parseCli(args);
    if (
      cmd.kind !== 'hook-claude-code' &&
      cmd.kind !== 'hook-codex' &&
      cmd.kind !== 'hook-hermes'
    ) {
      throw new UsageError('unknown hook');
    }
    const { SERVICE_PATHS } = await import('./service/paths.ts');
    const opts = {
      dataDir: cmd.dataDir,
      ...(cmd.service
        ? { hostTokenPath: SERVICE_PATHS.hostToken, socketPath: SERVICE_PATHS.intentSocket }
        : {}),
      agentId: cmd.agentId,
      stdin: process.stdin,
      log: (line: string) => process.stderr.write(`${line}\n`),
    };
    if (cmd.kind === 'hook-claude-code') {
      const { runClaudeCodeHook } = await import('./hook-claude-code.ts');
      await runClaudeCodeHook(opts);
    } else if (cmd.kind === 'hook-codex') {
      const { runCodexHook } = await import('./hook-codex.ts');
      await runCodexHook(opts);
    } else {
      const { runHermesHook } = await import('./hook-hermes.ts');
      await runHermesHook({ ...opts, owners: cmd.owners, profile: cmd.profile });
    }
  } catch (err) {
    const msg = err instanceof UsageError ? err.message : 'unexpected error';
    process.stderr.write(`keyflap hook: ${msg}\n`);
  }
  process.exit(0);
}

async function runMcpHeaders(args: string[]): Promise<void> {
  try {
    const cmd = parseCli(args);
    if (cmd.kind !== 'mcp-headers') throw new UsageError('expected mcp-headers');
    const m = await import('./mcp-headers.ts');
    let path: string;
    if (cmd.service) {
      const { SERVICE_PATHS } = await import('./service/paths.ts');
      path = m.serviceAgentTokenPath(SERVICE_PATHS.hookDir, cmd.agentId);
    } else {
      path = m.devAgentTokenPath(cmd.dataDir, cmd.agentId);
    }
    process.stdout.write(m.mcpHeadersJson(m.readAgentToken(path)));
    process.exitCode = 0;
  } catch (err) {
    const known = err instanceof UsageError || (err as Error).name === 'HeadersError';
    process.stderr.write(
      `keyflap mcp-headers: ${known ? (err as Error).message : 'unexpected error'}\n`,
    );
    process.exitCode = 1;
  }
}

function quietSqliteWarning(): void {
  const emit = process.emitWarning.bind(process);
  process.emitWarning = ((warning: string | Error, ...rest: unknown[]) => {
    const text = typeof warning === 'string' ? warning : warning.message;
    const type = typeof rest[0] === 'string' ? rest[0] : (rest[0] as { type?: string })?.type;
    if (type === 'ExperimentalWarning' && /SQLite/i.test(text)) return;
    (emit as (...a: unknown[]) => void)(warning, ...rest);
  }) as typeof process.emitWarning;
}

async function openedDevConsole(): Promise<boolean> {
  const { defaultDataDir } = await import('./data-dir.ts');
  const { devInstallAt } = await import('./console/dev-install.ts');
  if (devInstallAt(defaultDataDir()) === null) return false;
  quietSqliteWarning();
  try {
    const { openDevConsole } = await import('./console/dev-start.ts');
    const r = await openDevConsole();
    if (r === 'root') {
      console.error(
        'keyflap: the unprotected console runs as you, never as root: run keyflap without sudo.',
      );
      process.exit(1);
    }
    return r !== 'no-terminal';
  } catch (err) {
    console.error(`keyflap: ${(err as Error).message}`);
    process.exit(1);
  }
}

async function openedConsole(): Promise<boolean> {
  const { isServiceMode } = await import('./service/paths.ts');
  if (!isServiceMode()) return openedDevConsole();
  const { servicePlatformProblem } = await import('@aab/signer/platform');
  if (servicePlatformProblem()) return false;
  quietSqliteWarning();
  try {
    const { openServiceConsole } = await import('./console/start.ts');
    const r = await openServiceConsole();
    if (r === 'not-root') {
      process.stdout.write(USAGE);
      console.error('\nkeyflap: sudo keyflap, with no command, opens the management console.');
      return true;
    }
    return r === 'closed';
  } catch (err) {
    console.error(`keyflap: ${(err as Error).message}`);
    process.exit(1);
  }
}

async function runAdmin(args: string[]): Promise<void> {
  if (args.length === 0 && (await openedConsole())) return;
  let cmd: ReturnType<typeof parseCli>;
  try {
    cmd = parseCli(args);
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    console.error(`keyflap: ${err.message}\n\n${USAGE}`);
    process.exit(2);
  }
  quietSqliteWarning();
  const out = (text: string) => process.stdout.write(text);
  const { isServiceMode, SERVICE_PATHS } = await import('./service/paths.ts');
  const explicitDataDir = args.some((a) => a === '--data-dir' || a.startsWith('--data-dir='));
  if (!isServiceMode() && !explicitDataDir && 'dataDir' in cmd) {
    const { legacyDataDirNotice } = await import('./data-dir.ts');
    const notice = legacyDataDirNotice(cmd.dataDir);
    if (notice) console.error(notice);
  }
  if (isServiceMode() && cmd.kind !== 'help') {
    const { servicePlatformProblem } = await import('@aab/signer/platform');
    const unsupported = servicePlatformProblem();
    if (unsupported) {
      console.error(`keyflap: ${unsupported}`);
      process.exit(1);
    }
  }
  if (cmd.kind === 'setup' || cmd.kind === 'doctor') {
    await runGuided(cmd, isServiceMode(), explicitDataDir, out);
    return;
  }
  if (isServiceMode() && cmd.kind !== 'help') {
    try {
      if (explicitDataDir) {
        throw new Error(
          `--data-dir is dev-mode only; the installed broker keeps its data in ${dirname(SERVICE_PATHS.coreData)}`,
        );
      }
      const { runServiceCommand } = await import('./service/cli.ts');
      await runServiceCommand(cmd, out);
    } catch (err) {
      console.error(`keyflap: ${(err as Error).message}`);
      process.exit(1);
    }
    return;
  }
  try {
    switch (cmd.kind) {
      case 'help':
        out(USAGE);
        return;
      case 'approver-pair': {
        if (cmd.phone) {
          const { approverPair } = await import('./approver.ts');
          await approverPair({ dataDir: cmd.dataDir, phone: cmd.phone }, out);
          return;
        }
        console.error(
          'keyflap: in dev mode, pairing starts with the daemon: keyflap daemon --unprotected --approver phone … --pair\n' +
            '  to re-check the approval address after a trip (daemon stopped): keyflap approver pair --approver-origin URL [--approver-listen HOST:PORT]',
        );
        process.exit(2);
        return;
      }
      case 'daemon': {
        const { runDaemon, stopOnSignals } = await import('./daemon.ts');
        const daemon = runDaemon(cmd);
        stopOnSignals(daemon);
        await daemon;
        return;
      }
      case 'agent-add': {
        const { agentAdd } = await import('./agent.ts');
        await agentAdd(cmd, out);
        return;
      }
      case 'agent-list': {
        const { agentList } = await import('./agent.ts');
        agentList(cmd, out);
        return;
      }
      case 'agent-revoke': {
        const { agentRevoke } = await import('./agent.ts');
        if (!agentRevoke(cmd, out)) {
          console.error(`keyflap: no active agent with id ${cmd.id}`);
          process.exit(1);
        }
        return;
      }
      case 'password-add': {
        const { passwordAdd } = await import('./password.ts');
        await passwordAdd(cmd, out);
        return;
      }
      case 'password-list': {
        const { passwordList } = await import('./password.ts');
        passwordList(cmd, out);
        return;
      }
      case 'password-remove': {
        const { passwordRemove } = await import('./password.ts');
        await passwordRemove(cmd, out);
        return;
      }
      case 'password-import': {
        const { passwordImport } = await import('./password.ts');
        const r = await passwordImport(cmd, out);
        if (r.failed > 0) process.exit(1);
        return;
      }
      case 'approver-list': {
        const { approverList } = await import('./approver.ts');
        await approverList(cmd, out);
        return;
      }
      case 'approver-remove': {
        const { approverRemove } = await import('./approver.ts');
        await approverRemove(cmd, out);
        return;
      }
      case 'approver-qr': {
        const { approverQr } = await import('./approver.ts');
        approverQr(cmd, out);
        return;
      }
      case 'policy-set': {
        const { policySet } = await import('./policy.ts');
        policySet(cmd, out);
        return;
      }
      case 'policy-list': {
        const { policyList } = await import('./policy.ts');
        policyList(cmd, out);
        return;
      }
      case 'policy-remove': {
        const { policyRemove } = await import('./policy.ts');
        policyRemove(cmd, out);
        return;
      }
      case 'status': {
        const { status } = await import('./status.ts');
        const { styleFor } = await import('@aab/approver');
        const { hasKeyFile } = await import('./key-file.ts');
        status({ ...cmd, simple: hasKeyFile(cmd.dataDir), style: styleFor(process.stdout) }, out);
        return;
      }
      case 'audit-verify': {
        const { auditVerify } = await import('./status.ts');
        const { styleFor } = await import('@aab/approver');
        if (!auditVerify({ ...cmd, style: styleFor(process.stdout) }, out)) process.exit(1);
        return;
      }
      case 'audit-tail': {
        const { auditTail } = await import('./status.ts');
        auditTail(cmd, out);
        return;
      }
      case 'sessions-list': {
        const { sessionsList } = await import('./sessions.ts');
        sessionsList(cmd, out);
        return;
      }
      case 'sessions-clear': {
        const { sessionsClear } = await import('./sessions.ts');
        sessionsClear(cmd, out);
        return;
      }
      case 'sessions-keep': {
        const { sessionsKeep } = await import('./sessions.ts');
        sessionsKeep(cmd, out);
        return;
      }
      case 'sessions-unkeep': {
        const { sessionsUnkeep } = await import('./sessions.ts');
        sessionsUnkeep(cmd, out);
        return;
      }
      case 'password-source-trust':
      case 'password-source-add':
      case 'password-source-remove':
        throw new Error(
          `password-source ${cmd.kind.slice('password-source-'.length)} is for the installed broker (service mode): in dev mode the signer runs your own tool as you, started with --password-source`,
        );
      case 'hook-claude-code':
      case 'hook-codex':
      case 'hook-hermes':
      case 'mcp-headers':
        process.exit(0);
    }
  } catch (err) {
    console.error(`keyflap: ${(err as Error).message}`);
    process.exit(1);
  }
}

async function runGuided(
  cmd: Extract<ReturnType<typeof parseCli>, { kind: 'setup' | 'doctor' }>,
  service: boolean,
  explicitDataDir: boolean,
  out: (text: string) => void,
): Promise<void> {
  try {
    if (service && explicitDataDir) {
      const { SERVICE_PATHS } = await import('./service/paths.ts');
      throw new Error(
        `--data-dir is dev-mode only; the installed broker keeps its data in ${dirname(SERVICE_PATHS.coreData)}`,
      );
    }
    if (cmd.kind === 'doctor') {
      const { runDoctor } = await import('./setup/run.ts');
      const report = await runDoctor(
        { dataDir: cmd.dataDir, project: cmd.project, service, json: cmd.json },
        out,
      );
      if (!report.ok) process.exitCode = 1;
      return;
    }
    if (service && cmd.unprotected) {
      throw new Error(
        `this is the installed broker (service mode): run \`sudo keyflap setup\`; --unprotected is for a dev checkout`,
      );
    }
    const { isSimpleMode } = await import('./simple-install.ts');
    const simple = !service && isSimpleMode();
    if (!service && !cmd.unprotected && !simple) {
      console.error(
        `keyflap: no installed broker here (service mode: sudo keyflap setup after install.sh).\n` +
          'For the same-user dev broker, pass --unprotected: an agent with shell access as you can\n' +
          "read that broker's files, memory and code (docs/ISOLATION_PLAN.md).",
      );
      process.exit(2);
    }
    const { runSetup } = await import('./setup/run.ts');
    await runSetup({
      dataDir: cmd.dataDir,
      mcpPort: cmd.mcpPort,
      service,
      simple,
      host: cmd.host ?? null,
    });
  } catch (err) {
    if (
      (err as Error).name === 'PromptAborted' ||
      (err as Error).constructor?.name === 'PromptAborted'
    ) {
      console.error('\nkeyflap setup: stopped. Re-run it any time; finished steps are kept.');
      process.exit(130);
    }
    console.error(`keyflap: ${(err as Error).message}`);
    process.exit(1);
  }
}
