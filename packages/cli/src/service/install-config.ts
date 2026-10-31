import { renameSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { TAILSCALE_TOOL } from '@aab/signer/approver-address';
import { localApiDirProblem } from '@aab/signer/tailscale-localapi';
import { checkTool, isSha256, OP_TOOL, PASS_CLI_TOOL, type ToolSpec } from '@aab/sources';
import { buildServiceConfigs } from './config.ts';

export function trustedToolSha256(
  path: string,
  check = checkTool,
  spec: ToolSpec = PASS_CLI_TOOL,
): string {
  const r = check(path, spec);
  if (!r.ok) throw new Error(`${r.detail}\n  fix: ${r.fix}`);
  return r.sha256;
}

export function keptOrFreshPin(
  path: string,
  spec: ToolSpec,
  kept: string | undefined,
  warn: (text: string) => void,
  check = checkTool,
): string {
  const now = trustedToolSha256(path, check, spec);
  if (kept === undefined) return now;
  if (!isSha256(kept)) throw new Error(`the pinned hash of ${spec.command} must be 64 hex digits`);
  if (kept !== now) {
    warn(
      `note: ${path} changed since it was trusted; the signer refuses it until: sudo keyflap password-source trust ${spec.command}\n`,
    );
  }
  return kept;
}

function rootOnlyTool(path: string, spec: ToolSpec): string {
  trustedToolSha256(path, checkTool, spec);
  return path;
}

function rootOnlyDir(dir: string): string {
  const bad = localApiDirProblem(dir);
  if (bad !== null) {
    throw new Error(
      `${bad}\n  fix: the signer reads Tailscale's setting only from a directory nobody but root can change`,
    );
  }
  return dir;
}

function writeAtomic(path: string, text: string): void {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, text, { mode: 0o644, flag: 'wx' });
  renameSync(tmp, path);
}

export function installConfig(
  argv: string[],
  warn: (text: string) => void = (t) => {
    process.stderr.write(t);
  },
): { core: string; signer: string; approver: string } {
  const { values } = parseArgs({
    args: argv,
    strict: true,
    allowPositionals: false,
    options: {
      'out-dir': { type: 'string' },
      'approver-origin': { type: 'string' },
      'approver-listen': { type: 'string' },
      tls: { type: 'boolean' },
      'apns-key-id': { type: 'string' },
      'apns-team-id': { type: 'string' },
      'apns-bundle-id': { type: 'string' },
      'apns-sandbox': { type: 'boolean' },
      'apns-generic': { type: 'boolean' },
      'mcp-port': { type: 'string' },
      'high-risk': { type: 'string', multiple: true },
      'proton-pass-bin': { type: 'string' },
      'proton-pass-vault': { type: 'string' },
      'proton-pass-sha256': { type: 'string' },
      'op-bin': { type: 'string' },
      'op-sha256': { type: 'string' },
      '1password-vault': { type: 'string' },
      'tailscale-bin': { type: 'string' },
      'tailscale-localapi': { type: 'string' },
      xvfb: { type: 'string' },
      'xvfb-display': { type: 'string' },
      'ephemeral-browser': { type: 'boolean' },
    },
  });
  if (values['proton-pass-sha256'] !== undefined && !values['proton-pass-bin']) {
    throw new Error('--proton-pass-sha256 needs --proton-pass-bin');
  }
  if (values['op-sha256'] !== undefined && !values['op-bin']) {
    throw new Error('--op-sha256 needs --op-bin');
  }
  const outDir = values['out-dir'];
  if (!outDir) throw new Error('--out-dir is required');
  if (!values['approver-origin']) {
    throw new Error(
      '--approver-origin is required: service mode only runs with a phone approver (D5)',
    );
  }
  const mcpPort = values['mcp-port'];
  if (mcpPort !== undefined && !/^\d{1,5}$/.test(mcpPort)) {
    throw new Error('--mcp-port must be a port number');
  }
  const xd = values['xvfb-display'];
  if (xd !== undefined && !/^\d{1,3}$/.test(xd)) throw new Error('--xvfb-display must be a number');
  const { core, signer, approver } = buildServiceConfigs({
    ...(values.xvfb ? { xvfbBin: values.xvfb } : {}),
    ...(xd !== undefined ? { xvfbDisplay: Number(xd) } : {}),
    ...(values['ephemeral-browser'] === true ? { ephemeralBrowser: true } : {}),
    approverOrigin: values['approver-origin'],
    ...(values['approver-listen'] ? { approverListen: values['approver-listen'] } : {}),
    tls: values.tls === true,
    ...(values['apns-key-id'] !== undefined ||
    values['apns-team-id'] !== undefined ||
    values['apns-bundle-id'] !== undefined
      ? {
          apns: {
            keyId: values['apns-key-id'] ?? '',
            teamId: values['apns-team-id'] ?? '',
            bundleId: values['apns-bundle-id'] ?? '',
            sandbox: values['apns-sandbox'] === true,
            generic: values['apns-generic'] === true,
          },
        }
      : {}),
    ...(mcpPort !== undefined ? { mcpPort: Number(mcpPort) } : {}),
    highRisk: values['high-risk'] ?? [],
    ...(values['proton-pass-bin']
      ? {
          protonPassBin: values['proton-pass-bin'],
          protonPassSha256: keptOrFreshPin(
            values['proton-pass-bin'],
            PASS_CLI_TOOL,
            values['proton-pass-sha256'],
            warn,
          ),
        }
      : {}),
    ...(values['proton-pass-vault'] !== undefined
      ? { protonPassVault: values['proton-pass-vault'] }
      : {}),
    ...(values['op-bin']
      ? {
          onePasswordBin: values['op-bin'],
          onePasswordSha256: keptOrFreshPin(values['op-bin'], OP_TOOL, values['op-sha256'], warn),
        }
      : {}),
    ...(values['1password-vault'] !== undefined
      ? { onePasswordVault: values['1password-vault'] }
      : {}),
    ...(values['tailscale-bin']
      ? { tailscaleBin: rootOnlyTool(values['tailscale-bin'], TAILSCALE_TOOL) }
      : {}),
    ...(values['tailscale-localapi']
      ? { tailscaleLocalApi: rootOnlyDir(values['tailscale-localapi']) }
      : {}),
  });
  const corePath = join(outDir, 'core.json');
  const signerPath = join(outDir, 'signer.json');
  writeAtomic(corePath, `${JSON.stringify(core, null, 2)}\n`);
  const approverPath = join(outDir, 'approver.json');
  writeAtomic(signerPath, `${JSON.stringify(signer, null, 2)}\n`);
  writeAtomic(approverPath, `${JSON.stringify(approver, null, 2)}\n`);
  return { core: corePath, signer: signerPath, approver: approverPath };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const written = installConfig(process.argv.slice(2));
    process.stderr.write(`wrote ${written.core}, ${written.signer} and ${written.approver}\n`);
  } catch (err) {
    process.stderr.write(`install-config: ${(err as Error).message}\n`);
    process.exit(2);
  }
}
