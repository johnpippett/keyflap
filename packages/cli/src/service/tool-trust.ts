import { renameSync, writeFileSync } from 'node:fs';
import { parseServiceConfig } from '@aab/signer/service';
import { readProvisionedFile } from '@aab/signer/systemd';
import { checkTool, OP_TOOL, PASS_CLI_TOOL, type ToolCheck, type ToolSpec } from '@aab/sources';
import { SERVICE_PATHS, type ServicePaths } from './paths.ts';

export const PASSWORD_TOOLS: Record<string, ToolSpec> = {
  [PASS_CLI_TOOL.command]: PASS_CLI_TOOL,
  [OP_TOOL.command]: OP_TOOL,
};

const TOOL_SOURCE: Record<string, { key: 'protonPass' | 'onePassword'; flag: string }> = {
  [PASS_CLI_TOOL.command]: { key: 'protonPass', flag: 'proton-pass' },
  [OP_TOOL.command]: { key: 'onePassword', flag: '1password' },
};

export class ToolTrustError extends Error {}

export function trustTool(
  tool: string,
  out: (text: string) => void,
  o: {
    paths?: ServicePaths;
    check?: (path: string, spec: ToolSpec) => ToolCheck;
  } = {},
): void {
  const paths = o.paths ?? SERVICE_PATHS;
  const check = o.check ?? ((p: string, s: ToolSpec) => checkTool(p, s));
  const spec = PASSWORD_TOOLS[tool];
  if (!spec) {
    throw new ToolTrustError(
      `unknown tool "${tool}" (known: ${Object.keys(PASSWORD_TOOLS).join(', ')})`,
    );
  }
  const text = readProvisionedFile(paths.signerConfig);
  const cfg = parseServiceConfig(text);
  const source = TOOL_SOURCE[tool] as { key: 'protonPass' | 'onePassword'; flag: string };
  const pp = cfg.sources?.[source.key];
  if (!pp) {
    throw new ToolTrustError(
      `no password source uses ${tool} (connect it: sudo keyflap password-source add ${source.flag})`,
    );
  }
  const r = check(pp.bin, spec);
  if (!r.ok) throw new ToolTrustError(`${r.detail}\n  fix: ${r.fix}`);
  if (pp.sha256 === r.sha256) {
    out(`${pp.bin} is already trusted (SHA-256 ${r.sha256}).\n`);
    return;
  }
  const raw = JSON.parse(text) as { sources: Record<string, Record<string, unknown>> };
  (raw.sources[source.key] as Record<string, unknown>).sha256 = r.sha256;
  const next = `${JSON.stringify(raw, null, 2)}\n`;
  parseServiceConfig(next);
  const tmp = `${paths.signerConfig}.tmp-${process.pid}`;
  writeFileSync(tmp, next, { mode: 0o644, flag: 'wx' });
  renameSync(tmp, paths.signerConfig);
  out(
    [
      `Trusted ${pp.bin}`,
      `  SHA-256 ${r.sha256}`,
      pp.sha256 ? `  (was    ${pp.sha256})` : '  (no hash was pinned before)',
      'The signer runs it from its next use; no restart needed.',
      '',
    ].join('\n'),
  );
}
