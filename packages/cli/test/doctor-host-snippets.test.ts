import { describe, expect, it } from 'vitest';
import { hostChecks } from '../src/doctor-hosts.ts';
import {
  codexConfigToml,
  codexHookCommand,
  codexHooksJson,
  hermesConfigYaml,
  hermesPluginConfig,
  type ServiceHost,
} from '../src/host-config.ts';
import { mergeCodexHooks } from '../src/setup/hosts.ts';
import { AGENT_ID, FakeSystem } from './setup-fakes.ts';

const DATA_DIR = '/home/u/.keyflap';
const SERVICE: ServiceHost = {
  wrapper: '/usr/local/bin/keyflap',
  hookDir: '/var/lib/keyflap/hook',
};
const AGENTS = [{ id: AGENT_ID, name: 'host', revoked: false }];

function statuses(sys: FakeSystem, denyDir: string): Record<string, string> {
  return Object.fromEntries(
    hostChecks({
      sys,
      read: (p) => sys.readUserFile(p, { uid: 1000, gid: 1000 }),
      home: '/home/u',
      denyDir,
      agents: AGENTS,
    }).map((c) => [c.id, c.status]),
  );
}

describe('the doctor accepts exactly what keyflap agent add prints for Hermes and Codex', () => {
  it('Hermes: the printed config.yaml and plugin config.json pass every check', () => {
    const sys = new FakeSystem()
      .dir('/home/u/.hermes', 0o700)
      .file('/home/u/.hermes/plugins/keyflap-intent/__init__.py', '')
      .file(
        '/home/u/.hermes/plugins/keyflap-intent/config.json',
        JSON.stringify(hermesPluginConfig(AGENT_ID, DATA_DIR, ['telegram:1'])),
      )
      .file('/home/u/.hermes/config.yaml', hermesConfigYaml(8765));
    expect(statuses(sys, DATA_DIR)).toEqual({
      'hermes-plugin': 'ok',
      'hermes-backend': 'ok',
      'hermes-enabled': 'ok',
    });
  });

  it.each([
    ['dev mode', undefined, DATA_DIR],
    ['service mode', SERVICE, SERVICE.hookDir],
  ] as const)(
    'Codex, %s: the printed hooks.json and config.toml pass every check',
    (_, service, denyDir) => {
      for (const hooks of [
        codexHooksJson(AGENT_ID, DATA_DIR, service),
        mergeCodexHooks(undefined, codexHookCommand(AGENT_ID, DATA_DIR, service)).doc,
      ]) {
        const sys = new FakeSystem()
          .file('/home/u/.codex/hooks.json', JSON.stringify(hooks))
          .file(
            '/home/u/.codex/config.toml',
            codexConfigToml({ dataDir: DATA_DIR, mcpPort: 8765, ...(service ? { service } : {}) }),
          );
        expect(statuses(sys, denyDir)).toEqual({ 'codex-hook': 'ok', 'codex-deny': 'ok' });
      }
    },
  );
});
