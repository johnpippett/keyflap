import { join } from 'node:path';
import { plainStyle } from '@aab/approver';
import { agentList, agentRevoke, listAgents } from '../agent.ts';
import { approverList, approverRemove } from '../approver.ts';
import type { Command } from '../args.ts';
import { listPasswords, passwordList, passwordRemove } from '../password.ts';
import { policyList, policyRemove, policySet } from '../policy.ts';
import { sessionsClear, sessionsKeep, sessionsList, sessionsUnkeep } from '../sessions.ts';
import type { System } from '../setup/system.ts';
import { auditTail, auditVerify, status } from '../status.ts';
import { type DaemonKeeper, StillRunning } from './daemon-keeper.ts';
import type { KeyStoreUnlock } from './key-store-unlock.ts';
import type { Snapshot } from './overview.ts';
import type { Dispatch } from './run.ts';

export interface DevDispatchDeps {
  dataDir: string;
  simple: boolean;
  unlock: KeyStoreUnlock;
  keeper: DaemonKeeper;
  sys: System;
}

const keyStoreAt = (dataDir: string) => join(dataDir, 'signer', 'keys.enc.json');

export function devDispatch(d: DevDispatchDeps): Dispatch {
  const stopped = async (what: string) => {
    if (!(await d.keeper.stopped(what))) throw new StillRunning();
  };
  return async (parsed: Command, out) => {
    const cmd = 'dataDir' in parsed ? { ...parsed, dataDir: d.dataDir } : parsed;
    switch (cmd.kind) {
      case 'status':
        status({ dataDir: cmd.dataDir, json: cmd.json, simple: d.simple, style: plainStyle }, out);
        return;
      case 'audit-verify':
        if (!auditVerify({ dataDir: cmd.dataDir, style: plainStyle }, out)) {
          throw new Error('the audit hash chain is broken');
        }
        return;
      case 'audit-tail':
        auditTail(cmd, out);
        return;
      case 'password-list':
        passwordList(cmd, out);
        return;
      case 'password-remove':
        await stopped('removing a password');
        await d.unlock.with((unlock) => passwordRemove({ ...cmd, unlock }, out));
        return;
      case 'agent-list':
        agentList(cmd, out);
        return;
      case 'agent-revoke':
        if (!agentRevoke(cmd, out)) throw new Error(`no active agent with id ${cmd.id}`);
        return;
      case 'approver-list':
        if (!d.sys.exists(keyStoreAt(cmd.dataDir))) {
          out(cmd.json ? '[]\n' : 'No phone approvers.\n');
          return;
        }
        await stopped('listing the phones');
        await d.unlock.with((unlock) => approverList({ ...cmd, unlock }, out));
        return;
      case 'approver-remove':
        await stopped('removing a phone');
        await d.unlock.with((unlock) => approverRemove({ ...cmd, unlock }, out));
        return;
      case 'policy-set':
        policySet(cmd, out);
        return;
      case 'policy-list':
        policyList(cmd, out);
        return;
      case 'policy-remove':
        policyRemove(cmd, out);
        return;
      case 'sessions-list':
        sessionsList(cmd, out);
        return;
      case 'sessions-clear':
        sessionsClear(cmd, out);
        return;
      case 'sessions-keep':
        sessionsKeep(cmd, out);
        return;
      case 'sessions-unkeep':
        sessionsUnkeep(cmd, out);
        return;
      case 'password-source-trust':
        throw new Error(
          'trusting a password tool is for the full install: here the signer runs your own tool as you',
        );
      default:
        throw new Error(`the console does not run keyflap ${cmd.kind}`);
    }
  };
}

export function devSnapshot(o: {
  sys: System;
  dataDir: string;
  passwordSource: string | null;
}): Snapshot {
  const { sys, dataDir } = o;
  const has = (f: string) => sys.exists(join(dataDir, f));
  const devices = sys.readFile(join(dataDir, 'approver', 'devices.json'));
  let phones = 0;
  try {
    phones =
      devices === null
        ? 0
        : ((JSON.parse(devices) as { devices?: unknown[] }).devices ?? []).length;
  } catch {
    phones = 0;
  }
  const db = has('broker.sqlite');
  return {
    phones,
    agents: db ? listAgents(dataDir).filter((a) => a.revokedAt === null).length : 0,
    passwords: db ? listPasswords(dataDir).length : 0,
    passwordSource: o.passwordSource,
    address: null,
  };
}
