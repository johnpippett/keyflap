import { describe, expect, it } from 'vitest';
import {
  env,
  host,
  inspectProcesses,
  outcomes,
  phoneDecisions,
  pids,
  ptrace,
  skipReason,
  where,
} from './helpers.ts';
import { auditEvents, L, NODE, owner, restartCore } from './platform.ts';
import type { Attempt } from './probe/attempt.ts';

describe.skipIf(skipReason !== null)(`invariant 1: service mode (${where})`, () => {
  it('the user uid cannot read or list the broker data, credentials or key store', () => {
    const r = outcomes(L.unreadable);
    for (const [what, result] of Object.entries(r)) {
      expect.soft(result, what).toBe('EACCES');
    }
    const h = host();
    for (const path of L.present) {
      expect(h.exec(['test', '-s', path]).status, path).toBe(0);
    }
  });

  if (L.os === 'linux') {
    it("the user uid cannot read the broker processes' memory, environment or fds", () => {
      const { core, signer, chromium } = pids();
      const attempts: Record<string, Attempt> = {};
      for (const [name, pid] of Object.entries({ core, signer, chromium })) {
        attempts[`${name}.mem`] = { kind: 'open', path: `/proc/${pid}/mem` };
        attempts[`${name}.environ`] = { kind: 'read', path: `/proc/${pid}/environ` };
        attempts[`${name}.fd`] = { kind: 'list', path: `/proc/${pid}/fd` };
      }
      attempts['control.environ'] = { kind: 'own-child', file: 'environ' };
      attempts['control.fd'] = { kind: 'own-child', file: 'fd' };
      attempts['control.mem'] = { kind: 'own-child', file: 'mem' };
      const r = outcomes(attempts);
      expect(r['control.environ']).toBe('ok');
      expect(r['control.fd']).toBe('ok');
      expect(r['control.mem']).toBe('ok');
      for (const name of ['core', 'signer', 'chromium']) {
        expect.soft(r[`${name}.mem`], `${name} mem`).toBe('EACCES');
        expect.soft(r[`${name}.environ`], `${name} environ`).toBe('EACCES');
        expect.soft(r[`${name}.fd`], `${name} fd`).toBe('EACCES');
      }

      const t = ptrace([core, signer, chromium]);
      expect(t.control).toBe('ok');
      for (const pid of [core, signer, chromium])
        expect.soft(t[String(pid)], `ptrace ${pid}`).toBe('EPERM');
    });
  } else {
    it("the user uid cannot read the broker processes' memory, environment or fds", () => {
      const { core, signer, approver, chromium } = pids();
      const targets = { core, signer, approver, chromium };
      for (const [name, pid] of Object.entries(targets)) expect(pid, name).toBeGreaterThan(1);
      const { control, targets: seen } = inspectProcesses(Object.values(targets));
      expect(control).toEqual({
        vmmap: 'ok',
        sample: 'ok',
        lsof: 'ok',
        signal: 'ok',
        environment: 'ok',
        taskForPid: 'ok',
      });
      for (const [name, pid] of Object.entries(targets)) {
        expect.soft(seen[String(pid)], name).toEqual({
          vmmap: 'denied',
          sample: 'denied',
          lsof: 'denied',
          signal: 'EPERM',
          environment: 'denied',
          taskForPid: 'kr=5',
        });
      }
      const rootView = host().exec(['ps', 'eww', '-o', 'command=', '-p', String(core)], {
        check: true,
      }).stdout;
      expect(rootView, 'root sees the environment the user may not').toContain(
        'CREDENTIALS_DIRECTORY=/Library/Keyflap/credentials/core',
      );
    });

    it('no secret is on any broker command line, which every uid can read', () => {
      const h = host();
      const script = `
        const fs = require('node:fs');
        const out = {};
        const add = (name, buf) => {
          for (const enc of ['hex', 'base64', 'base64url']) out[name + '.' + enc] = buf.toString(enc);
          const text = buf.toString('utf8').trim();
          if (/^[\\x21-\\x7e]{16,}$/.test(text)) out[name + '.text'] = text;
        };
        for (const [n, p] of Object.entries(JSON.parse(process.argv[1]))) add(n, fs.readFileSync(p));
        console.log(JSON.stringify(out));`;
      const files = {
        kek: L.kek,
        signerChannelKey: L.channelKey,
        coreChannelKey: '/Library/Keyflap/credentials/core/channel-key',
        hostToken: '/Library/Keyflap/credentials/core/host-token',
      };
      const secrets = JSON.parse(
        h.exec([NODE, '-e', script, JSON.stringify(files)], { check: true }).stdout,
      ) as Record<string, string>;
      secrets['agentToken.text'] = env.agentToken as string;
      const ps = h.as(L.agentUser, ['/bin/ps', '-axww', '-o', 'user=,pid=,command='], {
        timeoutMs: 30_000,
      }).stdout;
      const service = ps
        .split('\n')
        .filter((l) => Object.values(L.users).includes(l.trim().split(/\s+/)[0] ?? ''));
      expect(service.some((l) => l.includes('core-main.ts'))).toBe(true);
      expect(service.some((l) => l.includes('signer'))).toBe(true);
      expect(service.some((l) => l.includes('--remote-debugging-pipe'))).toBe(true);
      const found = Object.entries(secrets)
        .filter(([, v]) => service.some((l) => l.includes(v)))
        .map(([k]) => k);
      expect(found).toEqual([]);
    });

    it('another local user (the admin who ran the install) reaches nothing of the broker either', () => {
      const other = env.otherUser as string;
      const r = outcomes(
        {
          ...L.unreadable,
          hookDir: { kind: 'list', path: L.hookDir },
          hostTokenCopy: { kind: 'read', path: `${L.hookDir}/host-token` },
          intent: { kind: 'connect', path: L.sockets.intent },
          signer: { kind: 'connect', path: L.sockets.signer },
          signerAdmin: { kind: 'connect', path: L.sockets.signerAdmin },
          coreAdmin: { kind: 'connect', path: L.sockets.coreAdmin },
          approverApi: { kind: 'connect', path: L.sockets.approverApi },
          ...L.immutable,
        },
        other,
      );
      for (const [what, result] of Object.entries(r)) expect.soft(result, what).toBe('EACCES');
      const { core, signer, chromium } = pids();
      const { control, targets } = inspectProcesses([core, signer, chromium], other);
      expect(control.taskForPid).toBe('ok');
      for (const pid of [core, signer, chromium]) {
        expect.soft(targets[String(pid)]?.taskForPid, `task_for_pid ${pid}`).toBe('kr=5');
        expect.soft(targets[String(pid)]?.vmmap, `vmmap ${pid}`).toBe('denied');
        expect.soft(targets[String(pid)]?.environment, `ps eww ${pid}`).toBe('denied');
      }
    });
  }

  it('the user uid cannot change the code, runtime, configuration or units', () => {
    const r = outcomes(L.immutable);
    for (const [what, result] of Object.entries(r)) expect.soft(result, what).toBe('EACCES');
  });

  it('the legitimate path works from that same uid, and only through phone approvals', () => {
    const h = host();
    const auditTypes = ['passkey.created', 'passkey.signed', 'admin.request', 'daemon.service'];
    const phoneBefore = phoneDecisions().length;
    const auditBefore = auditEvents(h, auditTypes).length;
    const r = h.as(
      L.agentUser,
      [
        L.node,
        `${L.probeDir}/legit.ts`,
        JSON.stringify({
          mcpUrl: env.mcpUrl,
          token: env.agentToken,
          agentId: env.agentId,
          rp: env.rpUrl,
        }),
      ],
      { timeoutMs: 240_000 },
    );
    expect(r.status, r.stderr).toBe(0);
    const out = JSON.parse(r.stdout) as Record<string, unknown>;
    expect(out.signup).toBe(`${env.rpUrl}account`);
    expect(out.enrollWithoutIntent).toEqual({ status: 'denied' });
    for (const k of ['hookRegister', 'hookDeny', 'hookLogin']) {
      expect(out[k], k).toEqual({ status: 0, stdout: '', stderr: '' });
    }
    expect(out.enrollApproved).toEqual({ status: 'success' });
    expect(out.loginDenied).toEqual({ status: 'denied' });
    expect(out.loginApproved).toEqual({ status: 'success' });
    expect(out.signedInAs).toBe('isolation-user');

    const decisionsSoFar = () =>
      phoneDecisions()
        .slice(phoneBefore)
        .filter((l) => l.event !== 'paired');
    const logged = Date.now() + 10_000;
    while (decisionsSoFar().length < 3 && Date.now() < logged) h.exec(['sleep', '0.5']);
    const decisions = decisionsSoFar();
    expect(decisions.map((d) => d.event)).toEqual(['approved', 'denied', 'approved']);
    expect(decisions[0]?.shown).toContain('add a passkey for the test site');
    expect(decisions[0]?.shown).toContain('http://rp.localhost:3000');
    expect(decisions[0]?.shown).toContain('isolation-agent');

    const all = auditEvents(h, auditTypes);
    const events = all.slice(auditBefore);
    expect(all).toContain('daemon.service');
    expect(all).toContain('admin.request');
    expect(events.filter((e) => e === 'passkey.created')).toHaveLength(1);
    expect(events.filter((e) => e === 'passkey.signed')).toHaveLength(1);
  });

  it('saved browser state: unreadable to the user uid, encrypted, survives a core restart, revoke removes it', () => {
    const h = host();
    const dir = L.browserState;
    const file = `${dir}/${env.agentId}.state`;
    const deadline = Date.now() + 30_000;
    while (h.exec(['test', '-s', file]).status !== 0) {
      if (Date.now() > deadline) throw new Error(`${file} never appeared`);
      h.exec(['sleep', '0.5']);
    }
    const r = outcomes({
      listBrowserState: { kind: 'list', path: dir },
      readStateFile: { kind: 'read', path: file },
    });
    expect.soft(r.listBrowserState, 'list browser-state').toBe('EACCES');
    expect.soft(r.readStateFile, 'read state file').toBe('EACCES');
    const raw = h.exec(['cat', file], { check: true }).stdout;
    expect(Object.keys(JSON.parse(raw)).sort()).toEqual(['ct', 'iv', 'tag', 'v']);
    for (const s of ['sid', 'rp.localhost', 'isolation-user', 'localhost:3000']) {
      expect(raw, s).not.toContain(s);
    }
    expect([owner(h, dir), owner(h, file)].map((o) => o.replace(/:\S+/, ''))).toEqual([
      `${L.users.core} 700`,
      `${L.users.core} 600`,
    ]);

    const before = phoneDecisions().length;
    restartCore(h);
    const p = h.as(
      L.agentUser,
      [
        L.node,
        `${L.probeDir}/persisted.ts`,
        JSON.stringify({ mcpUrl: env.mcpUrl, token: env.agentToken, rp: env.rpUrl }),
      ],
      { timeoutMs: 120_000 },
    );
    expect(p.status, p.stderr).toBe(0);
    expect(JSON.parse(p.stdout)).toEqual({
      url: `${env.rpUrl}account`,
      signedInAs: 'isolation-user',
    });
    expect(phoneDecisions().length).toBe(before);
    expect(
      auditEvents(h, ['browser_state.restored', 'session.keep_set', 'browser_state.save_failed']),
    ).toEqual(['session.keep_set', 'browser_state.restored']);

    h.exec(['/usr/local/bin/keyflap', 'agent', 'revoke', env.agentId as string], { check: true });
    const gone = Date.now() + 15_000;
    while (h.exec(['test', '-e', file]).status === 0) {
      if (Date.now() > gone) throw new Error('state file not removed on revoke');
      h.exec(['sleep', '0.2']);
    }
  });
});
