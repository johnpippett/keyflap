import { ApproverKey, ScriptedApprover } from '@aab/approver';
import { describe, expect, it } from 'vitest';
import { type ApproverDeps, startDaemon } from '../src/daemon.ts';
import { tmpDir } from './harness.ts';

describe('invariant 10: the approver gets an audit writer that cannot silently do nothing', () => {
  it('throws while the approver is built, then writes to the audit log once it is open', async () => {
    const key = ApproverKey.generate('test-approver');
    let early: unknown = null;
    let kept: ApproverDeps['auditBefore'] | null = null;
    const daemon = await startDaemon({
      dataDir: tmpDir(),
      passphrase: 'test-passphrase',
      trustedApproverKeys: key.trustEntry(),
      makeApprover: async ({ auditBefore }) => {
        try {
          auditBefore('approver.pairing_accepted', { credentialId: 'too-early' });
        } catch (err) {
          early = err;
        }
        kept = auditBefore;
        return { approver: new ScriptedApprover(key), close: async () => {} };
      },
    });
    try {
      expect(early).toBeInstanceOf(Error);
      expect((early as Error).message).toBe('the audit log is not open yet');
      expect(daemon.broker.audit.all().map((r) => r.event_type)).not.toContain(
        'approver.pairing_accepted',
      );

      (kept as unknown as ApproverDeps['auditBefore'])('approver.pairing_accepted', {
        credentialId: 'late-enough',
      });
      const last = daemon.broker.audit.all().at(-1);
      expect(last?.event_type).toBe('approver.pairing_accepted');
      expect(JSON.parse(last?.payload_json ?? '{}')).toEqual({ credentialId: 'late-enough' });
      expect(daemon.broker.audit.verify()).toBeNull();
    } finally {
      await daemon.stop();
    }
  });
});
