import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { type ApprovalRequest, ApproverKey, TerminalApprover } from '../src/index.ts';

const request = (requestId: string, site: string): ApprovalRequest => ({
  display: {
    intentText: 'log me in',
    intentAt: Date.UTC(2026, 0, 1),
    verifiedOrigin: site,
    agentName: 'dev-agent',
    credentialType: 'passkey',
    action: 'sign-in',
  },
  policy: { tier: 'ask' },
  binding: {
    requestId,
    kind: 'webauthn.get',
    rpId: new URL(site).hostname,
    credentialId: 'c1',
    intentHash: 'aA',
    clientDataHash: 'bB',
  },
});

const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 20));

describe('terminal approver: one prompt at a time', () => {
  it('a second request waits unprompted, and the answer to the first prompt never approves it', async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let shown = '';
    output.on('data', (chunk: Buffer) => {
      shown += chunk.toString();
    });
    const prompts = () => shown.split('approval requested').length - 1;
    const approver = new TerminalApprover({
      key: ApproverKey.generate('t'),
      input,
      output,
      timeoutMs: 5_000,
    });

    const first = approver.request(request('r1', 'https://one.example'));
    const second = approver.request(request('r2', 'https://two.example'));
    await settle();
    expect(prompts()).toBe(1);
    expect(shown).toContain('https://one.example');
    expect(shown).not.toContain('https://two.example');

    input.write('y\n');
    const approved = await first;
    expect(approved).toMatchObject({
      approved: true,
      approval: { statement: { requestId: 'r1' } },
    });
    await settle();
    expect(prompts()).toBe(2);
    expect(shown).toContain('https://two.example');

    input.write('n\n');
    expect(await second).toEqual({ approved: false, reason: 'user_denied' });
  });
});
