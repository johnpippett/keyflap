import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import type { ApproverKey } from './keys.ts';
import { renderPrompt } from './render.ts';
import { requestProblem } from './statement.ts';
import { styleFor, type TermStyle } from './term-style.ts';
import type { ApprovalDecision, ApprovalRequest, Approver } from './types.ts';

export interface TerminalApproverOptions {
  key: ApproverKey;
  input?: Readable;
  output?: Writable;
  timeoutMs?: number;
  style?: TermStyle;
}

export class TerminalApprover implements Approver {
  private readonly opts: Required<Omit<TerminalApproverOptions, 'style'>>;
  private readonly style: TermStyle;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: TerminalApproverOptions) {
    this.opts = {
      input: process.stdin,
      output: process.stdout,
      timeoutMs: 60_000,
      ...opts,
    };
    this.style = opts.style ?? styleFor(this.opts.output as { isTTY?: boolean });
  }

  request(req: ApprovalRequest, o?: { signal?: AbortSignal }): Promise<ApprovalDecision> {
    const problem = requestProblem(req);
    if (problem) return Promise.resolve({ approved: false, reason: problem });
    if (req.binding?.handoff !== undefined || req.display?.handoffSignIn !== undefined) {
      return Promise.resolve({ approved: false, reason: 'handoff_unsupported' });
    }
    if (req.policy?.tier !== 'ask') {
      return Promise.resolve({ approved: false, reason: 'user_verification_unavailable' });
    }
    const next = this.queue.then(() => this.ask(req, o?.signal));
    this.queue = next.catch(() => {});
    return next;
  }

  private ask(req: ApprovalRequest, signal?: AbortSignal): Promise<ApprovalDecision> {
    return new Promise((resolve) => {
      const rl = createInterface({
        input: this.opts.input,
        output: this.opts.output,
        terminal: false,
      });
      let done = false;
      const finish = (d: ApprovalDecision) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        rl.close();
        resolve(d);
      };
      const timer = setTimeout(
        () => finish({ approved: false, reason: 'timeout' }),
        this.opts.timeoutMs,
      );
      signal?.addEventListener('abort', () => finish({ approved: false, reason: 'aborted' }));
      rl.on('close', () => finish({ approved: false, reason: 'input_closed' }));
      this.opts.output.write(renderPrompt(req, this.style));
      rl.once('line', (line) => {
        if (done) return;
        const answer = line.trim().toLowerCase();
        if (answer === 'y' || answer === 'yes') {
          this.opts.output.write(`${this.style.ok('  approved')}\n`);
          finish({ approved: true, approval: this.opts.key.approve(req, { userVerified: false }) });
        } else {
          this.opts.output.write(`  ${this.style.bad('DENIED')}\n`);
          finish({ approved: false, reason: 'user_denied' });
        }
      });
    });
  }
}
