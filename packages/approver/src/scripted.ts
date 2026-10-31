import type { ApproverKey } from './keys.ts';
import { requestProblem } from './statement.ts';
import type { ApprovalDecision, ApprovalRequest, Approver } from './types.ts';

export class ScriptedApprover implements Approver {
  readonly seen: ApprovalRequest[] = [];
  private readonly key: ApproverKey;
  private readonly decide: (req: ApprovalRequest) => boolean | Promise<boolean>;
  private readonly userVerified: boolean;

  constructor(
    key: ApproverKey,
    decide: (req: ApprovalRequest) => boolean | Promise<boolean> = () => true,
    opts: { userVerified?: boolean } = {},
  ) {
    this.key = key;
    this.decide = decide;
    this.userVerified = opts.userVerified ?? false;
  }

  async request(req: ApprovalRequest): Promise<ApprovalDecision> {
    this.seen.push(req);
    const problem = requestProblem(req);
    if (problem) return { approved: false, reason: problem };
    if (!(await this.decide(req))) return { approved: false, reason: 'user_denied' };
    return { approved: true, approval: this.key.approve(req, { userVerified: this.userVerified }) };
  }
}
