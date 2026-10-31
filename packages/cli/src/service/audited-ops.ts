import { AdminError, AdminOps } from '@aab/signer/admin-wire';

export const ADMIN_AUDIT_REFUSAL = 'refused: the audit log could not record this request';

export class AuditedAdminOps extends AdminOps {
  private readonly recordRequest: (op: string) => void;
  private readonly recordResult: (op: string, ok: boolean) => void;

  constructor(
    recordRequest: (op: string) => void,
    recordResult: (op: string, ok: boolean) => void,
  ) {
    super();
    this.recordRequest = recordRequest;
    this.recordResult = recordResult;
  }

  override async dispatch(op: string, params: Record<string, unknown>): Promise<unknown> {
    try {
      this.recordRequest(op);
    } catch {
      throw new AdminError(ADMIN_AUDIT_REFUSAL);
    }
    try {
      const result = await super.dispatch(op, params);
      this.recordResult(op, true);
      return result;
    } catch (err) {
      this.recordResult(op, false);
      throw err;
    }
  }
}
