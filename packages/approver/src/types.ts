import type { ApprovalKind, SignedApproval } from '@aab/signer/approval';

export interface ApprovalRequest {
  display: {
    intentText: string;
    intentAt: number;
    verifiedOrigin: string;
    agentName: string;
    credentialType: 'passkey' | 'password' | 'password+totp' | 'totp';
    action: 'sign-in' | 'register';
    allowForMs?: number;
    keepSignedInSite?: string;
    handoffSignIn?: { withinMs: number };
  };
  policy: { tier: 'ask' | 'ask-strong' };
  binding: {
    requestId: string;
    kind: ApprovalKind;
    rpId: string;
    credentialId: string | null;
    intentHash: string;
    clientDataHash: string;
    grant?: { agentId: string; durationMs: number; uses?: 1 };
    handoff?: { id: string };
  };
}

export type ApprovalDecision =
  | { approved: true; approval: SignedApproval; deviceId?: string }
  | { approved: false; reason: string };

export interface Approver {
  request(req: ApprovalRequest, opts?: { signal?: AbortSignal }): Promise<ApprovalDecision>;
}

export interface HandoffView {
  id: string;
  host: string;
  agentName: string;
  intentText: string;
  intentAt: number;
  openedAt: number;
  expiresAt: number;
  withSignIn?: boolean;
}

export const HANDOFF_KEYS = [
  'Enter',
  'Backspace',
  'Tab',
  'Escape',
  'ArrowUp',
  'ArrowDown',
  'ArrowLeft',
  'ArrowRight',
] as const;
export type HandoffKey = (typeof HANDOFF_KEYS)[number];

export interface HandoffPoint {
  x: number;
  y: number;
}

export interface HandoffClip {
  x: number;
  y: number;
  w: number;
  h: number;
}

export type HandoffInput =
  | { type: 'click'; x: number; y: number }
  | { type: 'scroll'; dy: number }
  | { type: 'drag'; from: HandoffPoint; to: HandoffPoint }
  | { type: 'key'; key: HandoffKey }
  | { type: 'text'; text: string };

export type HandoffInputResult =
  | { ok: true }
  | { ok: false; reason: 'sensitive_field' | 'not_open' | 'not_controller' | 'failed' };

export type HandoffStartResult = 'ok' | 'not_found' | 'taken' | 'approval_only';

export interface HandoffPort {
  list(): HandoffView[];
  get(id: string): HandoffView | null;
  controller(id: string): string | null;
  start(id: string, deviceId: string): HandoffStartResult;
  frame(id: string, deviceId: string, clip?: HandoffClip): Promise<Buffer | null>;
  input(id: string, deviceId: string, input: HandoffInput): Promise<HandoffInputResult>;
  finish(id: string, deviceId: string, outcome: 'done' | 'cancelled'): boolean;
}

export interface HandoffSurface {
  attachHandoffs(port: HandoffPort): void;
  notifyHandoff(view: HandoffView): Promise<void>;
  handoffAvailable(): boolean;
}
