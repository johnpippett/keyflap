export type ApproverMode = 'unpaired' | 'phone' | 'phone-empty';

export interface ApproverModeRules {
  ed25519Counts: boolean;
  pairingNeedsApproval: boolean;
}

export function approverModeOf(latched: boolean, approverCount: number): ApproverMode {
  if (approverCount > 0) return 'phone';
  return latched ? 'phone-empty' : 'unpaired';
}

export function approverModeRules(mode: ApproverMode): ApproverModeRules {
  switch (mode) {
    case 'unpaired':
      return { ed25519Counts: true, pairingNeedsApproval: false };
    case 'phone':
    case 'phone-empty':
      return { ed25519Counts: false, pairingNeedsApproval: true };
    default: {
      const unhandled: never = mode;
      return unhandled;
    }
  }
}
