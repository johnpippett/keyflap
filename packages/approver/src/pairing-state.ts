import type { DeviceKind } from './devices.ts';

export type PairingState =
  | { kind: 'open' }
  | { kind: 'ceremony'; challenge: string }
  | { kind: 'verifying'; device: DeviceKind }
  | { kind: 'waiting'; device: DeviceKind }
  | { kind: 'paired'; device: DeviceKind; token: string }
  | { kind: 'done'; device: DeviceKind }
  | { kind: 'failed'; device: DeviceKind };

export type PairingEvent =
  | { kind: 'options'; challenge: string }
  | { kind: 'finish_web' }
  | { kind: 'finish_native' }
  | { kind: 'paired'; token: string }
  | { kind: 'needs_approval' }
  | { kind: 'rejected' }
  | { kind: 'approval_failed' }
  | { kind: 'token_taken' };

export type PairingStatus = 'open' | 'waiting' | 'paired' | 'done' | 'failed';

export function nextPairingState(state: PairingState, event: PairingEvent): PairingState {
  switch (state.kind) {
    case 'open':
      if (event.kind === 'options') return { kind: 'ceremony', challenge: event.challenge };
      if (event.kind === 'finish_native') return { kind: 'verifying', device: 'native' };
      return state;
    case 'ceremony':
      if (event.kind === 'options') return { kind: 'ceremony', challenge: event.challenge };
      if (event.kind === 'finish_web') return { kind: 'verifying', device: 'web' };
      return state;
    case 'verifying':
      if (event.kind === 'paired') {
        return { kind: 'paired', device: state.device, token: event.token };
      }
      if (event.kind === 'needs_approval') return { kind: 'waiting', device: state.device };
      if (event.kind === 'rejected') return { kind: 'open' };
      return state;
    case 'waiting':
      if (event.kind === 'paired') {
        return { kind: 'paired', device: state.device, token: event.token };
      }
      if (event.kind === 'approval_failed') return { kind: 'failed', device: state.device };
      return state;
    case 'paired':
      if (event.kind === 'token_taken') return { kind: 'done', device: state.device };
      return state;
    case 'done':
    case 'failed':
      return state;
    default: {
      const unhandled: never = state;
      return unhandled;
    }
  }
}

export function pairingStatus(state: PairingState): PairingStatus {
  switch (state.kind) {
    case 'open':
    case 'ceremony':
    case 'verifying':
      return 'open';
    case 'waiting':
    case 'paired':
    case 'done':
    case 'failed':
      return state.kind;
    default: {
      const unhandled: never = state;
      return unhandled;
    }
  }
}

export function pairingDevice(state: PairingState): DeviceKind | null {
  switch (state.kind) {
    case 'open':
      return null;
    case 'ceremony':
      return 'web';
    case 'verifying':
    case 'waiting':
    case 'paired':
    case 'done':
    case 'failed':
      return state.device;
    default: {
      const unhandled: never = state;
      return unhandled;
    }
  }
}
