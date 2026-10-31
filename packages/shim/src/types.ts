import type { Page } from 'playwright';

export interface ShimWebAuthnRequest {
  kind: 'create' | 'get';
  frame: { url: string; isMainFrame: boolean; securityOrigin: string | null };
  options: unknown;
  mediation: string | null;
}

export type ShimErrorName =
  | 'NotAllowedError'
  | 'InvalidStateError'
  | 'NotSupportedError'
  | 'SecurityError';

export interface SerializedCredential {
  id: string;
  type: 'public-key';
  authenticatorAttachment: 'platform';
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature?: string;
    userHandle?: string | null;
    attestationObject?: string;
    publicKey?: string;
    publicKeyAlgorithm?: number;
    transports?: string[];
  };
  clientExtensionResults: Record<string, unknown>;
}

export type ShimWebAuthnResult =
  | { ok: true; credential: SerializedCredential }
  | { ok: false; name: ShimErrorName };

export interface WebAuthnSource {
  page: Page;
}

export type WebAuthnHandler = (
  req: ShimWebAuthnRequest,
  source: WebAuthnSource,
) => Promise<ShimWebAuthnResult>;
