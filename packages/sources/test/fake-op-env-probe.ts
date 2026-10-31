#!/usr/bin/env node
import { appendFileSync } from 'node:fs';
import { join } from 'node:path';

appendFileSync(
  join(process.env.KEYFLAP_FAKE_OP_DIR ?? '', 'env-values.jsonl'),
  `${JSON.stringify({
    OP_CACHE: process.env.OP_CACHE ?? null,
    OP_BIOMETRIC_UNLOCK_ENABLED: process.env.OP_BIOMETRIC_UNLOCK_ENABLED ?? null,
  })}\n`,
);
await import('./fake-op.ts');
