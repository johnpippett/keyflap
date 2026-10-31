#!/bin/bash
# Installs workspace dependencies so typecheck, lint, and tests work in Claude Code
# cloud sessions. Idempotent; the container is cached after this runs.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

if ! command -v pnpm >/dev/null 2>&1; then
  corepack enable >/dev/null 2>&1 || npm install -g pnpm@10.28.0
fi

pnpm install --prefer-offline

# Cloud images may ship a Chromium under PLAYWRIGHT_BROWSERS_PATH, but not necessarily the
# revision the pinned Playwright drives (docs/IMPLEMENTATION_NOTES.md "Runtime pins").
# `playwright install` is a no-op when that exact revision is already there.
pnpm --filter @aab/shim exec playwright install chromium

if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  # node:sqlite is still flagged experimental on Node 22; keep test output readable.
  echo 'export NODE_OPTIONS="--disable-warning=ExperimentalWarning"' >> "$CLAUDE_ENV_FILE"
fi
