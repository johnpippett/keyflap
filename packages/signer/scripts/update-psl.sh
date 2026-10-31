#!/usr/bin/env bash
# Refreshes the signer's Public Suffix List snapshot (src/psl/public_suffix_list.dat) from
# https://publicsuffix.org/list/public_suffix_list.dat, the only supported source. The file
# is kept verbatim (MPL-2.0). The signer refuses to start if the list doesn't parse, so the
# new file is checked with the signer's own parser before it replaces the old one.
#
#   packages/signer/scripts/update-psl.sh
#   npx vitest run packages/signer/test/psl.test.ts packages/signer/test/inv3-public-suffix.test.ts
#
# Then commit the .dat with its VERSION line in the message. Review the diff: a removed
# rule widens what counts as one registrable domain.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="$here/../src/psl/public_suffix_list.dat"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp" https://publicsuffix.org/list/public_suffix_list.dat
node --input-type=module -e '
  import { readFileSync } from "node:fs";
  const { parsePublicSuffixList } = await import(process.argv[1]);
  const r = parsePublicSuffixList(readFileSync(process.argv[2], "utf8"));
  console.error(`public suffix list ${r.version}: ${r.normal.size + r.wildcard.size + r.exception.size} rules`);
' "$here/../src/psl.ts" "$tmp"
cp "$tmp" "$dest"
chmod 0644 "$dest"
grep -m1 '^// VERSION:' "$dest"
