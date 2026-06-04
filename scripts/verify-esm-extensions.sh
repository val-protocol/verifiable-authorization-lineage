#!/usr/bin/env bash
# Pre-publish verifier: assert dist/esm has no unextensioned relative imports.
#
# Bug class: TypeScript ESM emit does NOT auto-add `.js` to relative imports.
# `moduleResolution: "Bundler"` and `"Node"` accept extensionless source, but
# the emitted JS goes straight to Node strict ESM resolution, which rejects
# extensionless relative imports at `npm install`-time for external consumers.
#
# Guards against the ESM relative-import-without-.js-suffix regression that
# only surfaces at external consumers' `npm install`-time.
#
# Invoke from a package directory (cwd = the package). Expects dist/esm/ to
# exist (run after `npm run build`).

set -euo pipefail

DIST="${1:-dist/esm}"

if [ ! -d "$DIST" ]; then
  echo "verify-esm-extensions: $DIST does not exist — nothing to verify (likely CJS-only package)"
  exit 0
fi

# Match any relative import that does NOT end in .js or .json before the closing quote.
HITS=$(grep -rEn "from ['\"]\.\.?/[^'\"]*['\"]" "$DIST" 2>/dev/null \
  | grep -vE "\.js['\"]|\.json['\"]" \
  || true)

if [ -n "$HITS" ]; then
  echo "verify-esm-extensions: FAIL — unextensioned relative imports in $DIST:"
  echo "$HITS"
  echo ""
  echo "Fix: add '.js' suffix to the source TypeScript imports (e.g. from './foo' → from './foo.js')."
  exit 1
fi

echo "verify-esm-extensions: OK — $DIST has zero unextensioned relative imports"
