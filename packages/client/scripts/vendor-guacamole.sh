#!/usr/bin/env bash
# Re-vendor guacamole-common-js from the official Apache source tree.
# Usage: scripts/vendor-guacamole.sh [tag]   (default 1.6.0)
#
# We vendor the upstream modules (instead of a third-party npm repackaging)
# so the exact code that runs in the browser is reviewable and pinned.
set -euo pipefail
TAG="${1:-1.6.0}"
BASE="https://raw.githubusercontent.com/apache/guacamole-client/${TAG}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/vendor/guacamole-common-js"
MODULES=(Namespace ArrayBufferReader ArrayBufferWriter AudioContextFactory AudioPlayer AudioRecorder
  BlobReader BlobWriter Client DataURIReader Display Event InputSink InputStream IntegerPool JSONReader
  KeyEventInterpreter Keyboard Layer Mouse Object OnScreenKeyboard OutputStream Parser Position
  RawAudioFormat SessionRecording Status StringReader StringWriter Touch Tunnel UTF8Parser Version VideoPlayer)
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
: > "$TMP/manifest.txt"
for m in "${MODULES[@]}"; do
  curl -fsS -o "$TMP/$m.js" "$BASE/guacamole-common-js/src/main/webapp/modules/$m.js"
  echo "$(sha256sum "$TMP/$m.js" | cut -d' ' -f1)  $m.js" >> "$TMP/manifest.txt"
done
curl -fsS -o "$OUT/LICENSE" "$BASE/LICENSE"
curl -fsS -o "$OUT/NOTICE" "$BASE/NOTICE"
{
  echo "// guacamole-common-js ${TAG}, concatenated from the official Apache Guacamole"
  echo "// sources (Apache License 2.0, see LICENSE and NOTICE in this directory)."
  echo "// Regenerate with packages/client/scripts/vendor-guacamole.sh"
  for m in "${MODULES[@]}"; do cat "$TMP/$m.js"; echo; done
  echo "export default Guacamole;"
} > "$OUT/guacamole-common.js"
{
  echo "Source: https://github.com/apache/guacamole-client/tree/${TAG}/guacamole-common-js/src/main/webapp/modules"
  echo "SHA-256 of each upstream module:"
  cat "$TMP/manifest.txt"
} > "$OUT/SOURCES.txt"
echo "vendored guacamole-common-js ${TAG} -> $OUT"
