#!/usr/bin/env bash
set -euo pipefail

# Generate YARA rules from HA mdmp corpus using yara-signator.
# NOTE: This can be slow; start with small limits.

ROOT="${1:-/data/ha_dumps_unz}"
OUT_DIR="${2:-/data/rules/generated}"
MAX_FILES="${MAX_FILES:-200}"          # total mdmp files to process
MAX_PER_FOLDER="${MAX_PER_FOLDER:-10}" # mdmp files per dump folder

mkdir -p "$OUT_DIR"

if ! command -v yara-signator >/dev/null 2>&1; then
  echo "[*] Installing yara-signator from GitHub (requires network)..."
  pip install --no-cache-dir "git+https://github.com/fxb-cocacoding/yara-signator.git"
fi

echo "[*] Collecting mdmp files from: $ROOT"
LIST="$(mktemp)"
count=0
while IFS= read -r d; do
  per=0
  while IFS= read -r f; do
    echo "$f" >> "$LIST"
    count=$((count+1))
    per=$((per+1))
    if [[ "$per" -ge "$MAX_PER_FOLDER" ]]; then
      break
    fi
    if [[ "$count" -ge "$MAX_FILES" ]]; then
      break 2
    fi
  done < <(find "$d" -type f -name "*.mdmp" 2>/dev/null | sort)
done < <(find "$ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)

echo "[*] Selected mdmp files: $count (MAX_FILES=$MAX_FILES, MAX_PER_FOLDER=$MAX_PER_FOLDER)"

STAMP="$(date -u +%Y%m%d_%H%M%S)"
OUT_RULE="$OUT_DIR/ha_mdmp_yara_signator_${STAMP}.yar"

echo "[*] Running yara-signator..."
echo "[*] Output: $OUT_RULE"

# We don't assume exact CLI flags; run help if invocation fails.
if yara-signator --help >/dev/null 2>&1; then
  :
fi

# Attempt common invocation pattern:
# If this fails, check `yara-signator --help` in the container and adjust.
set +e
yara-signator --input-list "$LIST" --output "$OUT_RULE"
rc=$?
set -e

if [[ "$rc" -ne 0 ]]; then
  echo "[ERROR] yara-signator invocation failed (rc=$rc). Try running:" >&2
  echo "  yara-signator --help" >&2
  exit "$rc"
fi

echo "[*] Done."


