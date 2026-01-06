#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash fetch_memory_dump.sh --sha256-list <file> --out-dir <dir> [--max-samples N] [--max-dumps N]

Env:
  HA_COOKIE      (required) Hybrid-Analysis cookie string (copied from browser)
  HA_SLEEP_MIN   (default 2) random sleep min seconds
  HA_SLEEP_MAX   (default 6) random sleep max seconds
  HA_RETRY_MAX   (default 5) retries on 429/5xx
  HA_CONNECT_TIMEOUT (default 10) curl connect timeout seconds
  HA_MAX_TIME    (default 60) curl max time seconds
EOF
}

SHA256_LIST=""
OUT_DIR=""
MAX_SAMPLES=0
MAX_DUMPS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha256-list) SHA256_LIST="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --max-samples) MAX_SAMPLES="${2:-0}"; shift 2;;
    --max-dumps) MAX_DUMPS="${2:-0}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "[ERROR] Unknown arg: $1" >&2; usage; exit 2;;
  esac
done

if [[ -z "${SHA256_LIST}" || -z "${OUT_DIR}" ]]; then
  echo "[ERROR] --sha256-list and --out-dir are required" >&2
  usage
  exit 2
fi

if [[ ! -f "${SHA256_LIST}" ]]; then
  echo "[ERROR] sha256 list not found: ${SHA256_LIST}" >&2
  exit 2
fi

if [[ -z "${HA_COOKIE:-}" ]]; then
  echo "[ERROR] HA_COOKIE is required (set in .env)" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"

HA_SLEEP_MIN="${HA_SLEEP_MIN:-2}"
HA_SLEEP_MAX="${HA_SLEEP_MAX:-6}"
HA_RETRY_MAX="${HA_RETRY_MAX:-5}"
HA_CONNECT_TIMEOUT="${HA_CONNECT_TIMEOUT:-10}"
HA_MAX_TIME="${HA_MAX_TIME:-60}"

sleep_jitter() {
  local mn="${HA_SLEEP_MIN}" mx="${HA_SLEEP_MAX}"
  python3 - <<PY
import random, time
mn=float(${mn}); mx=float(${mx})
if mx < mn: mx = mn
time.sleep(random.uniform(mn, mx))
PY
}

curl_retry() {
  local url="$1"
  local out="$2"
  local attempt=1
  while true; do
    local code rc
    set +e
    code="$(curl -sS -L \
      --connect-timeout "${HA_CONNECT_TIMEOUT}" \
      --max-time "${HA_MAX_TIME}" \
      -o "${out}" -w "%{http_code}" \
      -H "cookie: ${HA_COOKIE}" \
      -H "user-agent: ${HA_UA:-Mozilla/5.0}" \
      "${url}")"
    rc=$?
    set -e

    if (( rc != 0 )); then
      # Treat transient network/TLS errors as retryable
      if (( attempt >= HA_RETRY_MAX )); then
        echo "[WARN] curl failed after ${attempt} tries: ${url} (rc=${rc})" >&2
        return 1
      fi
      local backoff=$(( 2 ** (attempt-1) ))
      echo "[WARN] curl rc=${rc} retry ${attempt}/${HA_RETRY_MAX}: ${url} (sleep ${backoff}s)" >&2
      sleep "${backoff}"
      attempt=$(( attempt + 1 ))
      continue
    fi

    if [[ "${code}" == "200" ]]; then
      return 0
    fi

    if [[ "${code}" == "429" || "${code}" =~ ^5 ]]; then
      if (( attempt >= HA_RETRY_MAX )); then
        echo "[WARN] giving up after ${attempt} tries: ${url} (HTTP ${code})" >&2
        return 1
      fi
      local backoff=$(( 2 ** (attempt-1) ))
      echo "[WARN] retry ${attempt}/${HA_RETRY_MAX} HTTP ${code}: ${url} (sleep ${backoff}s)" >&2
      sleep "${backoff}"
      attempt=$(( attempt + 1 ))
      continue
    fi

    echo "[WARN] HTTP ${code}: ${url}" >&2
    return 1
  done
}

count=0
while IFS= read -r SHA256; do
  SHA256="$(echo "${SHA256}" | tr -d '\r' | xargs || true)"
  [[ -z "${SHA256}" ]] && continue

  count=$((count+1))
  if (( MAX_SAMPLES > 0 && count > MAX_SAMPLES )); then
    break
  fi

  echo "[*] Processing SHA256: ${SHA256}"
  sleep_jitter

  html="$(mktemp)"
  # NOTE: /sample/<sha> is a JS-heavy page and often does not contain analysis IDs in raw HTML.
  # The search page HTML still contains links like: sample/<sha>/<analysis_id>
  if ! curl_retry "https://hybrid-analysis.com/search?query=${SHA256}" "${html}"; then
    echo "  [WARN] failed to fetch HA search page (network/TLS/block?): ${SHA256}" >&2
    rm -f "${html}"
    continue
  fi
  MEMORY_IDS="$(grep -Eo "sample\\/${SHA256}\\/[0-9a-f]{24}" "${html}" | awk -F'/' '{print $3}' | sort -u || true)"
  rm -f "${html}"

  if [[ -z "${MEMORY_IDS}" ]]; then
    echo "  - no memory dump ids found"
    continue
  fi

  n=0
  while IFS= read -r MEMORY_ID; do
    [[ -z "${MEMORY_ID}" ]] && continue
    n=$((n+1))
    if (( MAX_DUMPS > 0 && n > MAX_DUMPS )); then
      break
    fi

    out="${OUT_DIR}/${SHA256}_${MEMORY_ID}_memory.zip"
    echo "  - downloading dump ${MEMORY_ID} -> ${out}"
    sleep_jitter
    if ! curl_retry "https://hybrid-analysis.com/sample-memory-dump/${MEMORY_ID}/all" "${out}"; then
      rm -f "${out}" || true
      continue
    fi

    # quick sanity: rename if it's HTML
    if file "${out}" | grep -qi "html"; then
      mv "${out}" "${out}.html"
      echo "  [WARN] got HTML instead of ZIP (cookie expired?): ${out}.html" >&2
      continue
    fi
  done <<< "${MEMORY_IDS}"

done < "${SHA256_LIST}"

echo "[*] Done. Output dir: ${OUT_DIR}"
