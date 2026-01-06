#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Extract high-signal artifacts from Windows mdmp/minidump files using Volatility3.

Why:
  - Loaded PE modules: dump with windows.dlllist --dump
  - RWX / Private executable regions: dump with windows.malfind --dump

Usage (run inside Docker via scripts/apt_docker.sh):
  bash scripts/apt_docker.sh bash scripts/extract_mdmp.sh --mdmp /data/ha_dumps_unz/<folder>
  bash scripts/apt_docker.sh bash scripts/extract_mdmp.sh --mdmp /data/ha_dumps_unz/<folder>/something.mdmp

Options:
  --mdmp <path>         File or directory. If directory, scans *.mdmp/*.dmp recursively.
  --out <dir>           Output base dir (default: /data/mdmp_extracted)
  --mode <both|dlllist|malfind>
                        What to dump (default: both)
  --pid <pid[,pid...]>  Restrict to specific PID(s) for dlllist/malfind (optional)
  --offline             Do not download symbols (requires pre-populated symbols dir)

Notes:
  - Volatility symbol/cache are persisted in /data/volatility3 to avoid re-downloading.
  - This script intentionally extracts only "high signal" areas for downstream YARA scanning.
EOF
}

MDMP_PATH=""
OUT_BASE="/data/mdmp_extracted"
MODE="both"
PID_CSV=""
OFFLINE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --mdmp) MDMP_PATH="${2:-}"; shift 2 ;;
    --out) OUT_BASE="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --pid) PID_CSV="${2:-}"; shift 2 ;;
    --offline) OFFLINE=1; shift ;;
    *)
      echo "Unknown arg: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${MDMP_PATH}" ]]; then
  echo "ERROR: --mdmp is required" >&2
  usage >&2
  exit 2
fi

if [[ "${MODE}" != "both" && "${MODE}" != "dlllist" && "${MODE}" != "malfind" ]]; then
  echo "ERROR: --mode must be one of: both|dlllist|malfind" >&2
  exit 2
fi

SYMBOL_DIR="/data/volatility3/symbols"
CACHE_DIR="/data/volatility3/cache"
mkdir -p "${SYMBOL_DIR}" "${CACHE_DIR}" "${OUT_BASE}"

VOL_BASE=(vol --parallelism threads --cache-path "${CACHE_DIR}" -s "${SYMBOL_DIR}")
if [[ "${OFFLINE}" -eq 1 ]]; then
  VOL_BASE+=(--offline)
fi

pid_args=()
if [[ -n "${PID_CSV}" ]]; then
  # allow "123,456" or "123 456"
  PID_CSV="${PID_CSV//,/ }"
  # shellcheck disable=SC2206
  pid_args=(--pid ${PID_CSV})
fi

gather_mdmp_files() {
  local p="$1"
  if [[ -f "$p" ]]; then
    echo "$p"
    return 0
  fi
  if [[ -d "$p" ]]; then
    # mdmp sometimes uses .dmp in HA zips
    find "$p" -type f \( -iname '*.mdmp' -o -iname '*.dmp' \) -print
    return 0
  fi
  echo "ERROR: --mdmp path not found: $p" >&2
  exit 2
}

dump_one() {
  local f="$1"
  local base
  base="$(basename "$f")"
  base="${base%.*}"

  local out_dir="${OUT_BASE}/${base}"
  mkdir -p "${out_dir}"

  echo "[*] mdmp: ${f}"
  echo "    out: ${out_dir}"

  if [[ "${MODE}" == "both" || "${MODE}" == "dlllist" ]]; then
    local dll_out="${out_dir}/dlllist"
    mkdir -p "${dll_out}"
    echo "    - dumping loaded PE modules (windows.dlllist --dump)"
    "${VOL_BASE[@]}" -f "${f}" -o "${dll_out}" windows.dlllist "${pid_args[@]}" --dump || true
  fi

  if [[ "${MODE}" == "both" || "${MODE}" == "malfind" ]]; then
    local mal_out="${out_dir}/malfind"
    mkdir -p "${mal_out}"
    echo "    - dumping RWX/private executable regions (windows.malfind --dump)"
    "${VOL_BASE[@]}" -f "${f}" -o "${mal_out}" windows.malfind "${pid_args[@]}" --dump || true
  fi
}

count=0
while IFS= read -r mdmp; do
  dump_one "${mdmp}"
  count=$((count + 1))
done < <(gather_mdmp_files "${MDMP_PATH}")

echo "[*] done: processed ${count} mdmp file(s)"


