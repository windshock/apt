#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Extract high-signal artifacts from Windows memory dump artifacts.

Why:
  - Loaded PE modules (proxy): regions containing PE headers ("MZ" + "PE\0\0")
  - RWX / executable regions: regions whose filename encodes PAGE_EXECUTE* protections (HA exports)

Usage (run inside Docker via scripts/apt_docker.sh):
  # For HA region-split dumps (recommended): pass the root folder that contains many "*_memory/" subfolders
  bash scripts/apt_docker.sh bash scripts/extract_mdmp.sh --mdmp /data/ha_dumps_unz

  # Or process a single HA dump folder
  bash scripts/apt_docker.sh bash scripts/extract_mdmp.sh --mdmp /data/ha_dumps_unz/<dump_folder>

Options:
  --mdmp <path>         File or directory. If directory, scans *.mdmp/*.dmp recursively.
  --out <dir>           Output base dir (default: /data/mdmp_extracted)
  --mode <both|dlllist|malfind>
                        What to dump (default: both)
  --pid <pid[,pid...]>  Restrict to specific PID(s) for dlllist/malfind (optional)
  --offline             Do not download symbols (requires pre-populated symbols dir)
  --rwx-only            Only select PAGE_EXECUTE_READWRITE (0x40) regions (HA format only)
  --copy                Copy selected region files into /data (instead of symlinks). Uses more disk.

Notes:
  - Volatility symbol/cache are persisted in /data/volatility3 to avoid re-downloading.
  - For HA dumps, this script does NOT rely on Volatility (the files are already split into regions).
  - Output is always created under:
      <out>/<dump_or_file_basename>/{dlllist,malfind}/
EOF
}

MDMP_PATH=""
OUT_BASE="/data/mdmp_extracted"
MODE="both"
PID_CSV=""
OFFLINE=0
RWX_ONLY=0
COPY_MODE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --mdmp) MDMP_PATH="${2:-}"; shift 2 ;;
    --out) OUT_BASE="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --pid) PID_CSV="${2:-}"; shift 2 ;;
    --offline) OFFLINE=1; shift ;;
    --rwx-only) RWX_ONLY=1; shift ;;
    --copy) COPY_MODE=1; shift ;;
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
    # mdmp sometimes uses .dmp in other toolchains; HA exports use many *.mdmp per dump folder.
    find "$p" -type f \( -iname '*.mdmp' -o -iname '*.dmp' \) -print
    return 0
  fi
  echo "ERROR: --mdmp path not found: $p" >&2
  exit 2
}

select_ha_regions() {
  local dump_dir="$1"
  local name
  name="$(basename "$dump_dir")"
  local out_dir="${OUT_BASE}/${name}"
  mkdir -p "${out_dir}"

  local ha_args=(--src "$dump_dir" --out "$out_dir")
  if [[ "${RWX_ONLY}" -eq 1 ]]; then
    ha_args+=(--rwx-only)
  fi
  if [[ "${COPY_MODE}" -eq 1 ]]; then
    ha_args+=(--copy)
  fi

  echo "[*] HA regions: ${dump_dir}"
  echo "    out: ${out_dir}"
  python3 /work/scripts/extract_ha_mdmp_regions.py "${ha_args[@]}"
}

if [[ -d "${MDMP_PATH}" ]]; then
  # HA root: /data/ha_dumps_unz has many "*_memory/" subfolders.
  # If MDMP_PATH itself contains *.mdmp directly, treat it as a single dump folder.
  if [[ -n "$(find "${MDMP_PATH}" -maxdepth 1 -type f -name "*.mdmp" -print -quit 2>/dev/null)" ]]; then
    select_ha_regions "${MDMP_PATH}"
    echo "[*] done"
    exit 0
  fi

  # Otherwise process subfolders.
  processed=0
  while IFS= read -r d; do
    select_ha_regions "$d"
    processed=$((processed + 1))
  done < <(find "${MDMP_PATH}" -mindepth 1 -maxdepth 1 -type d -print)

  echo "[*] done: processed ${processed} dump folder(s)"
  exit 0
fi

# File input: attempt Volatility as a best-effort fallback (may not work for HA region files).
f="${MDMP_PATH}"
base="$(basename "$f")"
base="${base%.*}"
out_dir="${OUT_BASE}/${base}"
mkdir -p "${out_dir}"
echo "[*] file: ${f}"
echo "    out: ${out_dir}"

if [[ "${MODE}" == "both" || "${MODE}" == "dlllist" ]]; then
  dll_out="${out_dir}/dlllist"
  mkdir -p "${dll_out}"
  echo "    - dumping loaded PE modules (vol windows.dlllist --dump) [best-effort]"
  "${VOL_BASE[@]}" -f "${f}" -o "${dll_out}" windows.dlllist "${pid_args[@]}" --dump || true
fi

if [[ "${MODE}" == "both" || "${MODE}" == "malfind" ]]; then
  mal_out="${out_dir}/malfind"
  mkdir -p "${mal_out}"
  echo "    - dumping executable regions (vol windows.malfind --dump) [best-effort]"
  "${VOL_BASE[@]}" -f "${f}" -o "${mal_out}" windows.malfind "${pid_args[@]}" --dump || true
fi

echo "[*] done"


