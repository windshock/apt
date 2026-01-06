#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Docker-first helper for Volatility3 YARA scanning.

This project vendors an external alias plugin:
  - windows.yarascan (alias for volatility3's built-in windows.vadyarascan)

It lets you run the familiar command style:
  vol --plugin-dirs /work/vol_plugins windows.yarascan --yara-file=<rules> -f <mem>

Usage (host -> Docker):
  bash scripts/apt_docker.sh bash scripts/vol_yarascan.sh \
    --mem /data/some_windows_memory_image.raw \
    --rules /data/rules/malpedia/win.amadey.yar \
    --pid 1234

Options:
  --mem <path>     Memory image path inside container (/data/.. recommended)
  --rules <path>   YARA rules file path inside container
  --pid <pid>      Optional PID filter (can be repeated)
  --out <path>     Optional output file (default: stdout)

Notes:
  - This works only on memory images Volatility3 can stack (raw/VMEM/etc).
  - It does NOT work on Hybrid-Analysis /data/ha_dumps_unz region-split blobs.
EOF
}

MEM=""
RULES=""
OUT=""
PIDS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0;;
    --mem) MEM="${2:-}"; shift 2;;
    --rules) RULES="${2:-}"; shift 2;;
    --out) OUT="${2:-}"; shift 2;;
    --pid) PIDS+=("${2:-}"); shift 2;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 2;;
  esac
done

if [[ -z "${MEM}" || -z "${RULES}" ]]; then
  echo "ERROR: --mem and --rules are required" >&2
  usage >&2
  exit 2
fi

cmd=(vol --plugin-dirs /work/vol_plugins -f "${MEM}" windows.yarascan --yara-file "${RULES}")
if ((${#PIDS[@]})); then
  cmd+=(--pid "${PIDS[@]}")
fi

if [[ -n "${OUT}" ]]; then
  "${cmd[@]}" > "${OUT}"
  echo "Wrote: ${OUT}"
else
  "${cmd[@]}"
fi


