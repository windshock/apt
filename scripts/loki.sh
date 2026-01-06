#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run Neo23x0/Loki inside this project's Docker container (Docker-first).

Why:
  - Loki expects a full repo layout (loki.py + lib/ + config/ + signature-base/).
  - We avoid committing third-party code by cloning Loki into the Docker volume (/data) at runtime.
  - We reuse an existing signature-base clone (if present) to avoid duplicate downloads.

Refs:
  - Loki upstream: `https://github.com/Neo23x0/Loki`
  - signature-base: `https://github.com/Neo23x0/signature-base`

Usage:
  # help
  bash scripts/apt_docker.sh bash scripts/loki.sh -- --help

  # scan extracted HA regions
  bash scripts/apt_docker.sh bash scripts/loki.sh --scan /data/mdmp_extracted

  # scan downloaded sample corpus
  bash scripts/apt_docker.sh bash scripts/loki.sh --scan /data/unzip_amd_100

Options:
  --loki-dir <path>   Loki checkout path (default: /data/tools/loki)
  --sig-base <path>   signature-base path (default: /data/rules/thirdparty/signature-base if exists, else /data/tools/loki/signature-base)
  --scan <path>       Path to scan (mapped to Loki -p)
  --                 Everything after `--` is passed verbatim to loki.py (advanced).

Notes:
  - In Linux Docker, Loki's process-memory scan is not run (Windows-only in upstream).
EOF
}

LOKI_DIR="/data/tools/loki"
SIG_BASE=""
SCAN_PATH=""
PASSTHRU=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0;;
    --loki-dir) LOKI_DIR="${2:-}"; shift 2;;
    --sig-base) SIG_BASE="${2:-}"; shift 2;;
    --scan) SCAN_PATH="${2:-}"; shift 2;;
    --) shift; PASSTHRU+=("$@"); break;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 2;;
  esac
done

mkdir -p "$(dirname "$LOKI_DIR")"

if [[ ! -d "${LOKI_DIR}/.git" ]]; then
  echo "[*] cloning Loki into ${LOKI_DIR}"
  git clone --depth 1 https://github.com/Neo23x0/Loki.git "${LOKI_DIR}"
else
  echo "[*] updating Loki in ${LOKI_DIR}"
  (cd "${LOKI_DIR}" && git fetch --depth 1 origin master && git checkout -q master && git reset --hard origin/master)
fi

if [[ -z "${SIG_BASE}" ]]; then
  if [[ -d "/data/rules/thirdparty/signature-base/.git" ]]; then
    SIG_BASE="/data/rules/thirdparty/signature-base"
  else
    SIG_BASE="${LOKI_DIR}/signature-base"
  fi
fi

# Ensure signature-base is available under Loki's expected path.
if [[ "${SIG_BASE}" != "${LOKI_DIR}/signature-base" ]]; then
  rm -rf "${LOKI_DIR}/signature-base"
  ln -s "${SIG_BASE}" "${LOKI_DIR}/signature-base"
fi

cd "${LOKI_DIR}"

if ((${#PASSTHRU[@]})); then
  exec python3 loki.py "${PASSTHRU[@]}"
fi

if [[ -z "${SCAN_PATH}" ]]; then
  echo "ERROR: provide --scan <path> or pass Loki args after --" >&2
  exit 2
fi

# Minimal scan invocation:
# -p <path> scan path
# --intense also scans more extensions/types (useful for corpora)
exec python3 loki.py -p "${SCAN_PATH}" --intense


