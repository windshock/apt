#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run THOR Lite inside this project's Docker container (without committing the binary).

You must download THOR Lite yourself and place the Linux binary + signature pack under /data.
See: `https://www.nextron-systems.com/thor-lite/`

Typical layout in the Docker volume:
  /data/thor-lite/
    thor-lite              (or similar Linux binary name)
    signatures/            (signature pack; optional depending on distribution)

Usage:
  # show THOR Lite help
  bash scripts/apt_docker.sh bash scripts/thor_lite.sh -- --help

  # scan our extracted HA regions
  bash scripts/apt_docker.sh bash scripts/thor_lite.sh -- --folder /data/mdmp_extracted

  # scan downloaded sample corpus
  bash scripts/apt_docker.sh bash scripts/thor_lite.sh -- --folder /data/unzip_amd_100

Options:
  --bin <path>   THOR Lite binary path inside container (default: /data/thor-lite/thor-lite)
  --             Everything after `--` is passed verbatim to THOR Lite.
EOF
}

BIN="/data/thor-lite/thor-lite"

args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0;;
    --bin) BIN="${2:-}"; shift 2;;
    --) shift; args+=("$@"); break;;
    *) echo "Unknown arg (use -- to pass through): $1" >&2; usage >&2; exit 2;;
  esac
done

if [[ ! -x "${BIN}" ]]; then
  echo "ERROR: THOR Lite binary not found/executable: ${BIN}" >&2
  echo "Put it under /data/thor-lite/ (Docker volume) and chmod +x it." >&2
  exit 2
fi

exec "${BIN}" "${args[@]}"


