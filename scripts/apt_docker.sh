#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1; then
  # helpful on macOS when context is not set
  docker context use desktop-linux >/dev/null 2>&1 || true
fi

# Pass through selected env vars (useful for per-run overrides like MB_DOWNLOAD_DIR).
extra_env=()
while IFS='=' read -r name _; do
  case "$name" in
    MB_*|HA_*|MALPEDIA_*) extra_env+=(-e "$name");;
  esac
done < <(env)

docker compose run --rm "${extra_env[@]}" apt "$@"


