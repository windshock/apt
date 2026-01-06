#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1; then
  # helpful on macOS when context is not set
  docker context use desktop-linux >/dev/null 2>&1 || true
fi

docker compose run --rm apt "$@"


