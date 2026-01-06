#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1; then
  docker context use desktop-linux >/dev/null 2>&1 || true
fi

docker compose run --rm apt bash


