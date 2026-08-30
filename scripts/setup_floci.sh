#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Starting Floci container..."
cd "$ROOT_DIR"
docker compose up -d

echo "Waiting for Floci gateway (http://localhost:4566)..."
until curl -sf http://localhost:4566/ > /dev/null 2>&1 || curl -sf http://localhost:4566/_floci/health > /dev/null 2>&1 || curl -sf http://localhost:4566/_localstack/health > /dev/null 2>&1; do
  sleep 1
done

echo "Floci is ready."
