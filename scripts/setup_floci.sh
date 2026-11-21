#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENDPOINT="${FLOCI_ENDPOINT:-http://localhost:4566}"
MAX_ATTEMPTS="${FLOCI_WAIT_ATTEMPTS:-60}"

echo "Starting Floci container..."
cd "$ROOT_DIR"
docker compose up -d

echo "Waiting for Floci gateway (${ENDPOINT})..."
for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
  if curl -sf "${ENDPOINT}/" > /dev/null 2>&1 \
    || curl -sf "${ENDPOINT}/_floci/health" > /dev/null 2>&1 \
    || curl -sf "${ENDPOINT}/_localstack/health" > /dev/null 2>&1; then
    echo "Floci is ready."
    exit 0
  fi
  sleep 1
done

echo "ERROR: Floci did not become ready after ${MAX_ATTEMPTS}s." >&2
docker compose logs --tail 20 >&2 || echo "(could not read compose logs)" >&2
exit 1
