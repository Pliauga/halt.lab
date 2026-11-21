#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "${SCRIPT_DIR}/../terraform" && pwd)"

cd "$TF_DIR"
terraform init -input=false
# Extra arguments are forwarded, e.g. ./scripts/deploy.sh -var="is_local=false".
terraform apply -auto-approve -input=false "$@"
terraform output
