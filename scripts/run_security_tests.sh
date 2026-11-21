#!/usr/bin/env bash
# End-to-end verification of the halt.lab secret-scanning pipeline.
#
# Requires an initialised Terraform workspace (terraform init) whose outputs
# point at the S3/SQS stack under test. Tests are stateful and destructive:
# every object they upload is quarantined or tagged, so run this only against
# a disposable stack (Floci emulator or a sandbox account).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "${SCRIPT_DIR}/../terraform" && pwd)"

ENDPOINT="${AWS_ENDPOINT_URL:-http://localhost:4566}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Emulator credentials; real runs must provide real credentials via the
# environment instead. These are throw-away strings, not secrets.
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-mock_access_key}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-mock_secret_key}"
export AWS_DEFAULT_REGION="$REGION"

aws_cmd() {
  aws --endpoint-url="$ENDPOINT" "$@"
}

if [[ ! -d "$TF_DIR/.terraform" ]]; then
  echo "ERROR: ${TF_DIR}/.terraform is missing. Run 'terraform init' first." >&2
  exit 1
fi

DATA_BUCKET=$(terraform -chdir="$TF_DIR" output -raw data_vault_bucket)
QUARANTINE_BUCKET=$(terraform -chdir="$TF_DIR" output -raw quarantine_vault_bucket)
SQS_QUEUE_URL=$(terraform -chdir="$TF_DIR" output -raw sqs_event_queue_url)
SQS_DLQ_URL=$(terraform -chdir="$TF_DIR" output -raw sqs_dlq_url)

WORK_DIR=$(mktemp -d)
# Invoked indirectly via `trap cleanup EXIT`.
# shellcheck disable=SC2329
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

passed=0
failed=0

record() { # record <0|1> <description> [detail]
  local ok=$1 description=$2 detail=${3:-}
  if [[ "$ok" -eq 0 ]]; then
    printf 'OK   %s\n' "$description"
    passed=$((passed + 1))
  else
    if [[ -n "$detail" ]]; then
      printf 'FAIL %s (%s)\n' "$description" "$detail"
    else
      printf 'FAIL %s\n' "$description"
    fi
    failed=$((failed + 1))
  fi
}

wait_until() { # wait_until <attempts> <predicate> [args...]
  local attempts=$1
  shift
  local i
  for ((i = 0; i < attempts; i++)); do
    if "$@"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Invoked indirectly via the wait_until polling helper.
# shellcheck disable=SC2329
has_security_tag() { # has_security_tag <bucket> <key> <value>
  aws_cmd s3api get-object-tagging --bucket "$1" --key "$2" --output json 2>/dev/null \
    | jq -e --arg v "$3" 'any(.TagSet[]?; .Key == "SecurityStatus" and .Value == $v)' > /dev/null
}

tag_value() { # tag_value <bucket> <key> <tag-key>
  local value
  value=$(aws_cmd s3api get-object-tagging --bucket "$1" --key "$2" --output json 2>/dev/null \
    | jq -r --arg k "$3" '[.TagSet[]? | select(.Key == $k) | .Value][0] // ""' || echo "")
  printf '%s' "$value"
}

# Invoked indirectly via the wait_until polling helper.
# shellcheck disable=SC2329
has_no_versions() { # has_no_versions <bucket> <key>
  local listing
  listing=$(aws_cmd s3api list-object-versions --bucket "$1" --prefix "$2" --output json 2>/dev/null) || return 1
  jq -e --arg k "$2" '([.Versions[]?, .DeleteMarkers[]?] | map(select(.Key == $k)) | length) == 0' <<< "$listing" > /dev/null
}

quarantine_key_for() { # quarantine_key_for <substring> -> prints key or nothing
  local found
  found=$(aws_cmd s3api list-objects-v2 --bucket "$QUARANTINE_BUCKET" --prefix "quarantined/" \
    --query 'Contents[].Key' --output text 2>/dev/null \
    | tr '\t' '\n' | grep -F "$1" | head -n 1 || echo "")
  printf '%s' "$found"
}

# Invoked indirectly via the wait_until polling helper.
# shellcheck disable=SC2329
dlq_not_empty() {
  local depth
  depth=$(aws_cmd sqs get-queue-attributes --queue-url "$SQS_DLQ_URL" \
    --attribute-names ApproximateNumberOfMessages \
    --query 'Attributes.ApproximateNumberOfMessages' --output text 2>/dev/null || echo "0")
  [[ "$depth" =~ ^[1-9][0-9]*$ ]]
}

put_object() { # put_object <bucket> <key> <file> [tagging]
  local bucket=$1 key=$2 file=$3 tagging=${4:-}
  if [[ -n "$tagging" ]]; then
    aws_cmd s3api put-object --bucket "$bucket" --key "$key" --body "$file" --tagging "$tagging" > /dev/null
  else
    aws_cmd s3api put-object --bucket "$bucket" --key "$key" --body "$file" > /dev/null
  fi
}

purge_queue() { # purge_queue <url>
  if ! aws_cmd sqs purge-queue --queue-url "$1" > /dev/null 2>&1; then
    echo "(warning: could not purge $1)" >&2
  fi
  sleep 2
}

echo "Running security integration tests..."
echo "Target endpoint: $ENDPOINT"
echo "Data vault:      $DATA_BUCKET"
echo "Quarantine:      $QUARANTINE_BUCKET"
echo ""

purge_queue "$SQS_DLQ_URL"

# 1. Clean object is approved and keeps the owner's tags.
echo "1. Clean upload is approved and preserves custom tags"
printf 'Sample legitimate log payload.\n' > "$WORK_DIR/clean.txt"
put_object "$DATA_BUCKET" "uploads/clean_doc.txt" "$WORK_DIR/clean.txt" "Owner=alice&Team=platform"
clean_ok=1
if wait_until 30 has_security_tag "$DATA_BUCKET" "uploads/clean_doc.txt" "APPROVED"; then
  owner=$(tag_value "$DATA_BUCKET" "uploads/clean_doc.txt" "Owner")
  team=$(tag_value "$DATA_BUCKET" "uploads/clean_doc.txt" "Team")
  if [[ "$owner" == "alice" && "$team" == "platform" ]]; then
    clean_ok=0
  else
    clean_ok=1
  fi
  clean_detail="tags after approval: Owner=${owner:-<missing>} Team=${team:-<missing>}"
else
  clean_detail="object was not tagged APPROVED within 30s"
fi
record "$clean_ok" "clean upload approved with custom tags intact" "${clean_detail:-}"

# 2. A secret is quarantined, leaves no version behind, and lands versioned.
echo "2. Secret upload is quarantined and no version remains readable"
cat > "$WORK_DIR/secrets.env" << 'EOF'
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EOF
put_object "$DATA_BUCKET" "uploads/secrets.env" "$WORK_DIR/secrets.env"
quarantine_ok=1
if wait_until 30 has_no_versions "$DATA_BUCKET" "uploads/secrets.env"; then
  qkey=$(quarantine_key_for "secrets.env")
  if [[ -n "$qkey" ]]; then
    qversions=$(aws_cmd s3api list-object-versions --bucket "$QUARANTINE_BUCKET" --prefix "$qkey" \
      --query 'length(Versions[])' --output text 2>/dev/null || echo "0")
    if [[ "$qversions" =~ ^[1-9][0-9]*$ ]]; then
      quarantine_ok=0
    fi
    quarantine_detail="quarantine key ${qkey} has ${qversions:-0} version(s)"
  else
    quarantine_detail="no quarantined copy found"
  fi
else
  quarantine_detail="data vault still holds versions of uploads/secrets.env"
fi
record "$quarantine_ok" "secret purged from data vault into a versioned quarantine copy" "${quarantine_detail:-}"

# 3. Overwrite race: the superseded secret version is still caught.
echo "3. Overwrite race still quarantines the secret version"
cat > "$WORK_DIR/race.txt" << 'EOF'
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
EOF
put_object "$DATA_BUCKET" "uploads/race.txt" "$WORK_DIR/race.txt"
printf 'harmless replacement\n' > "$WORK_DIR/race_clean.txt"
put_object "$DATA_BUCKET" "uploads/race.txt" "$WORK_DIR/race_clean.txt"
race_ok=1
if wait_until 30 has_no_versions "$DATA_BUCKET" "uploads/race.txt"; then
  qkey=$(quarantine_key_for "race.txt")
  if [[ -n "$qkey" ]] && aws_cmd s3api get-object --bucket "$QUARANTINE_BUCKET" --key "$qkey" "$WORK_DIR/race_out" > /dev/null 2>&1; then
    if grep -q "AKIAIOSFODNN7EXAMPLE" "$WORK_DIR/race_out"; then
      race_ok=0
    else
      race_detail="quarantined copy did not contain the secret"
    fi
  else
    race_detail="no quarantined copy for race.txt"
  fi
else
  race_detail="secret version survived in the data vault"
fi
record "$race_ok" "overwrite race quarantines the superseded secret version" "${race_detail:-}"

# 4. Objects outside uploads/ are scanned too.
echo "4. Object outside the uploads/ prefix is scanned and quarantined"
cat > "$WORK_DIR/private_token.txt" << 'EOF'
token=ghp_012345678901234567890123456789012345
EOF
put_object "$DATA_BUCKET" "private/token.txt" "$WORK_DIR/private_token.txt"
prefix_ok=1
if wait_until 30 has_no_versions "$DATA_BUCKET" "private/token.txt"; then
  if [[ -n "$(quarantine_key_for "private/token.txt")" ]]; then
    prefix_ok=0
  else
    prefix_detail="no quarantined copy found"
  fi
else
  prefix_detail="private/token.txt was never removed from the data vault"
fi
record "$prefix_ok" "non-uploads/ prefix is scanned" "${prefix_detail:-}"

# 5. A long key must not break the alert path.
echo "5. Long object key quarantines without alert or DLQ errors"
long_key="uploads/$(printf 'a%.0s' $(seq 1 140)).txt"
printf 'password: hunter2-prod-2026\n' > "$WORK_DIR/long.txt"
put_object "$DATA_BUCKET" "$long_key" "$WORK_DIR/long.txt"
long_ok=1
if wait_until 30 has_no_versions "$DATA_BUCKET" "$long_key"; then
  if [[ -n "$(quarantine_key_for "$long_key")" ]]; then
    long_ok=0
  else
    long_detail="no quarantined copy found"
  fi
else
  long_detail="long key was not quarantined"
fi
dlq_depth=$(aws_cmd sqs get-queue-attributes --queue-url "$SQS_DLQ_URL" \
  --attribute-names ApproximateNumberOfMessages \
  --query 'Attributes.ApproximateNumberOfMessages' --output text 2>/dev/null || echo "unknown")
if [[ "$dlq_depth" != "0" && "$dlq_depth" != "unknown" ]]; then
  long_ok=1
  long_detail="DLQ depth is ${dlq_depth} after the long-key upload"
fi
record "$long_ok" "long key quarantines cleanly" "${long_detail:-}"

# 6. Detection coverage for the leak families that used to slip through.
echo "6. Leak corpus is caught (quoted, unquoted, PAT, UTF-16, oversize, .env)"
probe_failures=0
probe_names=()

write_probe() { # write_probe <name> <python expression writing to path>
  local name=$1 body=$2
  python3 -c "import sys; open(sys.argv[1], 'wb').write($body)" "$WORK_DIR/$name"
  probe_names+=("$name")
}

write_probe "01_quoted_aws.txt" "b'AWS_SECRET_ACCESS_KEY=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n'"
write_probe "02_unquoted_password.txt" "b'password: hunter2-prod-2026\n'"
write_probe "03_github_pat.txt" "b'token=ghp_012345678901234567890123456789012345\n'"
write_probe "04_utf16.txt" "'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'.encode('utf-16-le')"
write_probe "05_oversize.txt" "b'A' * 70000 + b'\nAKIAIOSFODNN7EXAMPLE\n'"
write_probe "06_control.env" "b'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'"

for name in "${probe_names[@]}"; do
  key="probes/${name}"
  put_object "$DATA_BUCKET" "$key" "$WORK_DIR/$name"
  if ! wait_until 30 has_no_versions "$DATA_BUCKET" "$key"; then
    probe_failures=$((probe_failures + 1))
    echo "     missed: $name" >&2
  fi
done
record "$probe_failures" "all ${#probe_names[@]} leak probes quarantined" "${probe_failures} probe(s) missed"

# 7. Bucket policies still enforce TLS on both vaults.
echo "7. Both vaults deny non-TLS requests"
tls_ok=0
for bucket in "$DATA_BUCKET" "$QUARANTINE_BUCKET"; do
  policy=$(aws_cmd s3api get-bucket-policy --bucket "$bucket" --output text 2>/dev/null || echo "")
  if ! grep -q "aws:SecureTransport" <<< "$policy"; then
    tls_ok=1
    echo "     missing SecureTransport deny on ${bucket}" >&2
  fi
done
record "$tls_ok" "TLS-only bucket policies on data and quarantine vaults"

# 8. Poison messages reach the DLQ (queue purged first so a stale depth cannot pass).
echo "8. Poison message is redriven to the DLQ"
purge_queue "$SQS_DLQ_URL"
aws_cmd sqs send-message --queue-url "$SQS_QUEUE_URL" --message-body "NON_JSON_CORRUPT_PAYLOAD" > /dev/null
dlq_ok=1
if wait_until 120 dlq_not_empty; then
  dlq_ok=0
fi
record "$dlq_ok" "malformed message routed to the DLQ" "${dlq_detail:-}"

echo ""
echo "Passed: ${passed}  Failed: ${failed}"
if [[ "$failed" -eq 0 ]]; then
  echo "All integration tests passed."
  exit 0
fi
echo "${failed} test(s) failed."
exit 1
