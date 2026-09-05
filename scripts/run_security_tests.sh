#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "${SCRIPT_DIR}/../terraform" && pwd)"

ENDPOINT="${AWS_ENDPOINT_URL:-http://localhost:4566}"
REGION="us-east-1"
export AWS_ACCESS_KEY_ID="mock_access_key"
export AWS_SECRET_ACCESS_KEY="mock_secret_key"
export AWS_DEFAULT_REGION="$REGION"

if [[ -d "$TF_DIR/.terraform" ]]; then
  DATA_BUCKET=$(terraform -chdir="$TF_DIR" output -raw data_vault_bucket 2>/dev/null || echo "halt-lab-data-vault")
  QUARANTINE_BUCKET=$(terraform -chdir="$TF_DIR" output -raw quarantine_vault_bucket 2>/dev/null || echo "halt-lab-quarantine-vault")
  SQS_QUEUE_URL=$(terraform -chdir="$TF_DIR" output -raw sqs_event_queue_url 2>/dev/null || echo "${ENDPOINT}/000000000000/halt-lab-security-events")
  SQS_DLQ_URL=$(terraform -chdir="$TF_DIR" output -raw sqs_dlq_url 2>/dev/null || echo "${ENDPOINT}/000000000000/halt-lab-security-dlq")
else
  DATA_BUCKET="halt-lab-data-vault"
  QUARANTINE_BUCKET="halt-lab-quarantine-vault"
  SQS_QUEUE_URL="${ENDPOINT}/000000000000/halt-lab-security-events"
  SQS_DLQ_URL="${ENDPOINT}/000000000000/halt-lab-security-dlq"
fi

aws_cmd() {
  aws --endpoint-url="$ENDPOINT" "$@"
}

failed_tests=0

echo "Running security integration tests..."
echo "Target endpoint: $ENDPOINT"
echo "Data vault:      $DATA_BUCKET"
echo "Quarantine:      $QUARANTINE_BUCKET"
echo ""

# Test 1: Clean object tagging
echo -n "1. Ingest clean document and verify approval tag: "
temp_clean=$(mktemp)
echo "Sample legitimate log payload." > "$temp_clean"
aws_cmd s3 cp "$temp_clean" "s3://${DATA_BUCKET}/uploads/clean_doc.txt" > /dev/null
rm -f "$temp_clean"

approved=0
for _ in {1..15}; do
  tags=$(aws_cmd s3api get-object-tagging --bucket "$DATA_BUCKET" --key "uploads/clean_doc.txt" 2>/dev/null || echo "")
  if echo "$tags" | grep -q "APPROVED"; then
    approved=1
    break
  fi
  sleep 1
done

if [[ $approved -eq 1 ]]; then
  echo "OK"
else
  echo "FAILED (object was not tagged APPROVED)"
  failed_tests=$((failed_tests + 1))
fi

# Test 2: Sensitive payload quarantine
echo -n "2. Ingest exposed credentials and verify quarantine: "
temp_secret=$(mktemp)
cat << 'EOF' > "$temp_secret"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EOF
aws_cmd s3 cp "$temp_secret" "s3://${DATA_BUCKET}/uploads/secrets.env" > /dev/null
rm -f "$temp_secret"

quarantined=0
for _ in {1..15}; do
  main_exists=$(aws_cmd s3 ls "s3://${DATA_BUCKET}/uploads/secrets.env" 2>&1 || true)
  quarantine_ls=$(aws_cmd s3 ls "s3://${QUARANTINE_BUCKET}/quarantined/" --recursive 2>&1 || true)

  if [[ -z "$main_exists" ]] && echo "$quarantine_ls" | grep -q "secrets.env"; then
    quarantined=1
    break
  fi
  sleep 1
done

if [[ $quarantined -eq 1 ]]; then
  echo "OK"
else
  echo "FAILED (object was not moved to quarantine vault)"
  failed_tests=$((failed_tests + 1))
fi

# Test 3: S3 TLS enforcement policy
echo -n "3. Verify S3 SecureTransport policy: "
policy=$(aws_cmd s3api get-bucket-policy --bucket "$DATA_BUCKET" --output text 2>/dev/null || echo "")
if echo "$policy" | grep -q "aws:SecureTransport"; then
  echo "OK"
else
  echo "FAILED (bucket policy missing SecureTransport deny statement)"
  failed_tests=$((failed_tests + 1))
fi

# Test 4: SQS DLQ redrive
echo -n "4. Verify SQS DLQ redrive for malformed messages: "
aws_cmd sqs send-message --queue-url "$SQS_QUEUE_URL" --message-body "NON_JSON_CORRUPT_PAYLOAD" > /dev/null

dlq_received=0
for _ in {1..20}; do
  msg_count=$(aws_cmd sqs get-queue-attributes \
    --queue-url "$SQS_DLQ_URL" \
    --attribute-names ApproximateNumberOfMessages \
    --query "Attributes.ApproximateNumberOfMessages" \
    --output text 2>/dev/null || echo "0")

  if [[ "$msg_count" =~ ^[1-9][0-9]*$ ]]; then
    dlq_received=1
    break
  fi
  sleep 1
done

if [[ $dlq_received -eq 1 ]]; then
  echo "OK"
else
  echo "FAILED (malformed message was not routed to DLQ)"
  failed_tests=$((failed_tests + 1))
fi

echo ""
if [[ $failed_tests -eq 0 ]]; then
  echo "All integration tests passed."
  exit 0
else
  echo "$failed_tests test(s) failed."
  exit 1
fi
