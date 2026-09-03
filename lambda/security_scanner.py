import json
import logging
import os
import re
import urllib.parse
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

QUARANTINE_BUCKET = os.environ["QUARANTINE_BUCKET"]
ALERT_SNS_TOPIC_ARN = os.environ.get("ALERT_SNS_TOPIC_ARN")
AWS_ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL") or None
MAX_SCAN_BYTES = int(os.environ.get("MAX_SCAN_BYTES", "65536"))

s3_client = boto3.client("s3", endpoint_url=AWS_ENDPOINT_URL)
sns_client = boto3.client("sns", endpoint_url=AWS_ENDPOINT_URL)

BLOCKED_EXTENSIONS = {".pem", ".key", ".env", ".sh", ".exe", ".bin"}
SECRET_PATTERNS = [
    (re.compile(r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}"), "AWS Secret Access Key"),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY-----"), "Private Key"),
    (re.compile(r"(?i)(?:api_key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "Hardcoded Secret / Token"),
]


def scan_object(bucket: str, key: str) -> tuple[bool, str]:
    _, ext = os.path.splitext(key.lower())
    if ext in BLOCKED_EXTENSIONS:
        return False, f"Blocked file extension: {ext}"

    try:
        response = s3_client.get_object(Bucket=bucket, Key=key, Range=f"bytes=0-{MAX_SCAN_BYTES}")
        body = response["Body"]
        sample = body.read(MAX_SCAN_BYTES).decode("utf-8", errors="ignore")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code in ("NoSuchKey", "404"):
            logger.warning(f"Object s3://{bucket}/{key} no longer exists; skipping scan")
            return True, ""
        logger.error(f"S3 get_object failed for s3://{bucket}/{key}: {e}")
        raise

    for pattern, label in SECRET_PATTERNS:
        if pattern.search(sample):
            return False, f"Detected sensitive pattern: {label}"

    return True, ""


def quarantine(bucket: str, key: str, reason: str) -> None:
    timestamp = datetime.now(timezone.utc)
    target_key = f"quarantined/{timestamp.strftime('%Y-%m-%d')}/{key}"

    logger.warning(f"Quarantining s3://{bucket}/{key} -> s3://{QUARANTINE_BUCKET}/{target_key} (Reason: {reason})")

    s3_client.copy_object(
        Bucket=QUARANTINE_BUCKET,
        CopySource={"Bucket": bucket, "Key": key},
        Key=target_key,
        TaggingDirective="REPLACE",
        Tagging=urllib.parse.urlencode({"QuarantineReason": reason[:256], "Status": "QUARANTINED"}),
    )
    s3_client.delete_object(Bucket=bucket, Key=key)

    if ALERT_SNS_TOPIC_ARN:
        payload = {
            "event": "OBJECT_QUARANTINED",
            "timestamp": timestamp.isoformat(),
            "source_bucket": bucket,
            "key": key,
            "quarantine_location": f"s3://{QUARANTINE_BUCKET}/{target_key}",
            "reason": reason,
        }
        sns_client.publish(
            TopicArn=ALERT_SNS_TOPIC_ARN,
            Subject=f"Security Alert: Object Quarantined ({key})",
            Message=json.dumps(payload, indent=2),
        )


def approve(bucket: str, key: str) -> None:
    logger.info(f"Approving s3://{bucket}/{key}")
    s3_client.put_object_tagging(
        Bucket=bucket,
        Key=key,
        Tagging={
            "TagSet": [
                {"Key": "SecurityStatus", "Value": "APPROVED"},
                {"Key": "LastScanned", "Value": datetime.now(timezone.utc).isoformat()},
            ]
        },
    )


def process_record(body: str) -> None:
    data = json.loads(body)
    records = data.get("Records", [])

    for s3_event in records:
        s3_info = s3_event.get("s3", {})
        bucket = s3_info.get("bucket", {}).get("name")
        raw_key = s3_info.get("object", {}).get("key")

        if not bucket or not raw_key:
            continue

        key = urllib.parse.unquote_plus(raw_key)
        is_clean, reason = scan_object(bucket, key)

        if is_clean:
            approve(bucket, key)
        else:
            quarantine(bucket, key, reason)


def lambda_handler(event: dict, context: object) -> dict:
    records = event.get("Records", [])
    failures = []

    for record in records:
        msg_id = record.get("messageId")
        try:
            process_record(record.get("body", "{}"))
        except Exception as e:
            logger.exception(f"Failed processing message {msg_id}: {e}")
            if msg_id:
                failures.append({"itemIdentifier": msg_id})

    return {"batchItemFailures": failures}
