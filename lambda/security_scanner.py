"""halt.lab security scanner.

Consumes S3 ObjectCreated events from the scan queue, inspects the exact object
version named in the event, and then either approves it or quarantines it.

Quarantine is a three-step sequence: copy the flagged version into the
quarantine bucket, publish the alert, and only then purge every version of that
key from the data vault. Purging last means a transient alerting failure can be
retried without stranding evidence.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import logging
import os
import re
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DEFAULT_MAX_SCAN_BYTES = 1048576
S3_TAG_LIMIT = 10
STATUS_APPROVED = "APPROVED"
STATUS_QUARANTINED = "QUARANTINED"
STATUS_INCOMPLETE = "SCAN_INCOMPLETE"

# Secret-bearing containers and names: quarantined on sight, never scanned.
BLOCKED_EXTENSIONS = frozenset(
    {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".ovpn", ".tfvars", ".exe", ".bin"}
)
BLOCKED_FILENAMES = frozenset(
    {".env", ".netrc", ".pypirc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd"}
)

# Binary containers we cannot inspect byte-wise without library support.
BINARY_EXTENSIONS = frozenset(
    {
        ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
        ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
        ".jar", ".war", ".class", ".so", ".dylib", ".dll", ".exe",
    }
)

_PLACEHOLDER_VALUE = re.compile(
    r"""^(?:
        x+ | \*+ | \.+ | -+ | _+
      | change[-_]?me\w* | example(?:[-_].*)? | sample(?:[-_].*)?
      | placeholder | dummy | redacted | none | null | nil | true | false
      | test(?:ing)? | dev | local
      | \$\{[^}]*\} | \{\{.*\}\} | <[^>]*> | %\([^)]*\)s | your[-_].*
    )$""",
    re.VERBOSE | re.IGNORECASE,
)

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\baws_?secret_?access_?key\b\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}"), "AWS Secret Access Key"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS Access Key ID"),
    (re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----"), "Private Key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub Personal Access Token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "GitHub Fine-Grained Token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack Token"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), "Stripe Live Key"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Google API Key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "JSON Web Token"),
    (re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^:\s/@]+:[^@\s/]+@[^\s]+"), "Credentialed Connection URI"),
]

_GENERIC_SECRET = re.compile(
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|apikey|token|private[_-]?key|access[_-]?key)\b"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"'`]{8,})[\"']?"
)


@dataclass(frozen=True)
class ScanOutcome:
    """Verdict for one object version."""

    status: str  # "clean" | "flagged" | "incomplete" | "gone"
    reason: str = ""


_clients: dict[str, object] = {}


def _client(name: str):
    if name not in _clients:
        _clients[name] = boto3.client(name, endpoint_url=os.environ.get("AWS_ENDPOINT_URL") or None)
    return _clients[name]


def _quarantine_bucket() -> str:
    return os.environ["QUARANTINE_BUCKET"]


def _alert_topic_arn() -> str:
    arn = os.environ.get("ALERT_SNS_TOPIC_ARN")
    if not arn:
        raise RuntimeError("ALERT_SNS_TOPIC_ARN is not configured; refusing to quarantine without alerting")
    return arn


def _max_scan_bytes() -> int:
    return int(os.environ.get("MAX_SCAN_BYTES", str(DEFAULT_MAX_SCAN_BYTES)))


def _fail_closed_oversize() -> bool:
    return os.environ.get("FAIL_CLOSED_OVERSIZE", "false").strip().lower() in ("1", "true", "yes")


def _version_kwargs(version_id: str | None) -> dict[str, str]:
    # "null" is what S3 reports for an unversioned bucket; it is not a real id.
    if version_id and version_id != "null":
        return {"VersionId": version_id}
    return {}


def decode_text(raw: bytes) -> str:
    """Best-effort decode that never throws and keeps UTF-16 payloads readable."""
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(codecs.BOM_UTF8):
        return raw.decode("utf-8-sig", errors="replace")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None or "\x00" in text:
        # BOM-less UTF-16 decodes as UTF-8 when the payload is ASCII, leaving
        # interleaved NULs, so the UTF-16 variants are tried before giving up.
        # ASCII text in LE puts NULs on odd offsets and BE on even ones.
        order = ("utf-16-le", "utf-16-be")
        if raw[0::2].count(0) > raw[1::2].count(0):
            order = ("utf-16-be", "utf-16-le")
        for encoding in order:
            try:
                candidate = raw.decode(encoding)
            except UnicodeDecodeError:
                continue
            if "\x00" not in candidate:
                return candidate
        if text is None:
            return raw.decode("latin-1", errors="replace")
    return text


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_VALUE.match(value.strip("'\"` ")))


def find_secret(text: str) -> str | None:
    """Return the label of the first matching secret family, or None."""
    for pattern, label in _SECRET_PATTERNS:
        if pattern.search(text):
            return label
    for match in _GENERIC_SECRET.finditer(text):
        if not _is_placeholder(match.group("value")):
            return "Hardcoded Secret / Token"
    return None


def scan_object(bucket: str, key: str, version_id: str | None = None) -> ScanOutcome:
    basename = key.rsplit("/", 1)[-1].lower()
    extension = os.path.splitext(basename)[1]

    if extension in BLOCKED_EXTENSIONS or basename in BLOCKED_FILENAMES:
        return ScanOutcome("flagged", f"Secret-bearing file type: {extension or basename}")
    if extension in BINARY_EXTENSIONS:
        return ScanOutcome("incomplete", f"Binary container {extension} cannot be inspected")

    kwargs = _version_kwargs(version_id)
    try:
        response = _client("s3").get_object(Bucket=bucket, Key=key, **kwargs)
        length = int(response["ContentLength"])
        if length > _max_scan_bytes():
            response["Body"].close()
            reason = f"Object size {length} exceeds scan cap {_max_scan_bytes()}"
            return ScanOutcome("flagged" if _fail_closed_oversize() else "incomplete", reason)
        sample = response["Body"].read(_max_scan_bytes())
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("NoSuchKey", "NoSuchVersion", "404", "NotFound"):
            logger.info("Object s3://%s/%s (version %s) no longer exists; nothing to scan", bucket, key, version_id)
            return ScanOutcome("gone", "Object version no longer exists")
        raise

    label = find_secret(decode_text(sample))
    if label:
        return ScanOutcome("flagged", f"Detected sensitive pattern: {label}")
    return ScanOutcome("clean", "")


def _status_tags(bucket: str, key: str, version_id: str | None, status: str, reason: str = "") -> list[dict[str, str]]:
    """Merge the security tags into the existing tag set, keeping user tags."""
    kwargs = _version_kwargs(version_id)
    try:
        existing = _client("s3").get_object_tagging(Bucket=bucket, Key=key, **kwargs).get("TagSet", [])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("NoSuchKey", "NoSuchVersion", "404", "NotFound"):
            raise
        logger.warning("Could not read existing tags for s3://%s/%s: %s", bucket, key, exc)
        existing = []

    tags = [
        {"Key": "SecurityStatus", "Value": status},
        {"Key": "LastScanned", "Value": datetime.now(timezone.utc).isoformat()},
    ]
    if reason:
        tags.append({"Key": "SecurityReason", "Value": reason[:256]})
    reserved = {tag["Key"] for tag in tags}
    for tag in existing:
        if len(tags) >= S3_TAG_LIMIT:
            break
        if tag.get("Key") in reserved:
            continue
        tags.append({"Key": tag["Key"], "Value": tag["Value"]})
    return tags


def _write_status(bucket: str, key: str, version_id: str | None, status: str, reason: str = "") -> None:
    try:
        _client("s3").put_object_tagging(
            Bucket=bucket,
            Key=key,
            **(_version_kwargs(version_id)),
            Tagging={"TagSet": _status_tags(bucket, key, version_id, status, reason)},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("NoSuchKey", "NoSuchVersion", "404", "NotFound"):
            # The version vanished while it was being handled (typically the
            # overwrite race). Retrying cannot succeed, so this is not a failure.
            logger.info("Object s3://%s/%s (version %s) vanished before tagging", bucket, key, version_id)
            return
        raise


def approve(bucket: str, key: str, version_id: str | None = None) -> None:
    logger.info("Approving s3://%s/%s (version %s)", bucket, key, version_id)
    _write_status(bucket, key, version_id, STATUS_APPROVED)


def mark_incomplete(bucket: str, key: str, version_id: str | None, reason: str) -> None:
    logger.warning("Flagging s3://%s/%s as %s: %s", bucket, key, STATUS_INCOMPLETE, reason)
    _write_status(bucket, key, version_id, STATUS_INCOMPLETE, reason)


def build_subject(key: str) -> str:
    """SNS subjects are limited to 100 printable ASCII characters."""
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    tail = re.sub(r"[^ -~]", "_", key.rsplit("/", 1)[-1])[-55:]
    subject = f"Security Alert: Quarantined ({digest}) {tail}"
    return subject[:100]


def purge_versions(bucket: str, key: str) -> int:
    """Delete every version and delete marker for one key; return how many were removed."""
    client = _client("s3")
    version_ids: list[str] = []
    for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key):
        for entry in page.get("Versions", []) + page.get("DeleteMarkers", []):
            if entry.get("Key") == key and entry.get("VersionId"):
                version_ids.append(entry["VersionId"])

    for version_id in version_ids:
        client.delete_object(Bucket=bucket, Key=key, VersionId=version_id)

    remaining = 0
    for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key):
        for entry in page.get("Versions", []) + page.get("DeleteMarkers", []):
            if entry.get("Key") == key:
                remaining += 1
    if remaining:
        raise RuntimeError(f"{remaining} version(s) of s3://{bucket}/{key} survived the purge")
    return len(version_ids)


def quarantine(bucket: str, key: str, version_id: str | None, reason: str) -> None:
    timestamp = datetime.now(timezone.utc)
    version_component = version_id if version_id and version_id != "null" else uuid.uuid4().hex
    target_key = f"quarantined/{timestamp:%Y-%m-%d}/{key}/{version_component}"

    logger.warning("Quarantining s3://%s/%s (version %s) -> s3://%s/%s (%s)",
                   bucket, key, version_id, _quarantine_bucket(), target_key, reason)

    copy_source = {"Bucket": bucket, "Key": key, **_version_kwargs(version_id)}
    _client("s3").copy_object(
        Bucket=_quarantine_bucket(),
        CopySource=copy_source,
        Key=target_key,
        TaggingDirective="REPLACE",
        Tagging=urllib.parse.urlencode(
            {"QuarantineReason": reason[:200], "Status": STATUS_QUARANTINED, "SourceVersion": str(version_component)}
        ),
    )

    payload = {
        "event": "OBJECT_QUARANTINED",
        "timestamp": timestamp.isoformat(),
        "source_bucket": bucket,
        "key": key,
        "version_id": version_id,
        "quarantine_location": f"s3://{_quarantine_bucket()}/{target_key}",
        "reason": reason,
    }
    # Publish before deleting: a transient SNS failure must leave the source intact.
    _client("sns").publish(
        TopicArn=_alert_topic_arn(),
        Subject=build_subject(key),
        Message=json.dumps(payload, indent=2),
    )

    purged = purge_versions(bucket, key)
    logger.warning("Purged %d version(s) of s3://%s/%s from the data vault", purged, bucket, key)


def process_record(body: str) -> int:
    """Handle one SQS message (an S3 event envelope). Returns the number of objects handled."""
    data = json.loads(body)
    if data.get("Event") == "s3:TestEvent":
        # S3 sends one of these when a notification configuration is created.
        # It carries no object, so acknowledging it is correct; treating it as a
        # failure would fill the DLQ with a message no retry can ever fix.
        logger.info("Ignoring S3 notification test event for bucket %s", data.get("Bucket"))
        return 0
    records = data.get("Records")
    if not isinstance(records, list) or not records:
        raise ValueError("event carries no Records")

    handled = 0
    for s3_event in records:
        s3_info = s3_event.get("s3") or {}
        bucket = (s3_info.get("bucket") or {}).get("name")
        raw_key = (s3_info.get("object") or {}).get("key")
        version_id = (s3_info.get("object") or {}).get("versionId")
        if not bucket or not raw_key:
            raise ValueError("S3 record is missing bucket name or object key")
        if not version_id:
            raise ValueError("S3 record is missing s3.object.versionId; cannot pin the scan")

        key = urllib.parse.unquote_plus(raw_key)
        outcome = scan_object(bucket, key, version_id)

        if outcome.status == "clean":
            approve(bucket, key, version_id)
        elif outcome.status == "flagged":
            quarantine(bucket, key, version_id, outcome.reason)
        elif outcome.status == "incomplete":
            mark_incomplete(bucket, key, version_id, outcome.reason)
        else:
            continue
        handled += 1
    return handled


def lambda_handler(event: dict, context: object) -> dict:
    failures = []
    for record in event.get("Records", []):
        message_id = record.get("messageId")
        try:
            process_record(record.get("body", "{}"))
        except Exception as exc:  # every failure must surface as a batch item failure, never a silent pass
            logger.exception("Failed processing message %s: %s", message_id, exc)
            if message_id:
                failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures}
