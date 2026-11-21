"""Unit tests for lambda/security_scanner.py.

Runnable with either `python3 -B -m unittest discover -s tests` (no third-party
dependencies) or `pytest tests/` (same TestCase classes, collected natively).
All AWS calls are exercised through a fake client, so no network is touched.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "lambda" / "security_scanner.py"
_spec = importlib.util.spec_from_file_location("security_scanner", MODULE_PATH)
scanner = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
# Python 3.13+ resolves `cls.__module__` through sys.modules while creating the
# @dataclass types, so the module must be registered before exec_module.
sys.modules[_spec.name] = scanner
_spec.loader.exec_module(scanner)

FAKE_AWS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
FAKE_GITHUB_TOKEN = "ghp_" + "0" * 36
FAKE_SLACK_TOKEN = "xoxb-" + "0" * 24
FAKE_STRIPE_KEY = "sk_live_" + "0" * 24
FAKE_GOOGLE_KEY = "AIza" + "0" * 35


def _not_found(code: str = "NoSuchVersion") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "missing"}}, "GetObject")


class FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self._data if size < 0 else self._data[:size]

    def close(self) -> None:
        self.closed = True


class FakePaginator:
    def __init__(self, client: "FakeS3") -> None:
        self._client = client

    def paginate(self, Bucket: str, Prefix: str = "") -> list[dict]:
        return self._client.list_object_versions(Bucket=Bucket, Prefix=Prefix)


class FakeS3:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str, str], bytes] = {}
        self.tags: dict[tuple[str, str, str], list[dict]] = {}
        self.deleted: list[tuple[str, str, str]] = []
        self.copied: list[dict] = []
        self.calls: list[tuple] = []

    # -- helpers -----------------------------------------------------------
    def put(self, bucket: str, key: str, version: str, body: bytes) -> None:
        self.objects[(bucket, key, version)] = body

    def _versions_for(self, bucket: str, prefix: str) -> list[tuple[str, str]]:
        return sorted(
            {(key, version) for (b, key, version) in self.objects if b == bucket and key.startswith(prefix)}
        )

    # -- boto3 surface -----------------------------------------------------
    def get_object(self, Bucket: str, Key: str, VersionId: str | None = None, **_: object) -> dict:
        self.calls.append(("get_object", Bucket, Key, VersionId))
        matches = [v for (k, v) in self._versions_for(Bucket, Key) if k == Key]
        if not matches:
            raise _not_found("NoSuchKey")
        version = VersionId or matches[-1]
        if (Bucket, Key, version) not in self.objects:
            raise _not_found("NoSuchVersion")
        body = self.objects[(Bucket, Key, version)]
        return {"Body": FakeBody(body), "ContentLength": len(body), "VersionId": version}

    def get_object_tagging(self, Bucket: str, Key: str, VersionId: str | None = None, **_: object) -> dict:
        return {"TagSet": list(self.tags.get((Bucket, Key, VersionId or "latest"), []))}

    def put_object_tagging(self, Bucket: str, Key: str, Tagging: dict, VersionId: str | None = None, **_: object) -> dict:
        self.tags[(Bucket, Key, VersionId or "latest")] = Tagging["TagSet"]
        return {}

    def copy_object(self, Bucket: str, CopySource: dict, Key: str, **extra: object) -> dict:
        self.copied.append({"Bucket": Bucket, "CopySource": CopySource, "Key": Key, **extra})
        source = (CopySource["Bucket"], CopySource["Key"], CopySource.get("VersionId"))
        self.objects[(Bucket, Key, "copy")] = self.objects.get(source, b"")
        return {}

    def delete_object(self, Bucket: str, Key: str, VersionId: str | None = None) -> dict:
        self.calls.append(("delete_object", Bucket, Key, VersionId))
        self.deleted.append((Bucket, Key, VersionId or ""))
        self.objects.pop((Bucket, Key, VersionId or ""), None)
        return {}

    def get_paginator(self, name: str) -> FakePaginator:
        assert name == "list_object_versions"
        return FakePaginator(self)

    def list_object_versions(self, Bucket: str, Prefix: str = "") -> list[dict]:
        return [{"Versions": [{"Key": k, "VersionId": v} for (k, v) in self._versions_for(Bucket, Prefix)],
                 "DeleteMarkers": []}]


class FakeSNS:
    def __init__(self, s3: FakeS3 | None = None) -> None:
        self.published: list[dict] = []
        self._s3 = s3

    def publish(self, TopicArn: str, Subject: str, Message: str) -> dict:
        if self._s3 is not None:
            self._s3.calls.append(("sns.publish", Subject))
        self.published.append({"TopicArn": TopicArn, "Subject": Subject, "Message": Message})
        return {"MessageId": "fake"}


class ScannerTestCase(unittest.TestCase):
    BUCKET = "data-vault"

    def setUp(self) -> None:
        self.s3 = FakeS3()
        self.sns = FakeSNS(self.s3)
        self._env = mock.patch.dict(
            os.environ,
            {
                "QUARANTINE_BUCKET": "quarantine-vault",
                "ALERT_SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:security-alerts",
                "AWS_ENDPOINT_URL": "http://localhost:4567",
                "MAX_SCAN_BYTES": str(scanner.DEFAULT_MAX_SCAN_BYTES),
            },
            clear=False,
        )
        self._env.start()
        os.environ.pop("FAIL_CLOSED_OVERSIZE", None)
        self._client_patch = mock.patch.object(
            scanner, "_client", side_effect=lambda name: self.s3 if name == "s3" else self.sns
        )
        self._client_patch.start()

    def tearDown(self) -> None:
        self._client_patch.stop()
        self._env.stop()

    # -- detection ---------------------------------------------------------
    def test_detects_each_leak_family(self) -> None:
        cases = {
            "quoted aws secret": f'AWS_SECRET_ACCESS_KEY="{FAKE_AWS_SECRET}"',
            "aws key id": f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY_ID}",
            "yaml password": "password: hunter2-prod-2026",
            "github token": f"token={FAKE_GITHUB_TOKEN}",
            "slack token": f"SLACK={FAKE_SLACK_TOKEN}",
            "stripe key": f"key={FAKE_STRIPE_KEY}",
            "google key": f"key={FAKE_GOOGLE_KEY}",
            "private key header": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "connection uri": "postgres://admin:s3cr3t-pass@db.internal:5432/app",
        }
        for name, payload in cases.items():
            with self.subTest(family=name):
                self.assertIsNotNone(scanner.find_secret(payload), name)

    def test_placeholder_values_are_not_secrets(self) -> None:
        for payload in ("password: ${DB_PASSWORD}", "token=<your-token-here>", "password: changeme123"):
            with self.subTest(payload=payload):
                self.assertIsNone(scanner.find_secret(payload))

    def test_utf16_payload_is_decoded_before_matching(self) -> None:
        raw = f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY_ID}".encode("utf-16")
        self.s3.put(self.BUCKET, "uploads/u16.txt", "v1", raw)
        outcome = scanner.scan_object(self.BUCKET, "uploads/u16.txt", "v1")
        self.assertEqual(outcome.status, "flagged")

    def test_bomless_utf16_payload_is_decoded_before_matching(self) -> None:
        # ASCII UTF-16LE is valid UTF-8 (all those NUL bytes), so a UTF-8-only
        # decoder would read it as noise and approve the file.
        for encoding in ("utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding):
                raw = f"AWS_ACCESS_KEY_ID={FAKE_AWS_KEY_ID}".encode(encoding)
                self.s3.put(self.BUCKET, "uploads/u16nobom.txt", "v1", raw)
                outcome = scanner.scan_object(self.BUCKET, "uploads/u16nobom.txt", "v1")
                self.assertEqual(outcome.status, "flagged")

    def test_binary_container_fails_closed(self) -> None:
        self.s3.put(self.BUCKET, "uploads/archive.zip", "v1", b"PK\x03\x04")
        outcome = scanner.scan_object(self.BUCKET, "uploads/archive.zip", "v1")
        self.assertEqual(outcome.status, "incomplete")

    def test_blocked_filename_without_extension(self) -> None:
        self.s3.put(self.BUCKET, "uploads/id_rsa", "v1", b"anything")
        outcome = scanner.scan_object(self.BUCKET, "uploads/id_rsa", "v1")
        self.assertEqual(outcome.status, "flagged")

    def test_shell_script_is_inspected_not_blanket_quarantined(self) -> None:
        self.s3.put(self.BUCKET, "uploads/hello.sh", "v1", b"#!/bin/sh\necho hello\n")
        outcome = scanner.scan_object(self.BUCKET, "uploads/hello.sh", "v1")
        self.assertEqual(outcome.status, "clean")

    # -- oversize ----------------------------------------------------------
    def test_oversize_is_never_approved(self) -> None:
        os.environ["MAX_SCAN_BYTES"] = "10"
        self.s3.put(self.BUCKET, "uploads/big.txt", "v1", b"x" * 50)
        self.assertEqual(scanner.scan_object(self.BUCKET, "uploads/big.txt", "v1").status, "incomplete")

    def test_oversize_can_fail_closed_to_quarantine(self) -> None:
        os.environ["MAX_SCAN_BYTES"] = "10"
        os.environ["FAIL_CLOSED_OVERSIZE"] = "true"
        self.s3.put(self.BUCKET, "uploads/big.txt", "v1", b"x" * 50)
        self.assertEqual(scanner.scan_object(self.BUCKET, "uploads/big.txt", "v1").status, "flagged")

    # -- version pinning ---------------------------------------------------
    def test_scan_reads_the_version_named_in_the_event(self) -> None:
        self.s3.put(self.BUCKET, "uploads/a.txt", "v1", b"clean")
        self.s3.put(self.BUCKET, "uploads/a.txt", "v2", b"clean too")
        scanner.scan_object(self.BUCKET, "uploads/a.txt", "v1")
        self.assertIn(("get_object", self.BUCKET, "uploads/a.txt", "v1"), self.s3.calls)

    def test_missing_version_id_is_a_batch_failure(self) -> None:
        event = {"Records": [{"messageId": "m1", "body": json.dumps({"Records": [
            {"s3": {"bucket": {"name": self.BUCKET}, "object": {"key": "uploads/x.txt"}}}]})}]}
        self.assertEqual(scanner.lambda_handler(event, None), {"batchItemFailures": [{"itemIdentifier": "m1"}]})

    def test_malformed_body_is_a_batch_failure(self) -> None:
        event = {"Records": [{"messageId": "m2", "body": "not json"}]}
        self.assertEqual(scanner.lambda_handler(event, None), {"batchItemFailures": [{"itemIdentifier": "m2"}]})

    def test_s3_notification_test_event_is_acknowledged(self) -> None:
        # S3 publishes one of these when the notification configuration is
        # created; failing it would park a permanently unretryable message in
        # the DLQ and page the operator on a healthy stack.
        body = json.dumps({"Service": "Amazon S3", "Event": "s3:TestEvent", "Bucket": self.BUCKET})
        event = {"Records": [{"messageId": "m4", "body": body}]}
        self.assertEqual(scanner.lambda_handler(event, None), {"batchItemFailures": []})

    def test_missing_object_is_skipped_not_failed(self) -> None:
        event = {"Records": [{"messageId": "m3", "body": json.dumps({"Records": [
            {"s3": {"bucket": {"name": self.BUCKET}, "object": {"key": "uploads/gone.txt", "versionId": "v9"}}}]})}]}
        self.assertEqual(scanner.lambda_handler(event, None), {"batchItemFailures": []})

    # -- tagging -----------------------------------------------------------
    def test_approve_preserves_existing_tags(self) -> None:
        self.s3.put(self.BUCKET, "uploads/doc.txt", "v1", b"nothing to see")
        self.s3.tags[(self.BUCKET, "uploads/doc.txt", "v1")] = [
            {"Key": "Owner", "Value": "alice"},
            {"Key": "Team", "Value": "platform"},
        ]
        scanner.approve(self.BUCKET, "uploads/doc.txt", "v1")
        written = {tag["Key"]: tag["Value"] for tag in self.s3.tags[(self.BUCKET, "uploads/doc.txt", "v1")]}
        self.assertEqual(written["SecurityStatus"], "APPROVED")
        self.assertEqual(written["Owner"], "alice")
        self.assertEqual(written["Team"], "platform")

    def test_tag_merge_respects_the_ten_tag_limit(self) -> None:
        self.s3.put(self.BUCKET, "uploads/doc.txt", "v1", b"clean")
        self.s3.tags[(self.BUCKET, "uploads/doc.txt", "v1")] = [
            {"Key": f"k{i}", "Value": "v"} for i in range(12)
        ]
        scanner.approve(self.BUCKET, "uploads/doc.txt", "v1")
        self.assertLessEqual(len(self.s3.tags[(self.BUCKET, "uploads/doc.txt", "v1")]), 10)

    # -- quarantine --------------------------------------------------------
    def test_quarantine_purges_every_version(self) -> None:
        for version in ("v1", "v2", "v3"):
            self.s3.put(self.BUCKET, "uploads/secret.env", version, b"x")
        scanner.quarantine(self.BUCKET, "uploads/secret.env", "v2", "Detected sensitive pattern")
        self.assertEqual([k for k in self.s3.objects if k[0] == self.BUCKET], [])
        copies = [c for c in self.s3.copied if c["Bucket"] == "quarantine-vault"]
        self.assertEqual(copies[0]["CopySource"]["VersionId"], "v2")
        self.assertIn("/v2", copies[0]["Key"])

    def test_quarantine_path_is_unique_per_version(self) -> None:
        self.s3.put(self.BUCKET, "uploads/dup.env", "v1", b"x")
        self.s3.put(self.BUCKET, "uploads/dup.env", "v2", b"y")
        scanner.quarantine(self.BUCKET, "uploads/dup.env", "v1", "r")
        scanner.quarantine(self.BUCKET, "uploads/dup.env", "v2", "r")
        keys = [c["Key"] for c in self.s3.copied if c["Key"].startswith("quarantined/")]
        self.assertEqual(len(set(keys)), 2, keys)

    def test_alert_is_published_before_the_purge(self) -> None:
        self.s3.put(self.BUCKET, "uploads/secret.env", "v1", b"x")
        scanner.quarantine(self.BUCKET, "uploads/secret.env", "v1", "r")
        publish_index = self.s3.calls.index(("sns.publish", self.sns.published[0]["Subject"]))
        self.assertTrue(all(not str(call).startswith("('delete") for call in self.s3.calls[:publish_index]),
                        "no delete may happen before the alert is published")

    def test_publish_failure_leaves_the_source_intact(self) -> None:
        self.s3.put(self.BUCKET, "uploads/secret.env", "v1", b"x")
        self.sns.publish = mock.Mock(side_effect=RuntimeError("sns down"))
        with self.assertRaises(RuntimeError):
            scanner.quarantine(self.BUCKET, "uploads/secret.env", "v1", "r")
        self.assertIn((self.BUCKET, "uploads/secret.env", "v1"), self.s3.objects)

    def test_subject_fits_sns_limits(self) -> None:
        subject = scanner.build_subject("uploads/" + "k" * 200 + "\u00e9\n.txt")
        self.assertLessEqual(len(subject), 100)
        self.assertTrue(all(32 <= ord(ch) <= 126 for ch in subject), subject)

    def test_alert_body_carries_the_forensic_fields(self) -> None:
        self.s3.put(self.BUCKET, "uploads/secret.env", "v7", b"x")
        scanner.quarantine(self.BUCKET, "uploads/secret.env", "v7", "Detected sensitive pattern: AWS Access Key ID")
        payload = json.loads(self.sns.published[0]["Message"])
        self.assertEqual(payload["version_id"], "v7")
        self.assertEqual(payload["source_bucket"], self.BUCKET)
        self.assertIn("AWS Access Key ID", payload["reason"])
        self.assertTrue(payload["quarantine_location"].startswith("s3://quarantine-vault/quarantined/"))


if __name__ == "__main__":
    unittest.main()
