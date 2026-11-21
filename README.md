# halt.lab

An automated security pipeline that watches an S3 bucket, scans every newly uploaded object for exposed secrets with a Lambda worker, and quarantines flagged content into an isolated, versioned vault.

## Why we built it

Accidentally dropping `.env` files, raw AWS keys, or private keys into shared cloud storage happens all the time. We needed a lightweight way to catch leaked credentials at the storage boundary without paying for expensive third-party scanning tools or running complex daemon agents.

## How it works

```
S3 event (any prefix)
   └─▶ SQS scanning queue ──▶ Lambda scanner
                                 ├─ clean      ▶ tag SecurityStatus=APPROVED (existing tags kept)
                                 ├─ secret     ▶ copy exact version to quarantine ▶ alert ▶ purge all versions
                                 └─ unreadable ▶ tag SecurityStatus=SCAN_INCOMPLETE (never APPROVED)
```

* **Every prefix is scanned.** The bucket is the security boundary, so no `uploads/`-only filter exists.
* **Version-pinned scanning.** The scanner reads the exact `versionId` carried by the S3 event, so a quick overwrite cannot hide a secret that was uploaded a moment earlier.
* **Quarantine means gone.** After copying the flagged version to the quarantine vault, every version and delete marker of that key is deleted from the data vault, so `GetObjectVersion` cannot retrieve the secret afterwards.
* **Alert before delete.** The SNS alert is published before the source is purged; if publishing fails the message is retried and the secret stays contained in the vault it was found in.
* **Fail closed.** Oversized or binary objects are never silently approved: they are tagged `SCAN_INCOMPLETE`, or quarantined when `fail_closed_oversize = true`.

## How to get it running

### Prerequisites

Docker, Terraform (>= 1.5.0), the AWS CLI, `jq`, and Python 3 (for the unit tests).

### 1. Start the local cloud emulator (Floci)

```bash
./scripts/setup_floci.sh
```

The compose file pins the emulator to an image digest. It mounts the Docker socket because Floci runs Lambda functions as sibling containers.

### 2. Provision the infrastructure

```bash
./scripts/deploy.sh
```

Bucket names carry a random suffix so they never collide with another account or another run:

```bash
terraform -chdir=terraform output -raw data_vault_bucket
```

### 3. Run the automated checks

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests   # unit tests
./scripts/run_security_tests.sh                                      # end-to-end on the emulator
```

The integration script verifies tag preservation, version purging, the overwrite race, non-`uploads/` prefixes, long object keys, six leak probes (quoted/unquoted secrets, GitHub PAT, UTF-16, oversize, `.env` control), TLS-only policies, and dead-letter routing. It is destructive: run it only against a disposable stack.

*(Cleanup: `terraform -chdir=terraform destroy -auto-approve && docker compose down -v`)*

## How to use it

```bash
DATA_VAULT=$(terraform -chdir=terraform output -raw data_vault_bucket)
QUARANTINE=$(terraform -chdir=terraform output -raw quarantine_vault_bucket)

aws --endpoint-url=http://localhost:4566 s3 cp ./my-config.env "s3://${DATA_VAULT}/uploads/"

# What did the scanner decide?
aws --endpoint-url=http://localhost:4566 s3api get-object-tagging \
  --bucket "$DATA_VAULT" --key uploads/my-config.env

# What was quarantined?
aws --endpoint-url=http://localhost:4566 s3 ls "s3://${QUARANTINE}/quarantined/" --recursive
```

## Going to production

```bash
cd terraform
terraform apply \
  -var="is_local=false" \
  -var="aws_region=eu-west-2" \
  -var="alert_email=security@example.com" \
  -var="break_glass_principal_arn=arn:aws:iam::123456789012:role/BreakGlass"
```

Before the first live apply:

* **Remote state.** `versions.tf` contains a commented `backend "s3"` block using `use_lockfile = true`; fill in your state bucket and uncomment it. Local state is fine for the emulator only.
* **Alerting.** With `alert_email` set, SNS creates an email subscription that must be confirmed once. Without it, alarms and quarantine alerts have no human recipient.
* **Alarms.** `enable_alarms = true` (default) raises CloudWatch alarms for a non-empty DLQ, scanner errors, and scanner throttles; they publish to the same SNS topic.
* **Immutability.** Set `object_lock_enabled = true` on a fresh quarantine vault to make evidence tamper-evident for `object_lock_retention_days`.
* **Retention.** `log_retention_days` defaults to 90; `kms_deletion_window_days` defaults to 30.
* **Runtime.** The Lambda runs `python3.13` on `arm64`; both are variables if the account or region lags behind.

## Where things live

```
.
├── docker-compose.yml        # Local Floci emulator (digest-pinned)
├── lambda/
│   └── security_scanner.py   # Version-pinned scanner, quarantine, alerting
├── tests/
│   └── test_security_scanner.py  # Unit tests (stdlib unittest, no AWS calls)
├── terraform/
│   ├── s3.tf                 # Data vault, quarantine vault, event wiring
│   ├── sqs_sns.tf            # Queue + DLQ, alert topic, alarms, CloudTrail
│   ├── lambda.tf             # Packaging, log group, SQS trigger
│   ├── iam.tf                # Least-privilege execution role
│   ├── kms.tf                # Data and quarantine CMKs
│   └── versions.tf           # Providers, endpoints, optional remote backend
└── scripts/
    ├── setup_floci.sh        # Start the emulator and wait (bounded) for health
    ├── deploy.sh             # terraform init + apply
    └── run_security_tests.sh # End-to-end verification suite
```
