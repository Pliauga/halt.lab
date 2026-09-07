# halt.lab

An automated security pipeline that monitors an S3 bucket, scans newly uploaded files for exposed secrets or risky scripts with a Lambda worker, and moves flagged files into an isolated quarantine bucket.

## Why we built it

Accidentally dropping `.env` files, raw AWS keys, or private SSH certificates into shared cloud storage happens all the time. We needed a lightweight way to catch leaked credentials and unauthorised files immediately at the storage boundary without paying for expensive third-party scanning tools or running complex daemon agents.

## How to get it running

### Prerequisites
Make sure you have Docker, Terraform (>= 1.5.0), and the AWS CLI installed.

### 1. Start the local cloud emulator (Floci)
```bash
./scripts/setup_floci.sh
```

### 2. Provision the infrastructure
```bash
./scripts/deploy.sh
```

### 3. Run the integration test suite
```bash
./scripts/run_security_tests.sh
```

*(To clean up everything when you are done, run `terraform -chdir=terraform destroy -auto-approve && docker compose down -v`)*

## How to use it

Upload a file to the primary data vault. Clean files receive an approval tag, whilst files with secrets get yanked into quarantine within seconds:

```bash
# Upload a test file to the data vault
aws --endpoint-url=http://localhost:4566 s3 cp ./my-config.env s3://halt-lab-data-vault/uploads/

# Check the quarantine bucket if the file contained leaked secrets
aws --endpoint-url=http://localhost:4566 s3 ls s3://halt-lab-quarantine-vault/quarantined/ --recursive
```

To deploy this directly to your live AWS account instead of local emulation, run:
```bash
cd terraform && terraform apply -var="is_local=false" -var="aws_region=eu-west-2"
```

## Where things live

```
.
├── docker-compose.yml       # Local Floci emulator container config
├── lambda/
│   └── security_scanner.py  # Python scanner checking extensions & secret patterns
├── terraform/
│   ├── s3.tf                # Primary data vault & isolated quarantine buckets
│   ├── sqs_sns.tf           # S3 event queue, dead-letter queue, and alert topics
│   ├── lambda.tf            # Scanner packaging & SQS event trigger
│   ├── iam.tf               # Scoped execution role & permissions
│   ├── kms.tf               # Customer-managed encryption keys
│   └── versions.tf          # AWS provider & local endpoint mappings
└── scripts/
    ├── setup_floci.sh       # Starts Floci container and checks gateway health
    ├── deploy.sh            # Inits and applies Terraform config
    └── run_security_tests.sh# Automated positive/negative integration tests
```

