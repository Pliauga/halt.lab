resource "random_id" "bucket_suffix" {
  byte_length = 4
}

locals {
  bucket_suffix           = var.bucket_suffix != "" ? var.bucket_suffix : random_id.bucket_suffix.hex
  data_vault_bucket       = "${var.project_prefix}-data-vault-${local.bucket_suffix}"
  quarantine_vault_bucket = "${var.project_prefix}-quarantine-vault-${local.bucket_suffix}"
  force_destroy           = var.is_local ? true : var.force_destroy
}

resource "aws_s3_bucket" "data_vault" {
  bucket        = local.data_vault_bucket
  force_destroy = local.force_destroy
}

resource "aws_s3_bucket_versioning" "data_vault_versioning" {
  bucket = aws_s3_bucket.data_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_vault_encryption" {
  bucket = aws_s3_bucket.data_vault.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.security_cmk.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "data_vault_pab" {
  bucket = aws_s3_bucket.data_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "data_vault_policy" {
  bucket = aws_s3_bucket.data_vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.data_vault.arn,
          "${aws_s3_bucket.data_vault.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_logging" "data_vault_logging" {
  count = var.enable_access_logging && var.access_log_bucket != "" ? 1 : 0

  bucket        = aws_s3_bucket.data_vault.id
  target_bucket = var.access_log_bucket
  target_prefix = "data-vault/"
}

# --- Quarantine vault -------------------------------------------------------
# Isolation is defence in depth: its own CMK, versioning, TLS-only policy and
# (optionally) Object Lock. force_destroy stays false outside local runs.

resource "aws_s3_bucket" "quarantine_vault" {
  bucket              = local.quarantine_vault_bucket
  force_destroy       = local.force_destroy
  object_lock_enabled = var.object_lock_enabled
}

resource "aws_s3_bucket_versioning" "quarantine_versioning" {
  bucket = aws_s3_bucket.quarantine_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "quarantine_lock" {
  count = var.object_lock_enabled ? 1 : 0

  bucket = aws_s3_bucket.quarantine_vault.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.quarantine_versioning]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine_encryption" {
  bucket = aws_s3_bucket.quarantine_vault.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.quarantine_cmk.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "quarantine_pab" {
  bucket = aws_s3_bucket.quarantine_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "quarantine_policy" {
  bucket = aws_s3_bucket.quarantine_vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.quarantine_vault.arn,
          "${aws_s3_bucket.quarantine_vault.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# --- Event wiring -----------------------------------------------------------
# Every object in the vault is scanned: the bucket is the security boundary, so
# no prefix filter is applied here.

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.data_vault.id

  queue {
    queue_arn = aws_sqs_queue.security_event_queue.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.security_queue_policy]
}
