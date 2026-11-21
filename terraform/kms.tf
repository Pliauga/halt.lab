data "aws_caller_identity" "current" {}

locals {
  account_root = var.is_local ? "*" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"

  deletion_protection = var.break_glass_principal_arn == "" ? [] : [
    {
      Sid       = "DenyKeyDeletionOutsideBreakGlass"
      Effect    = "Deny"
      Principal = "*"
      Action = [
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey"
      ]
      Resource = "*"
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = var.break_glass_principal_arn
        }
      }
    }
  ]
}

resource "aws_kms_key" "security_cmk" {
  description             = "KMS CMK for halt.lab data protection and queue encryption"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "AllowS3AndSQSServiceAccess"
        Effect = "Allow"
        Principal = {
          Service = [
            "s3.amazonaws.com",
            "sqs.amazonaws.com",
            "events.amazonaws.com",
            "sns.amazonaws.com"
          ]
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ], local.deletion_protection)
  })

  tags = {
    Name = "${var.project_prefix}-cmk"
  }
}

resource "aws_kms_alias" "security_cmk_alias" {
  name          = "alias/${var.project_prefix}-key"
  target_key_id = aws_kms_key.security_cmk.key_id
}

resource "aws_kms_key" "quarantine_cmk" {
  description             = "Dedicated KMS CMK for the halt.lab quarantine vault"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3ServiceAccess"
        Effect    = "Allow"
        Principal = { Service = ["s3.amazonaws.com"] }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ], local.deletion_protection)
  })

  tags = {
    Name = "${var.project_prefix}-quarantine-cmk"
  }
}

resource "aws_kms_alias" "quarantine_cmk_alias" {
  name          = "alias/${var.project_prefix}-quarantine-key"
  target_key_id = aws_kms_key.quarantine_cmk.key_id
}
