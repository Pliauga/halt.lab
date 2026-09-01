data "aws_caller_identity" "current" {
  count = var.is_local ? 0 : 1
}

resource "aws_kms_key" "security_cmk" {
  description             = "KMS CMK for halt.lab data protection and queue encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = var.is_local ? "*" : "arn:aws:iam::${data.aws_caller_identity.current[0].account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3AndSQSServiceAccess"
        Effect    = "Allow"
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
    ]
  })

  tags = {
    Name = "${var.project_prefix}-cmk"
  }
}

resource "aws_kms_alias" "security_cmk_alias" {
  name          = "alias/${var.project_prefix}-key"
  target_key_id = aws_kms_key.security_cmk.key_id
}
