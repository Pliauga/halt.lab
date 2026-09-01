resource "aws_sqs_queue" "security_dlq" {
  name                      = "${var.project_prefix}-security-dlq"
  kms_master_key_id         = aws_kms_key.security_cmk.arn
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "security_event_queue" {
  name                       = "${var.project_prefix}-security-events"
  visibility_timeout_seconds = 5
  kms_master_key_id          = aws_kms_key.security_cmk.arn

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.security_dlq.arn
    maxReceiveCount     = 1
  })
}

resource "aws_sqs_queue_policy" "security_queue_policy" {
  queue_url = aws_sqs_queue.security_event_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3BucketNotifications"
        Effect    = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.security_event_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.data_vault.arn
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_prefix}-security-alerts"
  kms_master_key_id = aws_kms_key.security_cmk.arn
}
