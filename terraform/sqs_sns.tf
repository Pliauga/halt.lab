resource "aws_sqs_queue" "security_dlq" {
  name                      = "${var.project_prefix}-security-dlq"
  kms_master_key_id         = aws_kms_key.security_cmk.arn
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "security_event_queue" {
  name                       = "${var.project_prefix}-security-events"
  visibility_timeout_seconds = var.sqs_visibility_timeout
  kms_master_key_id          = aws_kms_key.security_cmk.arn

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.security_dlq.arn
    maxReceiveCount     = var.sqs_max_receive_count
  })
}

resource "aws_sqs_queue_policy" "security_queue_policy" {
  queue_url = aws_sqs_queue.security_event_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3BucketNotifications"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.security_event_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.data_vault.arn
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
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

resource "aws_sns_topic_policy" "security_alerts_policy" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountOwner"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "sns:*"
        Resource  = aws_sns_topic.security_alerts.arn
      },
      {
        Sid       = "AllowScannerPublish"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lambda_security_role.arn }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alerts.arn
      },
      {
        Sid       = "AllowCloudWatchAlarmPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  count = var.alert_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- Monitoring -------------------------------------------------------------
# A detection that nobody sees is not a control. Alarms publish to the same
# topic an operator is subscribed to.

resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  count = var.enable_alarms ? 1 : 0

  alarm_name          = "${var.project_prefix}-dlq-not-empty"
  alarm_description   = "A security scan event reached the dead-letter queue"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.security_dlq.name
  }

  alarm_actions = [aws_sns_topic.security_alerts.arn]
  ok_actions    = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count = var.enable_alarms ? 1 : 0

  alarm_name          = "${var.project_prefix}-scanner-errors"
  alarm_description   = "The security scanner raised errors; some objects may be unscanned"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.security_scanner.function_name
  }

  alarm_actions = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  count = var.enable_alarms ? 1 : 0

  alarm_name          = "${var.project_prefix}-scanner-throttles"
  alarm_description   = "The security scanner is being throttled; scans are backing up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.security_scanner.function_name
  }

  alarm_actions = [aws_sns_topic.security_alerts.arn]
}

# --- Audit trail (optional) -------------------------------------------------

resource "aws_cloudtrail" "vault_audit" {
  count = var.enable_cloudtrail && var.cloudtrail_bucket != "" ? 1 : 0

  name                          = "${var.project_prefix}-vault-audit"
  s3_bucket_name                = var.cloudtrail_bucket
  include_global_service_events = true
  is_multi_region_trail         = false

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.data_vault.arn}/", "${aws_s3_bucket.quarantine_vault.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.data_vault_policy]
}
