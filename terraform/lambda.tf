data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/security_scanner.py"
  output_path = "${path.module}/../lambda/security_scanner.zip"
}

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${var.project_prefix}-scanner"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "security_scanner" {
  filename                       = data.archive_file.lambda_zip.output_path
  function_name                  = "${var.project_prefix}-scanner"
  role                           = aws_iam_role.lambda_security_role.arn
  handler                        = "security_scanner.lambda_handler"
  runtime                        = var.lambda_runtime
  architectures                  = [var.lambda_architecture]
  timeout                        = 30
  memory_size                    = 256
  reserved_concurrent_executions = var.reserved_concurrent_executions
  source_code_hash               = data.archive_file.lambda_zip.output_base64sha256

  tracing_config {
    mode = var.enable_xray ? "Active" : "PassThrough"
  }

  environment {
    variables = {
      QUARANTINE_BUCKET    = aws_s3_bucket.quarantine_vault.id
      ALERT_SNS_TOPIC_ARN  = aws_sns_topic.security_alerts.arn
      AWS_ENDPOINT_URL     = var.is_local ? var.lambda_endpoint : ""
      MAX_SCAN_BYTES       = tostring(var.max_scan_bytes)
      FAIL_CLOSED_OVERSIZE = var.fail_closed_oversize ? "true" : "false"
    }
  }

  tags = {
    Name = "${var.project_prefix}-scanner"
  }

  depends_on = [
    aws_cloudwatch_log_group.scanner,
    aws_iam_role_policy_attachment.lambda_attach_policy,
  ]
}

resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn        = aws_sqs_queue.security_event_queue.arn
  function_name           = aws_lambda_function.security_scanner.arn
  batch_size              = 5
  enabled                 = true
  function_response_types = ["ReportBatchItemFailures"]

  scaling_config {
    maximum_concurrency = var.max_event_concurrency
  }

  # Without this the mapping can be created before the role can read the queue,
  # so the first invocations fail with AccessDenied and are never retried.
  depends_on = [aws_iam_role_policy_attachment.lambda_attach_policy]
}
