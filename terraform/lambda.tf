data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/security_scanner.py"
  output_path = "${path.module}/../lambda/security_scanner.zip"
}

resource "aws_lambda_function" "security_scanner" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_prefix}-scanner"
  role             = aws_iam_role.lambda_security_role.arn
  handler          = "security_scanner.lambda_handler"
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 256
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      QUARANTINE_BUCKET   = aws_s3_bucket.quarantine_vault.id
      ALERT_SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
      AWS_ENDPOINT_URL    = var.is_local ? var.lambda_endpoint : ""
      MAX_SCAN_BYTES      = tostring(var.max_scan_bytes)
    }
  }

  tags = {
    Name = "${var.project_prefix}-scanner"
  }
}

resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn        = aws_sqs_queue.security_event_queue.arn
  function_name           = aws_lambda_function.security_scanner.arn
  batch_size              = 5
  enabled                 = true
  function_response_types = ["ReportBatchItemFailures"]
}
