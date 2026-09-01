output "kms_key_arn" {
  description = "ARN of Customer Managed KMS Key"
  value       = aws_kms_key.security_cmk.arn
}

output "data_vault_bucket" {
  description = "Name of the primary protected S3 Data Vault"
  value       = aws_s3_bucket.data_vault.id
}

output "quarantine_vault_bucket" {
  description = "Name of the isolated S3 Quarantine Vault"
  value       = aws_s3_bucket.quarantine_vault.id
}

output "sqs_event_queue_url" {
  description = "URL of the Main Security SQS Queue"
  value       = aws_sqs_queue.security_event_queue.id
}

output "sqs_dlq_url" {
  description = "URL of the Security Dead-Letter Queue (DLQ)"
  value       = aws_sqs_queue.security_dlq.id
}

output "sns_alert_topic_arn" {
  description = "ARN of the Security Alerts SNS Topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "lambda_function_name" {
  description = "Name of the deployed Security Scanner Lambda"
  value       = aws_lambda_function.security_scanner.function_name
}
