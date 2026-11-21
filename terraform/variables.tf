variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "local_endpoint" {
  description = "Endpoint URL for local emulation (Floci)"
  type        = string
  default     = "http://localhost:4566"
}

variable "lambda_endpoint" {
  description = "Endpoint URL for Lambda containers to access host emulation"
  type        = string
  default     = "http://host.docker.internal:4566"
}

variable "is_local" {
  description = "Toggle between local emulation (Floci) and live AWS cloud"
  type        = bool
  default     = true
}

variable "max_scan_bytes" {
  description = "Maximum object size scanned in full before failing closed (default 1 MiB)"
  type        = number
  default     = 1048576
}

variable "fail_closed_oversize" {
  description = "Quarantine objects larger than max_scan_bytes instead of tagging them SCAN_INCOMPLETE"
  type        = bool
  default     = false
}

variable "project_prefix" {
  description = "Prefix for naming resources to prevent collisions"
  type        = string
  default     = "halt-lab"
}

variable "bucket_suffix" {
  description = "Explicit global bucket-name suffix; generated from random_id when empty"
  type        = string
  default     = ""
}

variable "force_destroy" {
  description = "Allow destroy to delete non-empty buckets (forced on locally, off in production)"
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "Email address subscribed to the security alert topic; empty disables the subscription"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the scanner function"
  type        = number
  default     = 90
}

variable "reserved_concurrent_executions" {
  description = "Reserved concurrency for the scanner function (-1 leaves it unreserved)"
  type        = number
  default     = 20
}

variable "max_event_concurrency" {
  description = "Maximum concurrent Lambda invocations for the SQS event source mapping"
  type        = number
  default     = 10
}

variable "sqs_visibility_timeout" {
  description = "Queue visibility timeout; must be at least 6x the Lambda timeout (180s for 30s)"
  type        = number
  default     = 180
}

variable "sqs_max_receive_count" {
  description = "Receive attempts before a poison message is moved to the DLQ"
  type        = number
  default     = 3
}

variable "enable_alarms" {
  description = "Create CloudWatch alarms for the DLQ and the scanner function"
  type        = bool
  default     = true
}

variable "enable_access_logging" {
  description = "Enable S3 server access logging for the data vault (requires access_log_bucket)"
  type        = bool
  default     = false
}

variable "access_log_bucket" {
  description = "Existing bucket that receives S3 server access logs"
  type        = string
  default     = ""
}

variable "enable_cloudtrail" {
  description = "Create a CloudTrail trail with S3 data events for both vaults (requires cloudtrail_bucket)"
  type        = bool
  default     = false
}

variable "cloudtrail_bucket" {
  description = "Existing bucket that receives CloudTrail logs"
  type        = string
  default     = ""
}

variable "kms_deletion_window_days" {
  description = "KMS pending-deletion window; production value is 30 days"
  type        = number
  default     = 30

  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}

variable "break_glass_principal_arn" {
  description = "IAM principal still allowed to schedule key deletion; empty omits the deny statement"
  type        = string
  default     = ""
}

variable "object_lock_enabled" {
  description = "Enable S3 Object Lock on the quarantine vault (immutable evidence)"
  type        = bool
  default     = false
}

variable "object_lock_retention_days" {
  description = "Default Object Lock retention period for the quarantine vault"
  type        = number
  default     = 30
}

variable "lambda_runtime" {
  description = "Lambda runtime identifier (python3.13 in production)"
  type        = string
  default     = "python3.13"
}

variable "lambda_architecture" {
  description = "Lambda instruction set architecture"
  type        = string
  default     = "arm64"
}

variable "enable_xray" {
  description = "Enable AWS X-Ray active tracing on the scanner function"
  type        = bool
  default     = true
}
