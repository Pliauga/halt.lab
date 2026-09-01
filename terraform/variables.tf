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
  description = "Maximum byte range to inspect per uploaded object"
  type        = number
  default     = 65536
}

variable "project_prefix" {
  description = "Prefix for naming resources to prevent collisions"
  type        = string
  default     = "halt-lab"
}
