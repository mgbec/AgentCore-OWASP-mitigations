###############################################################################
# Variables
###############################################################################

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "owasp-mitigation-demo"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "availability_zones" {
  description = "Availability zones for subnets"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "runtime_idle_timeout" {
  description = "AgentCore Runtime idle session timeout in seconds (ASI08 mitigation)"
  type        = number
  default     = 300

  validation {
    condition     = var.runtime_idle_timeout >= 60 && var.runtime_idle_timeout <= 28800
    error_message = "Idle timeout must be between 60 and 28800 seconds."
  }
}

variable "runtime_max_lifetime" {
  description = "AgentCore Runtime max session lifetime in seconds (ASI08 mitigation)"
  type        = number
  default     = 1800

  validation {
    condition     = var.runtime_max_lifetime >= 60 && var.runtime_max_lifetime <= 28800
    error_message = "Max lifetime must be between 60 and 28800 seconds."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 90
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC flow logs for network monitoring"
  type        = bool
  default     = true
}

variable "financial_api_key" {
  description = "API key for financial service (stored in Secrets Manager)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "jwt_issuer_url" {
  description = "JWT issuer URL for Gateway CUSTOM_JWT authorization"
  type        = string
  default     = ""
}

variable "jwt_allowed_clients" {
  description = "Allowed JWT client IDs for Gateway authorization"
  type        = list(string)
  default     = []
}
