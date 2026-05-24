###############################################################################
# Outputs
###############################################################################

output "vpc_id" {
  description = "VPC ID for AgentCore Runtime"
  value       = aws_vpc.agent_vpc.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs for AgentCore Runtime VPC configuration"
  value       = aws_subnet.private[*].id
}

output "security_group_id" {
  description = "Security group ID for AgentCore Runtime"
  value       = aws_security_group.agent_runtime.id
}

output "runtime_role_arn" {
  description = "IAM role ARN for AgentCore Runtime execution"
  value       = aws_iam_role.agentcore_runtime.arn
}

output "gateway_role_arn" {
  description = "IAM role ARN for AgentCore Gateway"
  value       = aws_iam_role.agentcore_gateway.arn
}

output "kms_key_arn" {
  description = "KMS key ARN for secret encryption"
  value       = aws_kms_key.agent_secrets.arn
}

output "agent_code_bucket" {
  description = "S3 bucket for agent code deployment"
  value       = aws_s3_bucket.agent_code.id
}

output "input_validator_lambda_arn" {
  description = "ARN of the input validator Lambda interceptor"
  value       = aws_lambda_function.input_validator.arn
}

output "output_filter_lambda_arn" {
  description = "ARN of the output filter Lambda interceptor"
  value       = aws_lambda_function.output_filter.arn
}

output "financial_api_secret_arn" {
  description = "ARN of the financial API key secret"
  value       = aws_secretsmanager_secret.financial_api_key.arn
}

output "agentcore_deploy_command" {
  description = "Command to deploy the agent to AgentCore Runtime"
  value       = <<-EOT
    # Deploy agent code to AgentCore Runtime:
    cd ../
    agentcore deploy \
      --name owasp_mitigation_demo \
      --entry-point src/main.py \
      --runtime PYTHON_3_13 \
      --role-arn ${aws_iam_role.agentcore_runtime.arn} \
      --network-mode VPC \
      --subnets ${join(",", aws_subnet.private[*].id)} \
      --security-groups ${aws_security_group.agent_runtime.id} \
      --idle-timeout ${var.runtime_idle_timeout} \
      --max-lifetime ${var.runtime_max_lifetime}
  EOT
}
