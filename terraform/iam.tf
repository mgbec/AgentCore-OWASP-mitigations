###############################################################################
# IAM Roles - Least Privilege (ASI03 mitigation)
#
# Each component gets the minimum permissions required:
# - Runtime role: invoke models, access memory, get credentials
# - Gateway role: invoke runtime and Lambda interceptors only
# - Lambda role: basic execution + specific service access
#
# This prevents privilege escalation and limits blast radius.
###############################################################################

# AgentCore Runtime Execution Role
resource "aws_iam_role" "agentcore_runtime" {
  name_prefix = "${var.project_name}-runtime-"
  description = "Execution role for AgentCore Runtime (least privilege - ASI03)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "bedrock-agentcore.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "runtime_bedrock" {
  name_prefix = "bedrock-invoke-"
  role        = aws_iam_role.agentcore_runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeModels"
        Effect = "Allow"
        Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = [
          "arn:aws:bedrock:${var.aws_region}::foundation-model/anthropic.claude-*",
          "arn:aws:bedrock:${var.aws_region}::foundation-model/us.anthropic.claude-*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "runtime_agentcore" {
  name_prefix = "agentcore-services-"
  role        = aws_iam_role.agentcore_runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AccessMemory"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:CreateMemory",
          "bedrock-agentcore:GetMemory",
          "bedrock-agentcore:SearchMemory",
          "bedrock-agentcore:DeleteMemory"
        ]
        Resource = "arn:aws:bedrock-agentcore:${var.aws_region}:${data.aws_caller_identity.current.account_id}:memory/*"
      },
      {
        Sid    = "AccessIdentity"
        Effect = "Allow"
        Action = [
          "bedrock-agentcore:GetWorkloadToken",
          "bedrock-agentcore:RetrieveCredential"
        ]
        Resource = [
          "arn:aws:bedrock-agentcore:${var.aws_region}:${data.aws_caller_identity.current.account_id}:workload-identity/triage-agent-identity",
          "arn:aws:bedrock-agentcore:${var.aws_region}:${data.aws_caller_identity.current.account_id}:workload-identity/finance-agent-identity",
          "arn:aws:bedrock-agentcore:${var.aws_region}:${data.aws_caller_identity.current.account_id}:workload-identity/knowledge-agent-identity"
        ]
      },
      {
        Sid    = "CodeInterpreter"
        Effect = "Allow"
        Action = ["bedrock-agentcore:InvokeCodeInterpreter"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "runtime_logging" {
  name_prefix = "cloudwatch-logs-"
  role        = aws_iam_role.agentcore_runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "CloudWatchLogs"
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/bedrock-agentcore/*"
    }]
  })
}

resource "aws_iam_role_policy" "runtime_kms" {
  name_prefix = "kms-decrypt-"
  role        = aws_iam_role.agentcore_runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DecryptSecrets"
      Effect = "Allow"
      Action = [
        "kms:Decrypt",
        "kms:DescribeKey"
      ]
      Resource = [aws_kms_key.agent_secrets.arn]
    }]
  })
}

# Gateway Service Role
resource "aws_iam_role" "agentcore_gateway" {
  name_prefix = "${var.project_name}-gateway-"
  description = "Service role for AgentCore Gateway (ASI03 - cannot access secrets directly)"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "bedrock-agentcore.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "gateway_invoke" {
  name_prefix = "invoke-targets-"
  role        = aws_iam_role.agentcore_gateway.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeRuntime"
        Effect = "Allow"
        Action = ["bedrock-agentcore:InvokeAgentRuntime"]
        Resource = "arn:aws:bedrock-agentcore:${var.aws_region}:${data.aws_caller_identity.current.account_id}:runtime/*"
      },
      {
        Sid    = "InvokeLambdaInterceptors"
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          aws_lambda_function.input_validator.arn,
          aws_lambda_function.output_filter.arn
        ]
      }
    ]
  })
}

# Lambda Execution Role for Interceptors
resource "aws_iam_role" "lambda_interceptor" {
  name_prefix = "${var.project_name}-lambda-"
  description = "Execution role for Gateway Lambda interceptors"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_interceptor.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
