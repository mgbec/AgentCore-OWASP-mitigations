###############################################################################
# Lambda Interceptors - Gateway Input/Output Filtering
#
# These Lambda functions run as Gateway interceptors:
# - Input Validator: Scans requests for prompt injection (ASI01)
# - Output Filter: Redacts PII from responses (Data Leakage)
#
# They execute on every Gateway request/response, providing guaranteed
# enforcement regardless of agent behavior.
###############################################################################

# S3 bucket for Lambda deployment packages
resource "aws_s3_bucket" "lambda_code" {
  bucket_prefix = "${var.project_name}-lambda-"
  force_destroy = var.environment != "prod"

  tags = {
    Name = "${var.project_name}-lambda-code"
  }
}

resource "aws_s3_bucket_versioning" "lambda_code" {
  bucket = aws_s3_bucket.lambda_code.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lambda_code" {
  bucket = aws_s3_bucket.lambda_code.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.agent_secrets.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "lambda_code" {
  bucket = aws_s3_bucket.lambda_code.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###############################################################################
# Input Validator Lambda (ASI01 - Goal Hijack Prevention)
###############################################################################

data "archive_file" "input_validator" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/input_validator"
  output_path = "${path.module}/.build/input_validator.zip"
}

resource "aws_s3_object" "input_validator" {
  bucket = aws_s3_bucket.lambda_code.id
  key    = "input_validator/${data.archive_file.input_validator.output_md5}.zip"
  source = data.archive_file.input_validator.output_path
  etag   = data.archive_file.input_validator.output_md5
}

resource "aws_lambda_function" "input_validator" {
  function_name = "${var.project_name}-input-validator"
  description   = "Gateway interceptor: prompt injection detection (ASI01)"

  s3_bucket = aws_s3_bucket.lambda_code.id
  s3_key    = aws_s3_object.input_validator.key
  handler   = "handler.lambda_handler"
  runtime   = "python3.13"
  timeout   = 10
  memory_size = 256

  role = aws_iam_role.lambda_interceptor.arn

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda_interceptor.id]
  }

  environment {
    variables = {
      ENVIRONMENT    = var.environment
      BLOCK_THRESHOLD = "0.7"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name     = "${var.project_name}-input-validator"
    Security = "ASI01-mitigation"
  }
}

###############################################################################
# Output Filter Lambda (Data Leakage Prevention)
###############################################################################

data "archive_file" "output_filter" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/output_filter"
  output_path = "${path.module}/.build/output_filter.zip"
}

resource "aws_s3_object" "output_filter" {
  bucket = aws_s3_bucket.lambda_code.id
  key    = "output_filter/${data.archive_file.output_filter.output_md5}.zip"
  source = data.archive_file.output_filter.output_path
  etag   = data.archive_file.output_filter.output_md5
}

resource "aws_lambda_function" "output_filter" {
  function_name = "${var.project_name}-output-filter"
  description   = "Gateway interceptor: PII redaction and data leakage prevention"

  s3_bucket = aws_s3_bucket.lambda_code.id
  s3_key    = aws_s3_object.output_filter.key
  handler   = "handler.lambda_handler"
  runtime   = "python3.13"
  timeout   = 10
  memory_size = 256

  role = aws_iam_role.lambda_interceptor.arn

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda_interceptor.id]
  }

  environment {
    variables = {
      ENVIRONMENT = var.environment
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name     = "${var.project_name}-output-filter"
    Security = "data-leakage-mitigation"
  }
}
