###############################################################################
# VPC - Network Isolation (ASI04, ASI05 mitigation)
#
# Agents run in private subnets with no direct internet access.
# Egress is controlled via VPC endpoints and security groups.
# This prevents:
# - Data exfiltration (Model Exfiltration risk)
# - Unauthorized outbound connections (ASI10 - Rogue Agents)
# - Supply chain attacks via network (ASI04)
###############################################################################

resource "aws_vpc" "agent_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Private subnets - no internet gateway attached
resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.agent_vpc.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-private-${count.index + 1}"
    Tier = "private"
  }
}

# Security group for AgentCore Runtime (ASI05, ASI08 mitigation)
resource "aws_security_group" "agent_runtime" {
  name_prefix = "${var.project_name}-runtime-"
  vpc_id      = aws_vpc.agent_vpc.id
  description = "Security group for AgentCore Runtime - restricted egress"

  # No inbound from internet - only from VPC endpoints
  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Restricted egress - only to AWS services via VPC endpoints
  egress {
    description = "HTTPS to AWS services"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Allow egress to S3 and Bedrock via prefix lists
  egress {
    description     = "S3 via gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id]
  }

  tags = {
    Name = "${var.project_name}-runtime-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Security group for Lambda interceptors
resource "aws_security_group" "lambda_interceptor" {
  name_prefix = "${var.project_name}-lambda-"
  vpc_id      = aws_vpc.agent_vpc.id
  description = "Security group for Lambda interceptors"

  egress {
    description = "HTTPS to VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${var.project_name}-lambda-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

###############################################################################
# VPC Endpoints - Allow access to AWS services without internet
###############################################################################

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.agent_vpc.id
  service_name = "com.amazonaws.${var.aws_region}.s3"

  tags = {
    Name = "${var.project_name}-s3-endpoint"
  }
}

resource "aws_vpc_endpoint_route_table_association" "s3" {
  count = length(aws_subnet.private)

  route_table_id  = aws_route_table.private.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}

resource "aws_vpc_endpoint" "bedrock" {
  vpc_id              = aws_vpc.agent_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.agent_runtime.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-bedrock-endpoint"
  }
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.agent_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.agent_runtime.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-logs-endpoint"
  }
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.agent_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.agent_runtime.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-secrets-endpoint"
  }
}

# Route table for private subnets (no internet route)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.agent_vpc.id

  tags = {
    Name = "${var.project_name}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

###############################################################################
# VPC Flow Logs (ASI10 - Rogue Agent network detection)
###############################################################################

resource "aws_flow_log" "vpc" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  iam_role_arn    = aws_iam_role.flow_log[0].arn
  log_destination = aws_cloudwatch_log_group.flow_log[0].arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.agent_vpc.id

  tags = {
    Name = "${var.project_name}-flow-log"
  }
}

resource "aws_cloudwatch_log_group" "flow_log" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name              = "/aws/vpc/flow-log/${var.project_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-flow-log"
  }
}

resource "aws_iam_role" "flow_log" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name_prefix = "${var.project_name}-flow-log-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "flow_log" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name_prefix = "flow-log-"
  role        = aws_iam_role.flow_log[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}
