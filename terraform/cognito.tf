###############################################################################
# Cognito - JWT OAuth 2.1 Identity Provider (ASI03, ASI09 mitigation)
#
# Provides authentication for users and agents accessing the Gateway:
# - User Pool: manages user identities and credentials
# - App Client: issues JWT access tokens (OAuth 2.1 client_credentials flow)
# - Resource Server: defines custom scopes for fine-grained access
# - Domain: hosts the OAuth 2.1 authorization endpoints
#
# The Gateway's CUSTOM_JWT authorizer validates tokens issued by this pool.
###############################################################################

resource "aws_cognito_user_pool" "agent_users" {
  name = "${var.project_name}-users"

  # Password policy (strong defaults)
  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  # MFA enforcement
  mfa_configuration = "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }

  # Account recovery
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # Schema attributes
  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true

    string_attribute_constraints {
      min_length = 5
      max_length = 256
    }
  }

  # Advanced security (detects compromised credentials, adaptive auth)
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  # Token configuration
  admin_create_user_config {
    allow_admin_create_user_only = var.environment == "prod"
  }

  tags = {
    Name     = "${var.project_name}-user-pool"
    Security = "ASI03-identity"
  }
}

###############################################################################
# Resource Server - Custom OAuth 2.1 Scopes
###############################################################################

resource "aws_cognito_resource_server" "agentcore_api" {
  identifier = "agentcore-api"
  name       = "AgentCore API"

  user_pool_id = aws_cognito_user_pool.agent_users.id

  # Fine-grained scopes for different access levels
  scope {
    scope_name        = "finance.read"
    scope_description = "Read financial data (balances, transactions)"
  }

  scope {
    scope_name        = "finance.write"
    scope_description = "Execute financial operations (transfers)"
  }

  scope {
    scope_name        = "knowledge.read"
    scope_description = "Query knowledge base and documents"
  }

  scope {
    scope_name        = "admin"
    scope_description = "Full administrative access"
  }
}

###############################################################################
# App Client - Machine-to-Machine (Client Credentials Flow)
#
# Used by agents and services to obtain access tokens without user interaction.
# This is the OAuth 2.1 client_credentials grant type.
###############################################################################

resource "aws_cognito_user_pool_client" "agent_client" {
  name         = "${var.project_name}-agent-client"
  user_pool_id = aws_cognito_user_pool.agent_users.id

  # OAuth 2.1 configuration
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes = [
    "agentcore-api/finance.read",
    "agentcore-api/finance.write",
    "agentcore-api/knowledge.read",
  ]

  supported_identity_providers = ["COGNITO"]

  # Token validity (short-lived for security)
  access_token_validity  = 1 # 1 hour
  id_token_validity      = 1 # 1 hour
  refresh_token_validity = 1 # 1 day

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  # Prevent token leakage
  prevent_user_existence_errors = "ENABLED"

  depends_on = [aws_cognito_resource_server.agentcore_api]
}

###############################################################################
# App Client - User-Facing (Authorization Code Flow with PKCE)
#
# Used by end users authenticating via browser. OAuth 2.1 mandates PKCE
# for all authorization code flows.
###############################################################################

resource "aws_cognito_user_pool_client" "user_client" {
  name         = "${var.project_name}-user-client"
  user_pool_id = aws_cognito_user_pool.agent_users.id

  # OAuth 2.1 with PKCE (no client secret for public clients)
  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes = [
    "openid",
    "email",
    "agentcore-api/finance.read",
    "agentcore-api/knowledge.read",
  ]

  supported_identity_providers = ["COGNITO"]

  # Callback URLs (update with your actual app URLs)
  callback_urls = var.cognito_callback_urls
  logout_urls   = var.cognito_logout_urls

  # Token validity
  access_token_validity  = 1  # 1 hour
  id_token_validity      = 1  # 1 hour
  refresh_token_validity = 30 # 30 days

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  # Security settings
  prevent_user_existence_errors = "ENABLED"
  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
  ]

  depends_on = [aws_cognito_resource_server.agentcore_api]
}

###############################################################################
# Cognito Domain - OAuth 2.1 Endpoints
###############################################################################

resource "aws_cognito_user_pool_domain" "main" {
  domain       = "${var.project_name}-${data.aws_caller_identity.current.account_id}"
  user_pool_id = aws_cognito_user_pool.agent_users.id
}
