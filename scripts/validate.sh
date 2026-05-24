#!/bin/bash
###############################################################################
# Validation Script
#
# Runs pre-deployment checks:
# 1. Terraform validation and formatting
# 2. Python linting and security scanning
# 3. Dependency vulnerability audit
# 4. Security tests
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="${PROJECT_DIR}/terraform"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

log_info() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS + 1)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo "=== Pre-Deployment Validation ==="
echo ""

###############################################################################
# Terraform Checks
###############################################################################

echo "--- Terraform ---"

cd "${TERRAFORM_DIR}"

if terraform fmt -check -recursive >/dev/null 2>&1; then
    log_info "Terraform formatting"
else
    log_fail "Terraform formatting (run: terraform fmt -recursive)"
fi

if terraform init -backend=false >/dev/null 2>&1; then
    if terraform validate >/dev/null 2>&1; then
        log_info "Terraform validation"
    else
        log_fail "Terraform validation"
    fi
else
    log_fail "Terraform init"
fi

###############################################################################
# Python Checks
###############################################################################

echo ""
echo "--- Python ---"

cd "${PROJECT_DIR}"

# Check for secrets in code
if grep -r "sk_live\|AKIA[0-9A-Z]\|password\s*=" src/ lambda/ 2>/dev/null | grep -v "\.pyc" | grep -v "__pycache__"; then
    log_fail "Potential secrets found in source code"
else
    log_info "No secrets detected in source code"
fi

# Run bandit security scanner
if command -v bandit >/dev/null 2>&1; then
    if bandit -r src/ lambda/ -q 2>/dev/null; then
        log_info "Bandit security scan"
    else
        log_warn "Bandit found issues (review output above)"
    fi
else
    log_warn "Bandit not installed (pip install bandit)"
fi

# Run pip-audit
if command -v pip-audit >/dev/null 2>&1; then
    if pip-audit -r requirements.txt --strict 2>/dev/null; then
        log_info "Dependency vulnerability audit"
    else
        log_fail "Vulnerable dependencies found"
    fi
else
    log_warn "pip-audit not installed (pip install pip-audit)"
fi

###############################################################################
# Security Tests
###############################################################################

echo ""
echo "--- Security Tests ---"

if command -v pytest >/dev/null 2>&1; then
    if pytest tests/ -q --tb=no 2>/dev/null; then
        log_info "Security tests passed"
    else
        log_fail "Security tests failed"
    fi
else
    log_warn "pytest not installed"
fi

###############################################################################
# File Checks
###############################################################################

echo ""
echo "--- File Security ---"

# Check .gitignore exists
if [ -f "${PROJECT_DIR}/.gitignore" ]; then
    log_info ".gitignore present"
else
    log_fail ".gitignore missing"
fi

# Check no .env files committed
if find "${PROJECT_DIR}" -name ".env*" -not -path "*/.git/*" | grep -q .; then
    log_fail ".env files found in project (should be gitignored)"
else
    log_info "No .env files in project"
fi

# Check no terraform.tfvars committed
if [ -f "${TERRAFORM_DIR}/terraform.tfvars" ]; then
    log_fail "terraform.tfvars found (should not be committed)"
else
    log_info "No terraform.tfvars committed"
fi

###############################################################################
# Summary
###############################################################################

echo ""
echo "=== Validation Summary ==="
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}All checks passed. Safe to deploy.${NC}"
    exit 0
else
    echo -e "${RED}${ERRORS} check(s) failed. Fix issues before deploying.${NC}"
    exit 1
fi
