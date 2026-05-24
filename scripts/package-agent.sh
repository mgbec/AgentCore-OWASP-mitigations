#!/bin/bash
###############################################################################
# Package Agent Code for Deployment
#
# Creates a deployment zip package with:
# - Agent source code
# - Python dependencies
# - Excludes test files, dev dependencies, and secrets
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'
NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }

TIMESTAMP=$(date +%Y%m%d%H%M%S)
OUTPUT_DIR="${PROJECT_DIR}/dist"
PACKAGE_DIR=$(mktemp -d)
ZIP_FILE="${OUTPUT_DIR}/agent-${TIMESTAMP}.zip"

mkdir -p "${OUTPUT_DIR}"

log_info "Packaging agent code..."

# Copy source code
cp -r "${PROJECT_DIR}/src" "${PACKAGE_DIR}/"
cp "${PROJECT_DIR}/requirements.txt" "${PACKAGE_DIR}/"

# Install production dependencies
log_info "Installing dependencies..."
pip install \
    -r "${PROJECT_DIR}/requirements.txt" \
    -t "${PACKAGE_DIR}/lib" \
    --quiet \
    --no-cache-dir \
    --only-binary=:all: 2>/dev/null || \
pip install \
    -r "${PROJECT_DIR}/requirements.txt" \
    -t "${PACKAGE_DIR}/lib" \
    --quiet \
    --no-cache-dir

# Remove unnecessary files from package
find "${PACKAGE_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${PACKAGE_DIR}" -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true
find "${PACKAGE_DIR}" -name "*.pyc" -delete 2>/dev/null || true
find "${PACKAGE_DIR}" -name "*.pyo" -delete 2>/dev/null || true

# Create zip
log_info "Creating zip package..."
cd "${PACKAGE_DIR}"
zip -r "${ZIP_FILE}" . -x "*.pyc" "__pycache__/*" "*.egg-info/*" >/dev/null

# Cleanup
rm -rf "${PACKAGE_DIR}"

SIZE=$(du -h "${ZIP_FILE}" | cut -f1)
log_info "Package created: ${ZIP_FILE} (${SIZE})"
log_info ""
log_info "Upload to S3:"
log_info "  aws s3 cp ${ZIP_FILE} s3://\${CODE_BUCKET}/agent-code/${TIMESTAMP}/agent.zip"
