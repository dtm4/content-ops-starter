#!/usr/bin/env bash
set -euo pipefail

# Packages mcp_spend_server/ into a deployable ZIP (sources, Dockerfile, compose, .env.example).
SRC_DIR="./mcp_spend_server"
ZIP_NAME="mcp_spend_server_production.zip"

echo "🚀 Packaging $SRC_DIR..."
rm -f "$ZIP_NAME"
(cd "$SRC_DIR" && zip -r "../$ZIP_NAME" . -x "tests/*" "*__pycache__*" "*.db" ".env" ".pytest_cache/*" > /dev/null)

echo "✨ Production ZIP created successfully: $ZIP_NAME"
