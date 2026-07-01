#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

# ── Production-region guard ───────────────────────────────────────────────────
# If CAGE_DEPLOYMENT_REGION is already set to a production region, warn the
# developer before proceeding.  Running dev setup against a production region
# context may violate compliance requirements (GDPR Art. 44, MAS TRM §4.2).
if [[ "${CAGE_DEPLOYMENT_REGION:-}" == "US_FED" || \
      "${CAGE_DEPLOYMENT_REGION:-}" == "EU_ECB"  || \
      "${CAGE_DEPLOYMENT_REGION:-}" == "APAC_MAS" ]]; then
  echo ""
  echo "⚠️  WARNING: CAGE_DEPLOYMENT_REGION is set to a production region (${CAGE_DEPLOYMENT_REGION})."
  echo "   Running dev setup in a production region context may violate compliance requirements."
  echo "   This script will override CAGE_ENV=dev and set insecure placeholder secrets."
  read -r -p "   Continue anyway? [y/N] " confirm
  [[ "${confirm}" == "y" || "${confirm}" == "Y" ]] || exit 1
  echo ""
fi

# ── DEV POSTURE — explicitly declare all dev-mode env vars ───────────────────
#
# CAGE_ENV default changed to "prod" (fail-secure) in Phase 1.
# This script MUST explicitly set CAGE_ENV=dev so that:
#   • KMS evidence signing falls back to stub HMAC (no GCP KMS required locally)
#   • Routing seal accepts the insecure placeholder secret below
#   • Normative provider uses stub thresholds instead of Langfuse production data
#   • OPA runs in dry-run mode (no hard enforcement locally)
#
# These values are INTENTIONALLY INSECURE and must NEVER be used in production.
export CAGE_ENV=dev

# Prevents regional compliance overlays (US_FED / EU_ECB / APAC_MAS) from
# activating.  Leave unset or set to LOCAL for local development.
export CAGE_DEPLOYMENT_REGION="${CAGE_DEPLOYMENT_REGION:-LOCAL}"

# Insecure placeholder — satisfies the routing seal length check without
# requiring a real ≥64-char secret from Kubernetes Secrets.
export CAGE_ROUTING_SEAL_SECRET="${CAGE_ROUTING_SEAL_SECRET:-dev-only-insecure-placeholder-not-for-production-use}"

# Insecure placeholder — satisfies the HMAC governance salt check locally.
export GOVERNANCE_SALT="${GOVERNANCE_SALT:-dev-only-insecure-placeholder-not-for-production-use}"

# Run Langfuse posture check in dry-run mode — no enforcement, no hard failures.
export LANGFUSE_POSTURE_DRY_RUN=true

# ── DEV POSTURE ACTIVE banner ─────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           ⚠   CAGE DEV POSTURE ACTIVE   ⚠                   ║"
echo "║                                                              ║"
echo "║  The following production controls are DISABLED:             ║"
echo "║  • KMS evidence signing       (using stub HMAC)              ║"
echo "║  • Routing seal custom salt   (using insecure placeholder)   ║"
echo "║  • Langfuse normative provider (using stub thresholds)       ║"
echo "║  • OPA enforce mode           (dry-run only)                 ║"
echo "║  • PSA restricted labels      (not enforced locally)         ║"
echo "║                                                              ║"
echo "║  DO NOT use this configuration in production.                ║"
echo "║  Set CAGE_ENV=prod to enable full enforcement.               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Install dependencies ──────────────────────────────────────────────────────
echo "Setting up OSS development environment..."

# Setup standard node modules
cd src/agentsight-ui
echo "Installing Node Dependencies..."
npm install

cd ../../
# Install python requirements via standard mechanisms
echo "Installing Python Dependencies..."
uv pip install -e .

echo ""
echo "✅  Setup complete. You can now run the services."
echo "    CAGE_ENV=${CAGE_ENV}  CAGE_DEPLOYMENT_REGION=${CAGE_DEPLOYMENT_REGION}"
