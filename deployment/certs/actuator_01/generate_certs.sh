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

# generate_certs.sh — Generate mTLS certificates for actuator_01 integration
#
# Creates:
# 1. Root CA certificate (ca.crt) — for Archytan's trust store
# 2. Client certificate (client.crt) — CAGE's mTLS identity
# 3. Client private key (client.key) — CAGE's signing key
#
# Subject Alternative Name (SAN): cage.governance.example.com
# Common Name (CN): CAGE Governance Engine - actuator_01 Client

set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CERT_DIR"

echo "[INFO] Generating actuator_01 mTLS certificates in $CERT_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# 1. Generate Root CA
# ══════════════════════════════════════════════════════════════════════════════

echo "[1/4] Generating CA private key..."
openssl genrsa -out ca.key 4096 2>/dev/null

echo "[2/4] Generating CA certificate (10-year validity)..."
openssl req -new -x509 \
  -key ca.key \
  -out ca.crt \
  -days 3650 \
  -subj "/C=US/ST=California/L=Mountain View/O=CAGE Reference Architecture/OU=Governance Integrations/CN=CAGE actuator_01 Root CA" \
  2>/dev/null

# ══════════════════════════════════════════════════════════════════════════════
# 2. Generate Client Certificate with SAN
# ══════════════════════════════════════════════════════════════════════════════

echo "[3/4] Generating client private key..."
openssl genrsa -out client.key 4096 2>/dev/null

echo "[4/4] Generating client certificate with SAN (2-year validity)..."

# Create OpenSSL config for SAN
cat > client.cnf <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C = US
ST = California
L = Mountain View
O = CAGE Reference Architecture
OU = Governance Engine
CN = CAGE Governance Engine - actuator_01 Client

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = cage.governance.example.com
DNS.2 = cage-actuator01.governance.example.com
EOF

# Generate CSR with SAN
openssl req -new \
  -key client.key \
  -out client.csr \
  -config client.cnf \
  2>/dev/null

# Sign client cert with CA
openssl x509 -req \
  -in client.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out client.crt \
  -days 730 \
  -extensions req_ext \
  -extfile client.cnf \
  2>/dev/null

# Clean up CSR and config
rm -f client.csr client.cnf ca.srl

# ══════════════════════════════════════════════════════════════════════════════
# 3. Set Permissions
# ══════════════════════════════════════════════════════════════════════════════

chmod 600 ca.key client.key
chmod 644 ca.crt client.crt

# ══════════════════════════════════════════════════════════════════════════════
# 4. Display Certificate Details
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "Certificate Generation Complete"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Files created:"
echo "  - ca.crt        → Root CA certificate (send to Archytan)"
echo "  - ca.key        → Root CA private key (KEEP PRIVATE)"
echo "  - client.crt    → Client certificate (CAGE mTLS identity)"
echo "  - client.key    → Client private key (KEEP PRIVATE)"
echo ""
echo "────────────────────────────────────────────────────────────────────────────────"
echo "CA Certificate Details:"
echo "────────────────────────────────────────────────────────────────────────────────"
openssl x509 -in ca.crt -noout -subject -issuer -dates
echo ""
echo "────────────────────────────────────────────────────────────────────────────────"
echo "Client Certificate Details:"
echo "────────────────────────────────────────────────────────────────────────────────"
openssl x509 -in client.crt -noout -subject -issuer -dates -ext subjectAltName
echo ""
echo "────────────────────────────────────────────────────────────────────────────────"
echo "Identity Details for Archytan Registration:"
echo "────────────────────────────────────────────────────────────────────────────────"
echo "Subject CN: CAGE Governance Engine - actuator_01 Client"
echo "Primary SAN: cage.governance.example.com"
echo "Secondary SAN: cage-actuator01.governance.example.com"
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
