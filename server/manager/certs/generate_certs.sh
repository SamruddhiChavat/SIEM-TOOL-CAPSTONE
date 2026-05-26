#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# SecureWatch — Self-Signed Certificate Generator
# Generates CA + Server + Agent certs for mutual TLS authentication
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_DAYS=3650     # 10 years
CERT_DAYS=365    # 1 year

echo "🔐 SecureWatch Certificate Generator"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─── CA Certificate ──────────────────

echo "1/3 Generating Certificate Authority..."
openssl req -x509 -newkey rsa:4096 -sha256 -days "$CA_DAYS" \
    -nodes -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -subj "/CN=SecureWatch CA/O=SecureWatch/OU=SIEM" 2>/dev/null

echo "    ✅ CA cert: $CERT_DIR/ca.crt"

# ─── Server Certificate ─────────────

echo "2/3 Generating Manager Server certificate..."
openssl req -newkey rsa:2048 -nodes -sha256 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
    -subj "/CN=securewatch-manager/O=SecureWatch/OU=Manager" 2>/dev/null

openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/server.crt" -days "$CERT_DAYS" -sha256 2>/dev/null

rm -f "$CERT_DIR/server.csr"
echo "    ✅ Server cert: $CERT_DIR/server.crt"

# ─── Agent Certificate ──────────────

echo "3/3 Generating Agent certificate template..."
openssl req -newkey rsa:2048 -nodes -sha256 \
    -keyout "$CERT_DIR/agent.key" -out "$CERT_DIR/agent.csr" \
    -subj "/CN=securewatch-agent/O=SecureWatch/OU=Agent" 2>/dev/null

openssl x509 -req -in "$CERT_DIR/agent.csr" -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/agent.crt" -days "$CERT_DAYS" -sha256 2>/dev/null

rm -f "$CERT_DIR/agent.csr" "$CERT_DIR/ca.srl"
echo "    ✅ Agent cert: $CERT_DIR/agent.crt"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ All certificates generated in: $CERT_DIR"
echo "   Copy ca.crt + agent.crt + agent.key to each agent host."
