#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$ROOT_DIR/reverse-proxy/certs"
SAN_CONFIG="$ROOT_DIR/reverse-proxy/san.cnf"

mkdir -p "$CERT_DIR"

openssl req \
  -x509 \
  -nodes \
  -days 365 \
  -newkey rsa:2048 \
  -keyout "$CERT_DIR/localhost.key" \
  -out "$CERT_DIR/localhost.crt" \
  -config "$SAN_CONFIG" \
  -extensions v3_req

chmod 600 "$CERT_DIR/localhost.key"

echo "Generated:"
echo "  $CERT_DIR/localhost.crt"
echo "  $CERT_DIR/localhost.key"
