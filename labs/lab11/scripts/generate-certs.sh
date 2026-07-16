#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$LAB_DIR/reverse-proxy/certs"
mkdir -p "$CERT_DIR"

openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout "$CERT_DIR/localhost.key" \
  -out "$CERT_DIR/localhost.crt" \
  -subj "/CN=juice.local" \
  -addext "subjectAltName=DNS:juice.local,DNS:localhost,IP:127.0.0.1" \
  -days 3650

chmod 600 "$CERT_DIR/localhost.key"
chmod 644 "$CERT_DIR/localhost.crt"

echo "Generated $CERT_DIR/localhost.crt and localhost.key"
echo "The private key is for local lab use only and is ignored by Git."
