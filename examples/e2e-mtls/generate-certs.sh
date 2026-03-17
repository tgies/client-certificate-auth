#!/usr/bin/env bash
set -euo pipefail

# Generate a self-signed CA, server certificate, and client certificate
# for testing mTLS (mutual TLS) authentication.

CERTS_DIR="certs"
DAYS=365

mkdir -p "$CERTS_DIR"

echo "=== Generating Certificate Authority ==="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$CERTS_DIR/ca.key" -out "$CERTS_DIR/ca.pem" \
  -days "$DAYS" -nodes \
  -subj "/CN=Test CA/O=client-certificate-auth Example"

echo "=== Generating Server Certificate ==="
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$CERTS_DIR/server.key" -out "$CERTS_DIR/server.csr" \
  -nodes -subj "/CN=localhost/O=Test Server"

openssl x509 -req -in "$CERTS_DIR/server.csr" \
  -CA "$CERTS_DIR/ca.pem" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial \
  -out "$CERTS_DIR/server.pem" -days "$DAYS" \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

echo "=== Generating Client Certificate ==="
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$CERTS_DIR/client.key" -out "$CERTS_DIR/client.csr" \
  -nodes -subj "/CN=trusted-client/O=Test Client"

openssl x509 -req -in "$CERTS_DIR/client.csr" \
  -CA "$CERTS_DIR/ca.pem" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial \
  -out "$CERTS_DIR/client.pem" -days "$DAYS"

rm -f "$CERTS_DIR"/*.csr "$CERTS_DIR"/*.srl

echo ""
echo "Certificates generated in $CERTS_DIR/"
echo "  CA:     $CERTS_DIR/ca.pem"
echo "  Server: $CERTS_DIR/server.pem + $CERTS_DIR/server.key"
echo "  Client: $CERTS_DIR/client.pem + $CERTS_DIR/client.key"
