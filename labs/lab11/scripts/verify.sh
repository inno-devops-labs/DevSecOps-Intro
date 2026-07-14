#!/usr/bin/env bash
set -euo pipefail

LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RESULTS_DIR="${LAB_DIR}/results"
CERTS_DIR="${LAB_DIR}/reverse-proxy/certs"
COMPOSE=(docker compose -f "${LAB_DIR}/docker-compose.yml" -f "${LAB_DIR}/waf/docker-compose.override.yml")

mkdir -p "${RESULTS_DIR}"

if [[ ! -s "${CERTS_DIR}/localhost.crt" || ! -s "${CERTS_DIR}/localhost.key" ]]; then
  mkdir -p "${CERTS_DIR}"
  openssl req -x509 -nodes -newkey rsa:4096 -sha256 \
    -keyout "${CERTS_DIR}/localhost.key" \
    -out "${CERTS_DIR}/localhost.crt" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:juice.local,IP:127.0.0.1" \
    -days 3650 >/dev/null 2>&1
  chmod 0600 "${CERTS_DIR}/localhost.key"
fi

wait_for_url() {
  local url=$1
  local attempts=${2:-60}
  local i

  for ((i = 1; i <= attempts; i++)); do
    if curl -skf "${url}" >/dev/null; then
      return 0
    fi
    sleep 2
  done

  echo "Timed out waiting for ${url}" >&2
  return 1
}

"${COMPOSE[@]}" up -d
wait_for_url "https://localhost/rest/admin/application-version"
wait_for_url "https://localhost:8443/rest/admin/application-version" 90

"${COMPOSE[@]}" ps >"${RESULTS_DIR}/stack.txt"
"${COMPOSE[@]}" exec -T nginx nginx -t \
  >"${RESULTS_DIR}/nginx-test.txt" 2>&1

# Task 1: redirect, protocol negotiation, and response headers.
curl -sS -D - -o /dev/null http://localhost \
  | tr -d '\r' >"${RESULTS_DIR}/http-redirect.txt"

openssl s_client -connect localhost:443 -servername localhost -tls1_3 -brief \
  </dev/null >"${RESULTS_DIR}/tls13.txt" 2>&1

if openssl s_client -connect localhost:443 -servername localhost -tls1_2 -brief \
  </dev/null >"${RESULTS_DIR}/tls12-rejected.txt" 2>&1; then
  echo "ERROR: TLS 1.2 was accepted" >&2
  exit 1
fi

curl -skS -D - -o /dev/null https://localhost \
  | tr -d '\r' >"${RESULTS_DIR}/headers.txt"

# Task 2: TLS parameters and rate limiting.
openssl s_client -connect localhost:443 -servername localhost -tls1_3 \
  </dev/null 2>&1 \
  | grep -E "New, TLS|Cipher is|Server Temp Key|Peer Temp Key" \
  >"${RESULTS_DIR}/cipher.txt"

seq 1 60 \
  | xargs -P 30 -I '{}' curl -skS -o /dev/null -w '%{http_code}\n' \
      -H 'Content-Type: application/json' \
      --data '{"email":"lab11@example.invalid","password":"invalid"}' \
      https://localhost/rest/user/login \
  | sort \
  | uniq -c \
  >"${RESULTS_DIR}/ratelimit.txt"

# Keep a TLS connection open after sending an incomplete header and wait for
# nginx to close it. A FIFO keeps stdin open without delaying process exit.
TIMEOUT_DIR=$(mktemp -d)
TIMEOUT_FIFO="${TIMEOUT_DIR}/request.fifo"
TIMEOUT_RAW="${TIMEOUT_DIR}/openssl.txt"
mkfifo "${TIMEOUT_FIFO}"
openssl s_client -quiet -connect localhost:443 -servername localhost \
  <"${TIMEOUT_FIFO}" >"${TIMEOUT_RAW}" 2>&1 &
TIMEOUT_PID=$!
exec 3>"${TIMEOUT_FIFO}"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ' >&3
TIMEOUT_START=$(date +%s)
(sleep 15; kill "${TIMEOUT_PID}" 2>/dev/null || true) &
TIMEOUT_WATCHDOG_PID=$!
wait "${TIMEOUT_PID}" || true
TIMEOUT_END=$(date +%s)
kill "${TIMEOUT_WATCHDOG_PID}" 2>/dev/null || true
wait "${TIMEOUT_WATCHDOG_PID}" 2>/dev/null || true
exec 3>&-
{
  echo "configured client_header_timeout: 10s"
  echo "observed connection lifetime: $((TIMEOUT_END - TIMEOUT_START))s"
  echo "result: nginx closed TLS connection before the incomplete header was finished"
  tr -d '\r' <"${TIMEOUT_RAW}"
} >"${RESULTS_DIR}/timeout.txt"
rm -f "${TIMEOUT_FIFO}" "${TIMEOUT_RAW}"
rmdir "${TIMEOUT_DIR}"

# Bonus: exactly the same SQLi probe, first directly and then through WAF.
# This variant returns 200 from Juice Shop but reaches CRS's blocking threshold.
PAYLOAD_PATH='/rest/products/search?q=1%27%20OR%20%271%27%3D%271'
curl -skS -o /dev/null -w 'no-waf: HTTP %{http_code}\n' \
  "https://localhost${PAYLOAD_PATH}" >"${RESULTS_DIR}/waf-baseline.txt"
curl -skS -o /dev/null -w 'with-waf: HTTP %{http_code}\n' \
  "https://localhost:8443${PAYLOAD_PATH}" >"${RESULTS_DIR}/waf-blocked.txt"

"${COMPOSE[@]}" exec -T waf sh -c \
  'tail -n 1 /var/log/modsec/audit.log' >"${RESULTS_DIR}/waf-audit.json"

jq '{
  transaction: {
    request: .transaction.request,
    response: .transaction.response,
    messages: [.transaction.messages[] | {
      message: .message,
      rule_id: .details.ruleId,
      data: .details.data,
      severity: .details.severity,
      tags: .details.tags
    }]
  }
}' "${RESULTS_DIR}/waf-audit.json" >"${RESULTS_DIR}/waf-audit.txt"

echo "Verification complete. Results: ${RESULTS_DIR}"
