#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(cd "$LAB_DIR/../.." && pwd)"
RESULTS="$LAB_DIR/results"
BASE=(-f "$LAB_DIR/docker-compose.yml")
FULL=(-f "$LAB_DIR/docker-compose.yml" -f "$LAB_DIR/waf/docker-compose.override.yml")

mkdir -p "$RESULTS" "$LAB_DIR/logs" "$LAB_DIR/waf/logs"
touch "$LAB_DIR/waf/logs/audit.log" "$LAB_DIR/waf/logs/error.log"

command -v docker >/dev/null || { echo "Docker is required." >&2; exit 1; }
docker compose version

if [[ ! -s "$LAB_DIR/reverse-proxy/certs/localhost.crt" || ! -s "$LAB_DIR/reverse-proxy/certs/localhost.key" ]]; then
  bash "$LAB_DIR/scripts/generate-certs.sh"
fi

cleanup() {
  if [[ "${KEEP_STACK:-0}" != "1" ]]; then
    docker compose "${FULL[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[1/7] Starting Juice Shop and hardened Nginx..."
docker compose "${BASE[@]}" up -d

echo "[2/7] Waiting for Juice Shop through Nginx..."
for _ in $(seq 1 90); do
  if curl -skf https://localhost:8443/rest/admin/application-version >/dev/null; then
    break
  fi
  sleep 2
done
curl -skf https://localhost:8443/rest/admin/application-version >/dev/null

echo "[3/7] Collecting redirect, TLS and header evidence..."
curl -sI http://localhost:8080 | tee "$RESULTS/http-redirect.txt"
echo | openssl s_client -connect localhost:8443 -servername localhost -tls1_3 -brief 2>&1 \
  | head -12 | tee "$RESULTS/tls13.txt"
curl -skI https://localhost:8443 | tee "$RESULTS/headers.txt"

echo "[4/7] Exercising login rate limit..."
seq 1 60 | xargs -P 30 -I{} curl -sk \
  -X POST \
  -H 'Content-Type: application/json' \
  --data '{"email":"nobody@example.invalid","password":"invalid"}' \
  -o /dev/null -w '%{http_code}\n' \
  https://localhost:8443/rest/user/login 2>/dev/null \
  | sort | uniq -c | tee "$RESULTS/ratelimit.txt"

echo "[5/7] Checking slow-header timeout and negotiated cipher..."
python3 "$LAB_DIR/scripts/slow-header-test.py" | tee "$RESULTS/timeout.txt"
echo | openssl s_client -connect localhost:8443 -servername localhost -tls1_3 -brief 2>&1 \
  | grep -E 'Protocol version|Ciphersuite|Peer Temp Key|Server Temp Key' \
  | tee "$RESULTS/cipher.txt"

echo "[6/7] Starting WAF and probing SQL injection pattern..."
docker compose "${FULL[@]}" up -d
for _ in $(seq 1 90); do
  if curl -sk https://localhost:9443/ >/dev/null; then
    break
  fi
  sleep 2
done

PAYLOAD="https://localhost:8443/rest/products/search?q='%20OR%201=1--"
WAF_PAYLOAD="https://localhost:9443/rest/products/search?q='%20OR%201=1--"
curl -sk -o /dev/null -w 'no-waf: HTTP %{http_code}\n' "$PAYLOAD" | tee "$RESULTS/no-waf.txt"
curl -sk -o /dev/null -w 'with-waf: HTTP %{http_code}\n' "$WAF_PAYLOAD" | tee "$RESULTS/with-waf.txt"

sleep 2
if [[ -s "$LAB_DIR/waf/logs/audit.log" ]]; then
  tail -80 "$LAB_DIR/waf/logs/audit.log" > "$RESULTS/waf-audit.txt"
else
  docker compose "${FULL[@]}" exec -T waf sh -c 'cat /var/log/modsec/audit.log 2>/dev/null || true' \
    | tail -80 > "$RESULTS/waf-audit.txt"
fi

echo "[7/7] Rendering submissions/lab11.md from collected evidence..."
python3 "$LAB_DIR/scripts/render-report.py"

echo
echo "Completed. Report: $ROOT_DIR/submissions/lab11.md"
echo "Results: $RESULTS"
if [[ "${KEEP_STACK:-0}" == "1" ]]; then
  echo "KEEP_STACK=1: containers remain running."
fi
