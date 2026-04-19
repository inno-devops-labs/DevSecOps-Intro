#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker command is not available. Install Docker and ensure the daemon is running." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running or not accessible. Start Docker Desktop or the Docker daemon." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYSIS_DIR="$ROOT_DIR/analysis"
LOG_DIR="$ROOT_DIR/logs"
HTTP_TARGET="127.0.0.1:8080"
HTTPS_TARGET="127.0.0.1:8443"

run_testssl() {
  local attempt
  local tmp_output
  local -a docker_args
  local target

  tmp_output="$(mktemp)"

  for attempt in 1 2 3 4 5; do
    docker_args=(--rm)

    if [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]]; then
      docker_args+=(--platform linux/amd64)
    fi

    if [[ "$(uname -s)" == "Linux" ]]; then
      docker_args+=(--network host)
      target="https://localhost:8443"
    else
      target="https://host.docker.internal:8443"
    fi

    if docker run "${docker_args[@]}" drwetter/testssl.sh:latest "$target" > "$tmp_output" 2>&1 \
      && grep -q 'Overall Grade' "$tmp_output"; then
      mv "$tmp_output" "$ANALYSIS_DIR/testssl.txt"
      return 0
    fi

    sleep 5
  done

  mv "$tmp_output" "$ANALYSIS_DIR/testssl.txt"
  return 1
}

mkdir -p "$ANALYSIS_DIR" "$LOG_DIR" "$ROOT_DIR/reverse-proxy/certs"

"$ROOT_DIR/generate-certs.sh"

: > "$LOG_DIR/access.log"
: > "$LOG_DIR/error.log"

cd "$ROOT_DIR"

docker compose down --remove-orphans
docker compose up -d

juice_id="$(docker compose ps -q juice)"
nginx_id="$(docker compose ps -q nginx)"

for _ in $(seq 1 60); do
  juice_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$juice_id" 2>/dev/null || true)"
  nginx_state="$(docker inspect -f '{{.State.Status}}' "$nginx_id" 2>/dev/null || true)"

  if [[ "$juice_health" == "healthy" && "$nginx_state" == "running" ]]; then
    break
  fi

  sleep 1
done

juice_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$juice_id")"
nginx_state="$(docker inspect -f '{{.State.Status}}' "$nginx_id")"

if [[ "$juice_health" != "healthy" || "$nginx_state" != "running" ]]; then
  echo "Stack did not become ready. juice=$juice_health nginx=$nginx_state" >&2
  docker compose ps >&2
  exit 1
fi

for _ in $(seq 1 10); do
  if curl -skI "https://$HTTPS_TARGET/" > /dev/null; then
    break
  fi
  sleep 1
done

docker compose config > "$ANALYSIS_DIR/docker-compose-config.txt"
docker compose ps > "$ANALYSIS_DIR/docker-compose-ps.txt"

curl -sI "http://$HTTP_TARGET/" > "$ANALYSIS_DIR/headers-http.txt"
curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://$HTTP_TARGET/" > "$ANALYSIS_DIR/http-redirect.txt"
curl -s -o /dev/null -w "%{http_code}\n" "http://$HTTP_TARGET/" > "$ANALYSIS_DIR/http-redirect-code.txt"
curl -skI "https://$HTTPS_TARGET/" > "$ANALYSIS_DIR/headers-https.txt"
curl -sI -H 'Host: attacker.invalid' "http://$HTTP_TARGET/" > "$ANALYSIS_DIR/host-header-redirect-check.txt"

{
  if grep -qi '^strict-transport-security:' "$ANALYSIS_DIR/headers-http.txt"; then
    echo "HTTP HSTS present: yes"
  else
    echo "HTTP HSTS present: no"
  fi

  if grep -qi '^strict-transport-security:' "$ANALYSIS_DIR/headers-https.txt"; then
    echo "HTTPS HSTS present: yes"
  else
    echo "HTTPS HSTS present: no"
  fi
} > "$ANALYSIS_DIR/hsts-check.txt"

if ! run_testssl; then
  echo "testssl.sh did not produce a usable scan" >&2
  tail -n 20 "$ANALYSIS_DIR/testssl.txt" >&2 || true
  exit 1
fi

perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$ANALYSIS_DIR/testssl.txt" \
  | sed '/^WARNING: The requested image'\''s platform /d' \
  > "$ANALYSIS_DIR/testssl-clean.txt"
openssl x509 -in "$ROOT_DIR/reverse-proxy/certs/localhost.crt" -text -noout > "$ANALYSIS_DIR/cert-details.txt"

for _ in $(seq 1 12); do
  curl -sk -o /dev/null -w '%{http_code}\n' \
    -H 'Content-Type: application/json' \
    -X POST "https://$HTTPS_TARGET/rest/user/login" \
    -d '{"email":"a@a","password":"a"}'
done > "$ANALYSIS_DIR/rate-limit-test.txt"

sort "$ANALYSIS_DIR/rate-limit-test.txt" | uniq -c | awk '{print $2 " x " $1}' > "$ANALYSIS_DIR/rate-limit-counts.txt"
sleep 1
grep 'POST /rest/user/login' "$LOG_DIR/access.log" > "$ANALYSIS_DIR/access-log-login-tail.txt" || true
grep '"POST /rest/user/login HTTP' "$LOG_DIR/access.log" | grep ' 429 ' > "$ANALYSIS_DIR/access-429.txt" || true
cp "$ANALYSIS_DIR/access-429.txt" "$ANALYSIS_DIR/access-429-snippets.txt"
grep 'limiting requests' "$LOG_DIR/error.log" > "$ANALYSIS_DIR/rate-limit-warnings.txt" || true
tail -n 20 "$LOG_DIR/error.log" > "$ANALYSIS_DIR/rate-limit-errors.txt"
tail -n 20 "$LOG_DIR/access.log" > "$ANALYSIS_DIR/rate-limit-log-batch.txt"

{
  echo "HTTP redirect:"
  cat "$ANALYSIS_DIR/http-redirect.txt"
  echo
  echo "HSTS check:"
  cat "$ANALYSIS_DIR/hsts-check.txt"
  echo
  echo "Rate-limit counts:"
  cat "$ANALYSIS_DIR/rate-limit-counts.txt"
} > "$ANALYSIS_DIR/rate-limit-summary.txt"

echo "Evidence refreshed in $ANALYSIS_DIR"
