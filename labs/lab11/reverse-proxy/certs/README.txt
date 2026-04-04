Generate localhost TLS material before first `docker compose up` (not committed — secret scanners flag private keys).

From repo root, PowerShell:

  docker run --rm -v "${PWD}/labs/lab11/reverse-proxy/certs:/certs" alpine:latest sh -c "apk add --no-cache openssl && openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /certs/localhost.key -out /certs/localhost.crt -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'"

