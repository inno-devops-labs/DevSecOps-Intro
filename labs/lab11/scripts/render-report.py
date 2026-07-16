#!/usr/bin/env python3
from pathlib import Path
import re

lab = Path(__file__).resolve().parents[1]
root = lab.parents[1]
results = lab / "results"
out = root / "submissions" / "lab11.md"
nginx_conf = (lab / "reverse-proxy" / "nginx.conf").read_text(encoding="utf-8")

def read(name: str) -> str:
    path = results / name
    if not path.exists() or not path.read_text(encoding="utf-8", errors="replace").strip():
        return f"NOT COLLECTED — run `bash labs/lab11/scripts/run-lab.sh` to create `{name}`."
    return path.read_text(encoding="utf-8", errors="replace").strip()

def fence(text: str, lang: str = "text") -> str:
    return f"```{lang}\n{text}\n```"

rate = read("ratelimit.txt")
counts = {"2xx": 0, "4xx-other": 0, "429": 0, "5xx": 0}
if "NOT COLLECTED" not in rate:
    for line in rate.splitlines():
        m = re.match(r"\s*(\d+)\s+(\d{3})\s*$", line)
        if not m:
            continue
        count, code = int(m.group(1)), int(m.group(2))
        if code == 429:
            counts["429"] += count
        elif 200 <= code < 300:
            counts["2xx"] += count
        elif 400 <= code < 500:
            counts["4xx-other"] += count
        elif 500 <= code < 600:
            counts["5xx"] += count

rate_table = (
    "| HTTP class/code | Count out of 60 |\n"
    "|-----------------|----------------:|\n"
    f"| 2xx | {counts['2xx'] if 'NOT COLLECTED' not in rate else 'TBD'} |\n"
    f"| 429 | {counts['429'] if 'NOT COLLECTED' not in rate else 'TBD'} |\n"
    f"| Other 4xx | {counts['4xx-other'] if 'NOT COLLECTED' not in rate else 'TBD'} |\n"
    f"| 5xx | {counts['5xx'] if 'NOT COLLECTED' not in rate else 'TBD'} |"
)

report = f'''# Lab 11 — BONUS — Submission

> Evidence blocks in this file are generated from `labs/lab11/results/` by
> `bash labs/lab11/scripts/run-lab.sh`. A block marked **NOT COLLECTED** must be
> regenerated on the machine used for submission.

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

{fence(nginx_conf, "nginx")}

### A. HTTPS redirect proof

{fence(read("http-redirect.txt"))}

The lab stack publishes Nginx on host ports `8080` and `8443`; therefore the redirect target uses `https://localhost:8443` rather than privileged host port 443.

### B. TLS 1.3 proof

{fence(read("tls13.txt"))}

### C. Security headers proof

{fence(read("headers.txt"))}

### What each header defends against

- **HSTS:** Forces supported browsers to use HTTPS for the configured lifetime, reducing protocol-downgrade and SSL-stripping opportunities after the first trusted visit.
- **X-Content-Type-Options: nosniff:** Stops browsers from reinterpreting a response as a different MIME type, which limits content-sniffing attacks.
- **X-Frame-Options: DENY:** Prevents the application from being embedded in frames and protects users from clickjacking overlays.
- **Referrer-Policy:** Restricts how much URL information is sent in the `Referer` header when users navigate to another origin.
- **Permissions-Policy:** Disables camera, microphone and geolocation access for this origin unless the policy is deliberately changed.
- **Content-Security-Policy-Report-Only:** Evaluates a restrictive resource-loading policy and reports violations without immediately breaking the Juice Shop frontend during the tuning phase.

## Task 2: Production Posture

### Rate limit proof

{rate_table}

Raw command output:

{fence(rate)}

The login route is limited to 10 requests per minute per client address with a burst allowance of five requests. Rejected requests use HTTP `429` instead of the Nginx default `503`.

### Timeout enforced

{fence(read("timeout.txt"))}

The test opens a real TLS connection, sends an incomplete HTTP header and waits. Nginx closes the connection when `client_header_timeout 10s` expires.

### Cipher hardening

{fence(read("cipher.txt"))}

TLS is restricted to version 1.3. The accepted TLS 1.3 suites are configured with `ssl_conf_command Ciphersuites`, because current Nginx/OpenSSL builds do not use `ssl_ciphers` to select TLS 1.3 suites. The preferred key-exchange curve is X25519, with secp384r1 retained as a fallback.

### Cert rotation runbook (7 steps)

1. **Detect expiry:** Monitor the certificate `notAfter` date with an automated check and alert before the renewal window, for example at 30, 14 and 7 days remaining.
2. **Order new cert:** Request a replacement from the approved CA or ACME service using the existing domain set and an authorized account.
3. **Validate:** Verify the certificate chain, SAN entries, private-key match and expiry dates in a staging path before deployment.
4. **Atomic swap:** Write the new certificate and key to versioned files, update symlinks atomically, run `nginx -t`, and reload Nginx without stopping active connections.
5. **Verify:** Confirm the served certificate, TLS 1.3 negotiation, security headers and application health from an external client.
6. **Rollback plan:** Keep the previous known-good certificate and key available so the symlinks can be restored and Nginx reloaded immediately if validation fails.
7. **Audit:** Record the requester, CA order identifier, certificate fingerprint, deployment time, validation evidence and any rollback action in the change log.

### What OCSP stapling buys you

OCSP stapling allows a production server to attach a recent CA-signed revocation response to the TLS handshake, reducing client-side latency and avoiding a separate privacy-leaking request to the CA responder. It is not useful for this lab certificate because the certificate is self-signed and has no public CA OCSP responder or verifiable chain.

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- WAF used: ModSecurity v3 with the official OWASP CRS Nginx container
- OWASP CRS version: `4.28.0`
- Container tag: `4.28.0-nginx-alpine-202607100407`
- Paranoia level: `1`
- Public lab endpoint: `https://localhost:9443`
- Backend: hardened Nginx at `https://nginx:8443`
- Rule engine: blocking mode (`On`)
- Audit log: `/var/log/modsec/audit.log`

ModSecurity v3 was selected instead of Coraza because the course explicitly accepts either implementation and the official CRS container provides a direct, reproducible reverse-proxy setup with mature documentation and audit logging.

### Attack payload sent

`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)

{fence(read("no-waf.txt"))}

### After WAF

{fence(read("with-waf.txt"))}

### Audit log excerpt

{fence(read("waf-audit.txt"))}

Expected SQL-injection detections are in the CRS `942xxx` family. The exact rule ID must be taken from the generated audit log rather than assumed in advance.

### Tradeoff analysis

The WAF adds runtime inspection for malicious request patterns that can still reach a deployed service despite SAST, DAST and policy gates. This introduces tuning work, false-positive risk, extra latency, additional certificate and configuration ownership, and more logs to operate. I would avoid a WAF when the service has no HTTP attack surface, when equivalent controls already exist in a managed ingress, or when the team cannot monitor and tune blocking decisions safely.

## Files created

- `labs/lab11/docker-compose.yml`
- `labs/lab11/reverse-proxy/nginx.conf`
- `labs/lab11/scripts/generate-certs.sh`
- `labs/lab11/scripts/run-lab.sh`
- `labs/lab11/scripts/slow-header-test.py`
- `labs/lab11/scripts/render-report.py`
- `labs/lab11/waf/docker-compose.override.yml`
- `labs/lab11/results/*`
- `submissions/lab11.md`
'''
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(report, encoding="utf-8")
print(f"Rendered {out}")
