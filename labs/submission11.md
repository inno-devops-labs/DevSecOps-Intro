# Lab 11 Submission — Nginx Reverse Proxy Hardening (Juice Shop)

## Task 1 — Reverse proxy Compose setup

### Why a reverse proxy helps security

A reverse proxy sits in front of the application and becomes the **single network entry point**. It can terminate **TLS**, inject **security headers**, enforce **rate limits** and **timeouts**, normalize logging, and hide backend topology. The app no longer needs to listen on host-facing ports, which reduces direct exposure and lets operators enforce policy in one place without changing application code.

### Why hiding direct app ports reduces attack surface

If Juice Shop published **3000/tcp** on the host, attackers could bypass the proxy’s headers, TLS policy, and rate limits by talking to the app directly. Keeping the app on an **internal Docker network** and exposing only Nginx (**8080** / **8443**) forces all browser and API traffic through the hardened path.

### Compose port exposure (evidence)

Saved output: [`labs/lab11/analysis/compose-ps.txt`](lab11/analysis/compose-ps.txt).

```text
NAME            IMAGE                           ...   PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   ...   3000/tcp
lab11-nginx-1   nginx:stable-alpine             ...   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

Only **nginx** publishes host ports; **juice** shows `3000/tcp` with **no** `0.0.0.0:` mapping.

### HTTP → HTTPS redirect

[`labs/lab11/analysis/http-redirect-code.txt`](lab11/analysis/http-redirect-code.txt): `HTTP 308` for `http://127.0.0.1:8080/` (permanent redirect to HTTPS).

### Local environment note (SELinux)

On **Fedora** with SELinux **Enforcing**, bind mounts needed the **`:Z`** volume option in [`labs/lab11/docker-compose.yml`](lab11/docker-compose.yml) so the Nginx process could read the config, certificates, and write logs. Generated TLS material under `reverse-proxy/certs/` is listed in [`labs/lab11/.gitignore`](lab11/.gitignore) so private keys are not committed.

---

## Task 2 — Security headers

### Headers from HTTPS (excerpt)

Full captures: [`labs/lab11/analysis/headers-http.txt`](lab11/analysis/headers-http.txt), [`labs/lab11/analysis/headers-https.txt`](lab11/analysis/headers-https.txt).

Relevant lines from **HTTPS** (`curl -skI https://127.0.0.1:8443/`):

```text
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header protects against

| Header | Role |
| ------ | ---- |
| **X-Frame-Options** | Stops the site being embedded in frames/iframes on other origins, reducing **clickjacking** risk. |
| **X-Content-Type-Options** | Tells browsers not to **MIME-sniff** responses into executable types, which helps prevent some content-confusion attacks. |
| **Strict-Transport-Security (HSTS)** | Instructs browsers to use **HTTPS only** for the host (and optionally subdomains) for `max-age`, shrinking **sslstrip** / mixed-content downgrade windows. |
| **Referrer-Policy** | Limits how much **URL/leakage** goes in the `Referer` header on cross-origin navigations (here: send full URL for same-origin, origin-only for HTTPS→HTTPS cross-origin, none for downgrades). |
| **Permissions-Policy** | Disables powerful features (**camera**, **geolocation**, **microphone**) for this document, reducing abuse if XSS or third-party content slips in. |
| **COOP / CORP** | **Cross-Origin-Opener-Policy: same-origin** isolates the browsing context from cross-origin documents; **Cross-Origin-Resource-Policy: same-origin** signals the resource should not be loaded cross-origin—both reduce **cross-origin data leak** and some **Spectre**-class interaction surfaces. |
| **CSP-Report-Only** | Evaluates a **Content Security Policy** without enforcing it, reporting violations only—useful for a JS-heavy app like Juice Shop so you can tune policy before enforcement. |

### HSTS only on HTTPS

The **HTTP** response on port **8080** is a **308** redirect and includes the non-HSTS security headers, but **no** `Strict-Transport-Security` line (see `headers-http.txt`). **HSTS** appears only on **HTTPS** (`headers-https.txt`), which matches the lab guidance: do not advertise HSTS on cleartext responses.

---

## Task 3 — TLS, HSTS, rate limiting, and timeouts

### TLS / testssl.sh summary

Full scan: [`labs/lab11/analysis/testssl.txt`](lab11/analysis/testssl.txt) (target `https://127.0.0.1:8443` via `docker run --rm --network host drwetter/testssl.sh:latest`).

- **Protocols:** **SSLv2/SSLv3/TLS 1.0/TLS 1.1** not offered; **TLS 1.2** and **TLS 1.3** offered (TLS 1.3 marked final). **ALPN** offers **h2** and **http/1.1**.
- **Cipher preferences (examples):** TLS 1.3 suites include **TLS_AES_256_GCM_SHA384**, **TLS_CHACHA20_POLY1305_SHA256**, **TLS_AES_128_GCM_SHA256**; TLS 1.2 includes **ECDHE-RSA-AES256-GCM-SHA384** and **ECDHE-RSA-AES128-GCM-SHA256**. **Forward secrecy** (AEAD / ECDHE) is offered; NULL/anon/export/weak categories are not offered.
- **Why TLS 1.2+:** Older protocols have known design and implementation weaknesses; **TLS 1.2** is the modern baseline, and **TLS 1.3** removes obsolete primitives and improves handshake security and performance. This stack offers both, with 1.3 preferred.
- **Warnings / “NOT ok” (expected for local self-signed):** **Chain of trust not ok (self signed)**; **OCSP/CRL** not present; **OCSP stapling** not offered; **Certificate Transparency** / **DNS CAA** not applicable as in production; experimental **overall grade T** capped due to trust chain. Named **CVE** checks (e.g. Heartbleed, ROBOT, POODLE, SWEET32, LOGJAM, BEAST, RC4) reported **not vulnerable** or not applicable for this configuration.

### Rate limiting

Test script output: [`labs/lab11/analysis/rate-limit-test.txt`](lab11/analysis/rate-limit-test.txt).

- **Observed:** Requests **1–6** returned **401** (invalid credentials, upstream reached); requests **7–12** returned **429** (Nginx `limit_req`).

Configuration in [`labs/lab11/reverse-proxy/nginx.conf`](lab11/reverse-proxy/nginx.conf): `limit_req_zone ... rate=10r/m` and `limit_req zone=login burst=5 nodelay` on `location = /rest/user/login`. That allows a **short burst** (legitimate retries or a few parallel tabs) while capping sustained attempts to about **10 per minute per IP**, which slows **credential stuffing** without blocking normal users outright. Tuning would consider shared NAT, mobile carriers, and API clients.

**Access log lines (429):** [`labs/lab11/analysis/access-log-429.txt`](lab11/analysis/access-log-429.txt) (excerpt from [`labs/lab11/logs/access.log`](lab11/logs/access.log)).

### Timeouts (from `nginx.conf`) and trade-offs

| Setting | Value | Trade-off |
| ------- | ----- | --------- |
| `client_body_timeout` | **10s** | Closes slow uploads of request bodies—mitigates some **slow body** DoS patterns; too low can harm large uploads (mitigated here by `client_max_body_size 2m`). |
| `client_header_timeout` | **10s** | Limits time to send headers—reduces **slowloris**-style header stalls; very low values can hurt high-latency clients. |
| `proxy_read_timeout` | **30s** | Max wait for **upstream response**; protects against hung backends but may truncate legitimately slow operations. |
| `proxy_send_timeout` | **30s** | Max time to **send** a request to upstream; similar balance for slow clients talking to the proxy. |
| `proxy_connect_timeout` | **5s** | Fails fast if the app is unreachable—good for resilience; may need raising on cold starts or distant upstreams. |
| `send_timeout` | **10s** | Limits sending a response to a slow client—reduces resource pinning by **slow readers**. |

Shorter timeouts improve **resource recovery** under abuse; longer timeouts improve **compatibility** on poor networks and for slow endpoints. This profile targets a lab/demo app with modest payloads.

---

## Artifacts checklist

| Artifact | Path |
| -------- | ---- |
| Compose `ps` | `labs/lab11/analysis/compose-ps.txt` |
| HTTP redirect code | `labs/lab11/analysis/http-redirect-code.txt` |
| Headers (HTTP / HTTPS) | `labs/lab11/analysis/headers-http.txt`, `headers-https.txt` |
| testssl.sh | `labs/lab11/analysis/testssl.txt` |
| Rate-limit run | `labs/lab11/analysis/rate-limit-test.txt` |
| 429 log excerpt | `labs/lab11/analysis/access-log-429.txt` |

After capturing evidence, the stack was stopped with `docker compose down` under `labs/lab11` per lab cleanup (re-run `docker compose up -d` to reproduce).
