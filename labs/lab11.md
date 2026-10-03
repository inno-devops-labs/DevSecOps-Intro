# Lab 11 — Edge Hardening with a Reverse Proxy

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Edge%20Hardening-blue)
![points](https://img.shields.io/badge/points-10-orange)
![tech](https://img.shields.io/badge/tech-Nginx%20%2B%20TLS%20%2B%20WAF-informational)

> **Goal:** Put a hardened reverse proxy in front of Juice Shop, prove each control with a command rather than a screenshot, and add a web application firewall that blocks something the proxy happily forwards.
> **Deliverable:** A PR from `feature/lab11` with `submissions/lab11.md` and your `nginx.conf`. Submit the PR link via Moodle.
> **Bonus lab:** 4 + 4 + 2 points. Reading 11 covers the theory.

## Setup

- Docker Compose, `curl`, `openssl`.

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab11
```

```bash
mkdir -p labs/lab11/reverse-proxy/certs labs/lab11/logs labs/lab11/results
openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
  -keyout labs/lab11/reverse-proxy/certs/localhost.key \
  -out labs/lab11/reverse-proxy/certs/localhost.crt \
  -subj '/CN=localhost'
chmod 644 labs/lab11/reverse-proxy/certs/localhost.*
```

The file names matter: the shipped `nginx.conf` reads `localhost.crt` and `localhost.key` from `/etc/nginx/certs/`. The certificate is self-signed, so every `curl` below needs `-k`.

Provided: `labs/lab11/docker-compose.yml` (Juice Shop with no published port, plus Nginx on 80 and 443) and `labs/lab11/reverse-proxy/nginx.conf`, the starter you harden.

## Task 1 — TLS and headers (4 pts)

### 11.1 Harden the proxy

```nginx
# labs/lab11/reverse-proxy/nginx.conf
# YOUR TASK: TLS and response headers
# Requirements:
#   - port 80 redirects every request to HTTPS with a permanent redirect
#   - TLS 1.2 and 1.3 only; no TLS 1.0 or 1.1
#   - six headers, each with `always` so they survive error responses:
#     Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options,
#     Referrer-Policy, Permissions-Policy, Content-Security-Policy-Report-Only
#   - proxy to the juice service on port 3000, passing the real client address
# Hints:
#   - Reading 11 explains what each header does and why Report-Only comes first
#   - the starter already has most of the structure; read it before editing
```

### 11.2 Bring it up

```bash
cd labs/lab11 && docker compose up -d && cd -
until curl -sk -o /dev/null https://localhost/rest/admin/application-version; do sleep 2; done
docker compose -f labs/lab11/docker-compose.yml ps
```

### 11.3 Prove each control

```bash
curl -sI http://localhost | tee labs/lab11/results/http-redirect.txt | head -2

echo | openssl s_client -connect localhost:443 -tls1_3 -brief 2>&1 \
  | grep -E 'Protocol|Ciphersuite' | tee labs/lab11/results/tls13.txt

curl -skI https://localhost | tee labs/lab11/results/headers.txt \
  | grep -iE 'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|content-security'
```

To show what the server offers rather than what your client is willing to speak, enumerate it:

```bash
docker run --rm --network host drwetter/testssl.sh:3.2 --protocols --color 0 \
  https://localhost | tee labs/lab11/results/protocols.txt
```

`openssl s_client -tls1_1` is not a test of your server. OpenSSL 3 refuses TLS 1.1 locally with `no protocols available` and never sends a packet, so you learn nothing about the far end. A scanner that carries its own TLS stack does.

**Submit** in `submissions/lab11.md`, section `## Task 1`:

- The redirect status code and why you chose 301 or 308.
- The protocol and cipher suite negotiated on a TLS 1.3 connection, and the protocol table from the scanner showing which versions the server offers.
- All six headers as returned by the server.
- Three or four sentences: you set `Content-Security-Policy-Report-Only` rather than enforcing. What would break if you enforced it today against Juice Shop, and what is the process for getting to enforcement?

## Task 2 — Availability controls (4 pts)

### 11.4 Rate limits and timeouts

```nginx
# YOUR TASK: extend nginx.conf
# Requirements:
#   - a rate limit that applies to the login endpoint specifically, not the whole site
#   - requests over the limit answer 429, not the nginx default 503
#   - a connection limit per client address
#   - proxy read, connect and send timeouts set explicitly
#   - TLS 1.3 cipher suites restricted to AES-GCM
# Hints:
#   - limit_req_zone goes in the http block, limit_req in the location block
#   - ssl_ciphers does NOT configure TLS 1.3. For 1.3 the directive is
#     `ssl_conf_command Ciphersuites ...` (nginx 1.19.4+, OpenSSL 1.1.1+).
#     nginx accepts TLS_AES_* names in ssl_ciphers and silently ignores them
```

### 11.5 Prove the limit bites

```bash
for i in $(seq 1 14); do
  curl -sk -o /dev/null -w '%{http_code} ' -X POST https://localhost/rest/user/login \
    -H 'Content-Type: application/json' -d '{"email":"a@b.c","password":"x"}'
done; echo
```

<!-- verify:skip only fails once the student has restricted the 1.3 suites -->
```bash
echo | openssl s_client -connect localhost:443 -tls1_3 \
  -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -icE 'alert|failure'
```

The first few requests reach Juice Shop and get a 401; then the limit takes over and returns 429. The second command must fail: `-ciphersuites` is how you name a TLS 1.3 suite. `-cipher` with a `TLS_AES_*` name gives `no cipher match` from OpenSSL itself before it ever talks to your server, which is a test bug, not a finding.

**Submit**, section `## Task 2`:

- The sequence of status codes, and the exact rate and burst you configured.
- Your cipher configuration and the proof that a suite outside it is refused.
- Your timeout values, with a sentence on what each one protects against, and one command that shows a timeout actually firing rather than just being configured.
- Two or three sentences on OCSP stapling: what it saves the client, and why you would or would not enable it here.
- A cert rotation runbook: the steps, in order, to replace the certificate with zero failed requests. Include how you verify the new one is live.
- Three or four sentences: your rate limit is per client address. Name two ways an attacker gets around that, and what you would add at this layer or above it.

## Bonus — A WAF that catches what the proxy forwards (2 pts)

Nginx forwards `?q=' OR 1=1--` without comment. A WAF with the OWASP Core Rule Set does not.

```yaml
# labs/lab11/waf/docker-compose.override.yml
# YOUR TASK: put a CRS-enabled WAF in front of the app
# Requirements:
#   - a WAF container in the same compose project, published on a different port
#     than the plain proxy so you can compare them side by side
#   - OWASP CRS active in blocking mode
#   - the app itself must not be reachable from outside except through a proxy
# Hints:
#   - owasp/modsecurity-crs:nginx takes BACKEND and PORT env vars and ships CRS 4
#   - Coraza is the Go alternative if you prefer it; the CRS rules are the same
#   - blocking mode versus detection-only is one environment variable
```

**Submit**, section `## Bonus`:

- The same request through the plain proxy and through the WAF, with both status codes.
- The CRS rule id that fired, from the WAF's log, and what that rule checks.
- One legitimate request the WAF blocks that it should not, or evidence you looked for one and found none.
- Three or four sentences: CRS in blocking mode on day one is how teams end up turning the WAF off. Describe how you would roll this out in front of a real application.

## Acceptance criteria

- Task 1 (4): redirect proven with its status code; TLS 1.3 protocol and suite shown; a scanner's protocol table showing 1.0 and 1.1 not offered; all six headers present in the response; the CSP answer describes a path to enforcement.
- Task 2 (4): the status-code sequence shows the rate limit engaging and returning 429; a per-address connection limit is configured; a cipher suite outside your list is refused; each timeout explained; the rotation runbook is ordered and includes verification; the bypass answer names two concrete techniques.
- Bonus (2): the same payload compared through both paths with status codes; a real CRS rule id from the log; a false-positive hunt with a result either way; a rollout plan that does not start in blocking mode.
## Submit

<!-- verify:skip student fork files -->
```bash
git add <proof of work + lab11.md> (labs/lab11/reverse-proxy/nginx.conf submissions/lab11.md, bonus: labs/lab11/waf/, ...)
git commit -m "feat(lab11): hardened reverse proxy + WAF"
git push -u origin feature/lab11
```

Do not commit `labs/lab11/reverse-proxy/certs/` or `labs/lab11/logs/`. Clean up with `docker compose -f labs/lab11/docker-compose.yml down -v`.


## Common pitfalls

- `ssl_ciphers` has no effect on TLS 1.3. nginx accepts `TLS_AES_*` names there and ignores them; the directive for 1.3 is `ssl_conf_command Ciphersuites`.
- `openssl s_client -cipher TLS_AES_256_GCM_SHA384` fails with `no cipher match` before connecting: `-cipher` is TLS 1.2 and earlier. Use `-ciphersuites` for 1.3.
- The self-signed certificate makes every `curl` need `-k`, and `openssl s_client` will always print a verify error. That is expected, not a misconfiguration.
- `openssl s_client -tls1_0` and `-tls1_1` fail with `no protocols available` on OpenSSL 3 regardless of the server. Use a scanner to enumerate what the server offers.
- Certificate files must be readable by the nginx user inside the container. A key written as `600` by root on the host is unreadable after the bind mount.
- Ports 80 and 443 need privileges on some setups. Remap to 8080 and 8443 in the compose file and adjust every URL in your report to match.
- Headers without `always` disappear from 4xx and 5xx responses, which is exactly when a browser is most exposed.
- A rate limit without `limit_req_status 429` answers 503, which tells a client to retry rather than back off.

## Resources

- [nginx ssl module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html), in particular `ssl_conf_command`, and [limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — a defensible starting point per compatibility level
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) — what each header is for
- [OWASP Core Rule Set](https://coreruleset.org/) and the [ModSecurity CRS container](https://github.com/coreruleset/modsecurity-crs-docker)
