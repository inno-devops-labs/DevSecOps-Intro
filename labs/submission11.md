# Task 1

```
docker compose ps
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     42 seconds ago   Up 42 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     42 seconds ago   Up 42 seconds   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```
As can be seen, juice shop isn't exposed

Hiding direct app ports allows for an additional security level

# Task 2

```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

- X-Frame-Options: protects againts embedding in frames
- X-Content-Type-Options: protects against MIME-sniffing attacks
- Strict-Transport-Security (HSTS) (unused): protects against HTTPS downgrade and some MITM attacks by requiring future connections over HTTPS
- Referrer-Policy: protects against leaking sensitive URL/referrer data to other sites
- Permissions-Policy: protects against unwanted use of browser features (here: camera, microphone, and geolocation)
- COOP/CORP: COOP protects against cross-origin window interaction attacks; CORP protects resources from unwanted cross-origin inclusion and some side-channel attacks.
- CSP-Report-Only: does not block attacks itself, but reports potential CSP violations so unsafe script/content loading can be identified before enforcing CSP

# Task 3

## TestSSL
- TLS 1.2 and 1.3 were offered, also ALPN/HTTP2 was offered
- Forward Secrecy strong encryption (AEAD ciphers) was offered

### Supported cipher suites
- ECDHE-RSA-AES256-GCM-SHA384 
- ECDHE-RSA-AES128-GCM-SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- TLS_AES_128_GCM_SHA256

### TLS 1.0/1.1 are obsolete and weaker, while TLS 1.2+ provides modern secure cipher suites; TLS 1.3 is preferred because it improves security and simplifies the handshake.

### Warnings / vulnerabilities
No tested TLS vulnerabilities were detected, but the certificate is self-signed, the trust chain is not valid, and no CRL/OCSP URI is provided

## Rate limiting

### Command line output
```
[RatPC|rightrat lab11] for i in $(seq 1 12); do \
  curl -sk -o /dev/null -w "%{http_code}\n" \
  -H 'Content-Type: application/json' \
  -X POST https://localhost:8443/rest/user/login \
  -d '{"email":"a@a","password":"a"}'; \
done | tee analysis/rate-limit-test.txt
401
401
401
401
401
401
429
429
429
429
429
429
```
Total: 6 **401**s and 6 **429**s

### access.log
```
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.20.0" rt=0.024 uct=0.000 urt=0.025
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.20.0" rt=0.009 uct=0.000 urt=0.009
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.20.0" rt=0.016 uct=0.000 urt=0.016
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.20.0" rt=0.008 uct=0.000 urt=0.007
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.20.0" rt=0.006 uct=0.001 urt=0.007
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 401 26 "-" "curl/8.20.0" rt=0.006 uct=0.000 urt=0.007
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.20.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.20.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.20.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.20.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.20.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [12/May/2026:18:45:26 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.20.0" rt=0.000 uct=- urt=-
```

### Explaination
- ``rate=10r/m`` allows 10 requests per minute per IP
- ``burst=5`` allows up to 5 immediate requests before responding with 429
- ``lient_body_timeout 10s``: Nginx waits at most 10 seconds between chunks of the request body
- ``client_header_timeout 10s``: Nginx waits up to 10 seconds for request headers
- ``proxy_read_timeout 30s``: Nginx waits up to 30 seconds between response reads from the upstream
- ``proxy_send_timeout 30s``: Nginx waits up to 30 seconds between writes while sending the request to the upstream
