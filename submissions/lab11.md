# Lab 11 — Edge Hardening with a Reverse Proxy

## Task 1

Status code:
```
HTTP/1.1 308 Permanent Redirect
```
308 because it doesnt allow changing requests from post to get, which is safer, and it keeps the body and headers

```
PProtocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
strict-transport-security: max-age=86400
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

```
 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK): final
 NPN/SPDY   not offered
 ALPN/HTTP2 h2, http/1.1 (offered)
```

Unchanged, it will block cookie-consent init, inline styles, and remote fonts, cause the fetched HTML contains an inline script & two inline styles with that. To get to enforcement i'd probably log violations, replace inline code, then review and test the enforcement again.


## Task 2

Status code sequence, at rate of 10 requests per minute and burst of 5:
```
401 401 401 401 401 401 429 429 429 429 429 429 429 429
```


Cypher config:
```
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;
```
Proof:
```
echo | openssl s_client -connect localhost:443 -tls1_3 \
  -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -icE 'alert|failure'
1
```

timeouts:

|name|time|protection|
|---|---|---|
| proxy_connect_timeout | 5 | for upstream connection |
| proxy_read_timeout | 30 | if upstream sends no response |
| proxy_send_timeout | 30 | if upstream cant accept req data |
| client_header_timeout | 10 | for client req headers |
| client_body_timeout | 10 | for client req body |
| send_timeout | 10 | for responding to client |
| keepalive_timeout | 10 | for idle client connection |

command & real timeout:
```
curl -sk --max-time 40 -o NUL -w 'status=%{http_code} seconds=%{time_total}' https://localhost/rest/admin/application-version
status=504 seconds=30.040660
```

With OSCP stapling and a CA certificate server provides a signed revocation-status response without separate client requests to CA responder. Would rather not use it, because there is no CA responder to give staples here.

Runbook:
1. Get replacement certificate and key, check their details.
2. Start HTTPS probe against endpoint, record the current serial+fingerprint 
3. Replace certificate and key.
4. $ docker exec lab11-nginx-1 nginx -t
5. $ docker exec lab11-nginx-1 nginx -s reload
6. Verify that the certificate on a fresh TLS connection is the staged one

An attacker can spread attempts across several accounts by switching between them to remain under threshold. They can even set up a botnet for that. I would add velocity checks and IP limits to prevent that.

## Bonus

One legitimate request the WAF blocks that it should not, or evidence you looked for one and found none.
Three or four sentences: CRS in blocking mode on day one is how teams end up turning the WAF off. Describe how you would roll this out in front of a real application.

```
$ curl -sk -o NUL -w '%{http_code}' 'https://localhost/rest/products/search?q=%27+OR+1%3D1--'
500
$ curl -s -o NUL -w '%{http_code}' 'http://localhost:8081/rest/products/search?q=%27+OR+1%3D1--'
403
```

The CRS rule id is 942100, which checks for SQLi using libinjection.

After trying several requests, the only type blocked is the one with " ' " present (e.g. "surf 'n' turf"), raising the error 500, which is not even sqli being raised. Other stuff returned 200.


How to roll out CRS:

First i would run CRS detection-only. During that i would investigate alerts and write rule exclusions for spotted false positives. After that i would run CRS in blocking, and now it wont be such a nuisance.