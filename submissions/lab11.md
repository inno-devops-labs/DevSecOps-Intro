# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections only)

```nginx
# HTTPS server
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;
    ssl_session_timeout 1d;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ecdh_curve X25519:secp384r1;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 1.1.1.1 valid=300s;
    resolver_timeout 5s;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
}
```

### A. HTTPS redirect proof

```
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/
```

### B. TLS 1.3 proof

```
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

### C. Security headers proof (all 6 present)

```
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against (1 sentence each)

- HSTS: защищает от SSL-stripping атак, заставляя браузер использовать только HTTPS после первого ответа с этим заголовком.
- X-Content-Type-Options: nosniff: предотвращает MIME-sniffing атаки, запрещая браузеру угадывать тип контента.
- X-Frame-Options: DENY: защищает от clickjacking, запрещая встраивание сайта в iframe на других доменах.
- Referrer-Policy: предотвращает утечку URL-путей при переходе на сторонние сайты, отправляя только origin.
- Permissions-Policy: ограничивает доступ сторонних скриптов к браузерным API (камера, микрофон, геолокация).
- Content-Security-Policy: защищает от XSS и data exfiltration, ограничивая источники загрузки ресурсов.

---

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 200 | 0 |
| 429 | 54 |
| 5xx | 6 |

### Timeout enforced

```
HTTP/1.1 400 Bad Request
Server: nginx
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

### Cipher hardening

```
Peer Temp Key: X25519, 253 bits
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

### Cert rotation runbook (7 steps)

1. **Detect expiry**: мониторинг истечения сертификата — alert за 30 дней, page за 7 дней (через Prometheus + Alertmanager или certbot timer).
2. **Order new cert**: заказ нового сертификата через Let's Encrypt (certbot) или платного CA для EV-сертификатов.
3. **Validate**: проверка цепочки сертификата — `openssl x509 -in newcert.pem -text` и `openssl verify -CAfile ca.pem newcert.pem`.
4. **Atomic swap**: атомарная замена через симлинки — `ln -sf newcert.pem current.pem && nginx -s reload` (без downtime).
5. **Verify**: проверка в production — `curl -vk https://site.com` для проверки нового сертификата, `testssl.sh` для полной проверки TLS posture.
6. **Rollback plan**: хранение предыдущего сертификата + ключа 7 дней для отката через переустановку симлинка.
7. **Audit**: логирование события ротации с serial номером и expiry в SIEM/DefectDojo.

### What OCSP stapling buys you (2-3 sentences, reference Reading 11)

OCSP stapling позволяет серверу самостоятельно кэшировать и прикладывать OCSP-ответ об отзыве сертификата к TLS handshake, устраняя задержку и privacy-утечку (клиенту не нужно обращаться к OCSP responder'у CA). В production с публичным сертификатом это критически важно для производительности и конфиденциальности. Для self-signed сертификата в лабе OCSP stapling не имеет смысла, т.к. самоподписанный сертификат не зарегистрирован в CA и не может быть отозван через OCSP — nginx закономерно игнорирует `ssl_stapling on` с предупреждением "issuer certificate not found".

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice
- WAF used: ModSecurity v3 (owasp/modsecurity-crs:nginx image)
- OWASP CRS version: 3.3.10 (image default; CRS v4 available with `:v4` tag)
- Paranoia level: 1
- SecRuleEngine: On (blocking mode)

### Attack payload sent
```
GET /rest/products/search?q=' OR 1=1-- (URL-encoded)
```

### Before WAF (Nginx alone)
```
no-waf: HTTP 500    # Juice Shop internal error, but NOT blocked by Nginx
```

### After WAF
```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)
```
Rule ID 942100: "SQL Injection Attack Detected via libinjection"
  Matched Data: s&1c found within ARGS:q: ' OR 1=1--
  Tags: attack-sqli, paranoia-level/1, OWASP_CRS

Rule ID 949110: "Inbound Anomaly Score Exceeded (Total Score: 5)"
  -> resulted in 403 Forbidden
```
Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis (3 sentences)

WAF добавляет защиту на уровне приложения (L7), которую не могут обеспечить SAST + DAST (статический/динамический анализ на этапе разработки) и Conftest (политики IaC) — WAF перехватывает атаки в реальном времени, такие как SQL-инъекции, которые Nginx сам по себе не блокирует. Цена WAF — ложные срабатывания (FP) на высоких уровнях paranoia, операционные накладные расходы на конфигурацию и тюнинг правил, а также усложнение cert/config management. WAF не стоит разворачивать, если сервис не имеет публичного доступа (internal-only), или если трафик太低 для оправдания накладных расходов, либо при использовании API Gateway с встроенным WAF (AWS WAF, Cloudflare) на более высоком уровне инфраструктуры.