# Lab 11: Защита веб-приложений с Nginx

**Студент:** Pavel Shnyakin  
**GitHub:** shnupel  
**Email:** ufamail.com2@gmail.com  
**Дата:** 15 октября 2026

## Задача 1: Настройка самозаверенного SSL-сертификата

Создал самозаверенный SSL-сертификат для локального тестирования HTTPS.

### Шаг 1: Генерация приватного ключа и сертификата

Использовал OpenSSL для создания сертификата со сроком действия 365 дней:

```bash
mkdir -p ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/nginx.key \
  -out ssl/nginx.crt \
  -subj "/C=RU/ST=Moscow/L=Moscow/O=Study/CN=localhost"
```

Параметры:
- `-x509` - создать самозаверенный сертификат
- `-nodes` - не шифровать приватный ключ
- `-days 365` - срок действия 1 год
- `-newkey rsa:2048` - RSA ключ 2048 бит
- `CN=localhost` - Common Name для локальной работы

### Результаты

Созданы два файла:
- `ssl/nginx.key` - приватный ключ (2048 бит RSA)
- `ssl/nginx.crt` - самозаверенный сертификат X.509

Проверка сертификата:
```bash
openssl x509 -in ssl/nginx.crt -noout -text
```

![Certificate Info](images/cert-info.png)

## Задача 2: Настройка Nginx как Reverse Proxy с HTTPS и Security Headers

Настроил Nginx в качестве reverse proxy с HTTPS, безопасными заголовками и rate limiting.

### Шаг 1: Создание docker-compose.yml

Создал файл `docker-compose.yml` с двумя сервисами:

```yaml
services:
  juice:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - juice
```

### Шаг 2: Конфигурация nginx.conf

Создал конфигурацию с:
- Редиректом HTTP → HTTPS
- TLS 1.2 и 1.3
- Ограниченными cipher suites для TLS 1.3 (только AES-GCM)
- Security headers
- Rate limiting для /rest/user/login
- Connection limit per IP
- Proxy timeouts

Основные параметры конфигурации:

**HTTP → HTTPS редирект:**
```nginx
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
```

**TLS настройки:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384;
ssl_prefer_server_ciphers on;
```

**Security Headers:**
```nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Referrer-Policy "no-referrer" always;
```

**Rate Limiting для login endpoint:**
```nginx
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/s;

location /rest/user/login {
    limit_req zone=login_limit burst=10 nodelay;
    proxy_pass http://juice:3000;
}
```

**Connection limit:**
```nginx
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
limit_conn conn_limit 10;
```

**Proxy timeouts:**
```nginx
proxy_connect_timeout 10s;
proxy_send_timeout 30s;
proxy_read_timeout 30s;
send_timeout 30s;
```

### Шаг 3: Запуск сервисов

```bash
docker compose up -d
```

Проверка статуса:
```bash
docker ps
```

![Docker Services Running](images/docker-running.png)

### Шаг 4: Проверка конфигурации

**1. HTTP → HTTPS редирект:**
```bash
curl -I http://localhost/
```
Ответ: `301 Moved Permanently` с `Location: https://localhost/`

**2. Доступ по HTTPS:**
```bash
curl -k https://localhost/ | head -20
```
Приложение Juice Shop успешно доступно через HTTPS.

![HTTPS Working](images/https-working.png)

**3. Проверка SSL протоколов:**

Использовал `testssl.sh` для детальной проверки:
```bash
docker run --rm -ti --network=host drwetter/testssl.sh --protocols localhost:443
```

Результаты:
- ✅ SSLv2: не поддерживается
- ✅ SSLv3: не поддерживается  
- ✅ TLS 1.0: не поддерживается
- ✅ TLS 1.1: не поддерживается
- ✅ TLS 1.2: поддерживается
- ✅ TLS 1.3: поддерживается

![Protocol Check](images/protocol-check.png)

**4. Проверка TLS 1.3 ciphers (только AES-GCM):**
```bash
docker run --rm -ti --network=host drwetter/testssl.sh --each-cipher localhost:443
```

Результаты для TLS 1.3:
- ✅ TLS_AES_256_GCM_SHA384 - работает
- ✅ TLS_AES_128_GCM_SHA256 - работает
- ❌ TLS_CHACHA20_POLY1305_SHA256 - не работает (отключен в конфигурации)

![Cipher Check](images/cipher-check.png)

**5. Проверка security headers:**
```bash
curl -Isk https://localhost/ | grep -E '(X-Frame|X-Content|X-XSS|Strict-Transport|Content-Security|Referrer-Policy)'
```

Результаты:
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
Referrer-Policy: no-referrer
```

![Security Headers](images/security-headers.png)

**6. Проверка rate limiting:**

Отправил 20 запросов на `/rest/user/login`:
```bash
for i in {1..20}; do curl -sk -w "\n%{http_code}\n" -X POST https://localhost/rest/user/login -H "Content-Type: application/json" -d '{"email":"test@test.com","password":"test"}'; done
```

Результаты:
- Первые 15 запросов: 401 Unauthorized (приложение отклоняет неверные credentials)
- Следующие запросы: 503 Service Temporarily Unavailable (rate limit сработал)

![Rate Limit](images/rate-limit.png)

**7. Проверка proxy timeout:**
```bash
curl -sk https://localhost/ --max-time 15
```

Таймаут настроен на 10 секунд для подключения и 30 секунд для чтения/отправки.

### Результаты

Все требования Task 2 выполнены:
- ✅ HTTP редирект на HTTPS
- ✅ TLS 1.2 и 1.3 only
- ✅ TLS 1.3 использует только AES-GCM cipher suites
- ✅ 6 security headers
- ✅ Rate limiting на /rest/user/login (5 req/s + burst 10)
- ✅ Connection limit per client (10 соединений)
- ✅ Proxy timeouts настроены

## Bonus: WAF с OWASP ModSecurity Core Rule Set

Развернул WAF на базе OWASP ModSecurity CRS перед приложением.

### Шаг 1: Добавление WAF в docker-compose.yml

Добавил сервис WAF с использованием официального образа OWASP ModSecurity CRS:

```yaml
waf:
  image: owasp/modsecurity-crs:nginx
  ports:
    - "8443:8443"
  environment:
    - BACKEND=http://juice:3000
    - PORT=8080
    - SSL_PORT=8443
    - MODSEC_RULE_ENGINE=On
    - BLOCKING_PARANOIA=2
    - ANOMALY_INBOUND=10
    - ANOMALY_OUTBOUND=5
    - PROXY_SSL=on
    - PROXY_SSL_CERT=/etc/nginx/ssl/nginx.crt
    - PROXY_SSL_CERT_KEY=/etc/nginx/ssl/nginx.key
    - MODSEC_AUDIT_LOG=/var/log/modsecurity/modsec_audit.log
    - MODSEC_AUDIT_LOG_FORMAT=JSON
    - MODSEC_AUDIT_LOG_TYPE=Serial
  volumes:
    - ./ssl:/etc/nginx/ssl:ro
    - ./waf/logs:/var/log/modsecurity
  depends_on:
    - juice
```

Параметры:
- `MODSEC_RULE_ENGINE=On` - включил ModSecurity
- `BLOCKING_PARANOIA=2` - уровень параноидности 2 (больше правил, но меньше false positives чем на уровне 3-4)
- `ANOMALY_INBOUND=10` - порог для блокировки входящих запросов
- `ANOMALY_OUTBOUND=5` - порог для блокировки исходящих ответов
- `PROXY_SSL=on` - включил SSL для проксирования

### Шаг 2: Проверка работы WAF

Запустил сервисы:
```bash
docker compose up -d
```

![WAF Running](images/waf-running.png)

### Шаг 3: Тестирование блокировки атак

**Нормальный запрос** - работает корректно:
```bash
curl -sk https://localhost:8443/ | head -20
```
Результат: полная HTML-страница (9903 байт)

**SQL Injection** - блокируется:
```bash
curl -sk "https://localhost:8443/rest/products/search?q=1'%20OR%20'1'='1"
```
Результат: 403 Forbidden (146 байт)

![WAF Block SQL Injection](images/waf-block-sqli.png)

**XSS Attack** - блокируется:
```bash
curl -sk "https://localhost:8443/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```
Результат: 403 Forbidden

![WAF Block XSS](images/waf-block-xss.png)

### Результаты

WAF успешно блокирует распространенные типы атак:
- SQL Injection (правило 942*)
- XSS (правило 941*)
- Path Traversal (правило 930*)

OWASP CRS работает с уровнем параноидности 2, что обеспечивает хороший баланс между защитой и количеством ложных срабатываний.

Приложение доступно через WAF на порту 8443, а прямой доступ к Juice Shop остается на порту 3000 для сравнения поведения.

## Выводы

В ходе лабораторной работы:
1. Создал самозаверенный SSL-сертификат для HTTPS
2. Настроил Nginx как reverse proxy с:
   - HTTPS редиректом
   - Современными TLS протоколами (1.2, 1.3)
   - Ограниченными cipher suites для TLS 1.3
   - Security headers для защиты от XSS, clickjacking, MIME sniffing
   - Rate limiting для защиты от brute-force атак
   - Connection limiting для защиты от DoS
   - Proxy timeouts
3. Развернул WAF с OWASP ModSecurity CRS для защиты от распространенных веб-атак

Все механизмы безопасности работают корректно и обеспечивают базовую защиту веб-приложения.
