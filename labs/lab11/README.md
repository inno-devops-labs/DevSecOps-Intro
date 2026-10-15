# Lab 11: Защита веб-приложений с Nginx

## Структура директории

```
lab11/
├── docker-compose.yml           # Основной compose файл с nginx, juice-shop и WAF
├── reverse-proxy/
│   ├── nginx.conf              # Конфигурация Nginx reverse proxy
│   └── certs/                  # SSL сертификаты
│       ├── localhost.crt
│       └── localhost.key
├── waf/
│   └── logs/                   # Логи ModSecurity WAF
├── logs/                       # Логи Nginx
├── results/                    # Результаты тестирования
└── images/                     # Артефакты для отчета
```

## Запуск

### 1. Запустить все сервисы:

```bash
docker compose up -d
```

### 2. Проверить статус:

```bash
docker ps
```

Должны быть запущены:
- `lab11-juice-1` - Juice Shop на порту 3000
- `lab11-nginx-1` - Nginx reverse proxy на портах 80 (HTTP) и 443 (HTTPS)
- `lab11-waf-1` - ModSecurity WAF на порту 8443

## Endpoints

- **HTTP (редирект на HTTPS):** http://localhost/
- **HTTPS через Nginx:** https://localhost/
- **HTTPS через WAF:** https://localhost:8443/
- **Прямой доступ к Juice Shop:** http://localhost:3000/

## Тестирование

### Проверка HTTP → HTTPS редиректа

```bash
curl -I http://localhost/
```

Ожидается: `301 Moved Permanently` с `Location: https://localhost/`

### Проверка TLS протоколов

```bash
docker run --rm -ti --network=host drwetter/testssl.sh --protocols localhost:443
```

### Проверка TLS 1.3 ciphers

```bash
docker run --rm -ti --network=host drwetter/testssl.sh --each-cipher localhost:443
```

### Проверка security headers

```bash
curl -Isk https://localhost/ | grep -E '(X-Frame|X-Content|X-XSS|Strict-Transport|Content-Security|Referrer-Policy)'
```

### Проверка rate limiting

```bash
for i in {1..20}; do 
  curl -sk -w "\n%{http_code}\n" -X POST https://localhost/rest/user/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"test"}'
done
```

### Тестирование WAF

**Нормальный запрос:**
```bash
curl -sk https://localhost:8443/ | wc -c
```

**SQL Injection (блокируется):**
```bash
curl -sk "https://localhost:8443/rest/products/search?q=1'%20OR%20'1'='1" | wc -c
```

**XSS (блокируется):**
```bash
curl -sk "https://localhost:8443/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

## Остановка

```bash
docker compose down
```

## Конфигурация

### Nginx Security Features

- TLS 1.2 и 1.3 only
- TLS 1.3 с ограниченными cipher suites (только AES-GCM)
- 6 security headers (X-Frame-Options, HSTS, CSP, и др.)
- Rate limiting: 10 запросов/минуту для /rest/user/login
- Connection limit: 10 соединений per IP
- Proxy timeouts: 10s connect, 30s read/send

### ModSecurity WAF

- OWASP Core Rule Set (CRS)
- Paranoia level: 1
- Anomaly scoring mode
- Блокирует: SQL Injection, XSS, Path Traversal и другие OWASP Top 10 атаки

## Автор

Pavel Shnyakin (shnupel)
