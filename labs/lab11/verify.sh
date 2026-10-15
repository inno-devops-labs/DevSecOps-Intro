#!/bin/bash
# Проверка конфигурации Lab 11

echo "=========================================="
echo "Lab 11 - Nginx Security Configuration"
echo "=========================================="
echo ""

# Проверка запущенных контейнеров
echo "1. Проверка контейнеров:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep lab11
echo ""

# HTTP -> HTTPS redirect
echo "2. HTTP -> HTTPS redirect:"
curl -I http://localhost/ 2>/dev/null | grep -E '(HTTP|Location)'
echo ""

# Security headers
echo "3. Security Headers:"
curl -Isk https://localhost/ 2>/dev/null | grep -E '(X-Frame|X-Content|X-XSS|Strict-Transport|Content-Security|Referrer-Policy)'
echo ""

# TLS версии (быстрая проверка)
echo "4. TLS Версии (быстрая проверка с OpenSSL):"
echo "   TLS 1.0:"
openssl s_client -connect localhost:443 -tls1 </dev/null 2>&1 | grep -q 'Cipher is (NONE)' && echo "   ❌ Отключен" || echo "   ✅ Включен"
echo "   TLS 1.1:"
openssl s_client -connect localhost:443 -tls1_1 </dev/null 2>&1 | grep -q 'Cipher is (NONE)' && echo "   ❌ Отключен" || echo "   ✅ Включен"
echo "   TLS 1.2:"
openssl s_client -connect localhost:443 -tls1_2 </dev/null 2>&1 | grep -q 'Cipher is (NONE)' && echo "   ✅ Включен" || echo "   ❌ Отключен"
echo "   TLS 1.3:"
openssl s_client -connect localhost:443 -tls1_3 </dev/null 2>&1 | grep -q 'Cipher is (NONE)' && echo "   ✅ Включен" || echo "   ❌ Отключен"
echo ""

# WAF проверка
echo "5. WAF (ModSecurity) проверка:"
NORMAL=$(curl -sk https://localhost:8443/ 2>/dev/null | wc -c | tr -d ' ')
BLOCKED=$(curl -sk "https://localhost:8443/?q=1' OR '1'='1" 2>/dev/null | wc -c | tr -d ' ')
echo "   Нормальный запрос: $NORMAL байт"
echo "   SQL Injection: $BLOCKED байт"
if [ "$BLOCKED" -lt 1000 ]; then
  echo "   ✅ WAF блокирует атаки"
else
  echo "   ❌ WAF не блокирует атаки"
fi
echo ""

echo "=========================================="
echo "Проверка завершена!"
echo "=========================================="
