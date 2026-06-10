## Goal
Deploy OWASP Juice Shop locally and perform an initial security assessment including health checks, API exploration, and risk identification.

## Changes
- Added `submissions/lab1.md` with deployment details, health check results, and top 3 OWASP Top 10:2025 risks
- Added `.github/PULL_REQUEST_TEMPLATE.md` for future PR consistency

## Testing
```bash
# Verify container is running
docker ps | grep juice-shop

# Health check on root (expected 200)
curl -I http://127.0.0.1:3000/

# Check products endpoint (corrected to /api/products)
curl http://127.0.0.1:3000/api/products | head -c 200
```

## Artifacts & Screenshots
