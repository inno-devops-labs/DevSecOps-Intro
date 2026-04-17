## Rate Limiting Summary

### Test result
The login endpoint `/rest/user/login` was tested with 12 rapid POST requests.

Observed results:
- 6 responses returned `401 Unauthorized`
- 6 responses returned `429 Too Many Requests`

### Interpretation
The first requests were forwarded to Juice Shop and failed only because of invalid credentials.
After the configured threshold was exceeded, Nginx rate limiting was triggered and returned `429`.

### Security rationale
The configured login protection reduces brute-force risk by limiting repeated authentication attempts.
This helps protect user accounts and reduces automated abuse.

### Trade-off
A strict rate limit improves security, but values that are too aggressive may affect legitimate users who retry login several times.
