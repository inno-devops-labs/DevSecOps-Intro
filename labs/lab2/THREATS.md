# THREATS.md

## Context
Local OWASP Juice Shop deployment in a Docker container.
Users connect via browser on port 3000 or through an optional reverse proxy with TLS and security headers.
The application may persist logs/files on a host-mounted volume and send outbound requests to Email/SMS or webhook providers.

## Top 5 Risks
1. Injection [Tampering] — unsanitized input may corrupt database or application state.
2. Session hijacking [Spoofing] — attacker may steal or forge tokens to impersonate users.
3. Sensitive logs exposure [Information Disclosure] — secrets or PII may leak from host-mounted storage.
4. DoS flood [Denial of Service] — excessive requests may exhaust container CPU/memory resources.
5. Missing audit trail [Repudiation] — user or attacker actions may go untracked without logging.
