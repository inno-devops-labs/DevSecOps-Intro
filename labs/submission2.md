# Lab 2 --- Threat Modeling with Threagile (OWASP Juice Shop)

## Task 1 --- Baseline Threat Model

### Generation

Threagile model was generated using Docker and the provided YAML model.

Artifacts generated: - report.pdf - data-flow diagram - data-asset
diagram - risks.json - stats.json

### Risk Ranking Methodology

Severity mapping: critical=5, elevated=4, high=3, medium=2, low=1\
Likelihood mapping: very-likely=4, likely=3, possible=2, unlikely=1\
Impact mapping: high=3, medium=2, low=1

Composite score = Severity*100 + Likelihood*10 + Impact

### Top Risks Summary

Major baseline risks: - Unencrypted communication between browser, proxy
and application - Lack of storage encryption - XSS / CSRF attack
vectors - Missing security infrastructure (vault, WAF, identity store) -
Weak hardening and missing build infrastructure

------------------------------------------------------------------------

## Task 2 --- Secure Variant

### Model Changes

-   Browser → App: protocol=https
-   Reverse Proxy links: protocol=https
-   Persistent Storage: encryption=transparent

### Risk Category Delta Table

  Category                                 Baseline   Secure    Δ
  -------------------------------------- ---------- -------- ----
  container-baseimage-backdooring                 1        1    0
  cross-site-request-forgery                      2        2    0
  cross-site-scripting                            1        1    0
  missing-authentication                          1        1    0
  missing-authentication-second-factor            2        2    0
  missing-build-infrastructure                    1        1    0
  missing-hardening                               2        2    0
  missing-identity-store                          1        1    0
  missing-vault                                   1        1    0
  missing-waf                                     1        1    0
  server-side-request-forgery                     2        2    0
  unencrypted-asset                               2        1   -1
  unencrypted-communication                       2        0   -2
  unnecessary-data-transfer                       2        2    0
  unnecessary-technical-asset                     2        2    0

### Analysis

Enabling TLS removed unencrypted communication risks and reduced risks
related to unencrypted storage.\
Application-layer and infrastructure risks remain because they require
additional controls beyond encryption.

## Conclusion

The secure variant demonstrates how TLS and encryption-at-rest
significantly reduce the threat landscape while leaving
application-level vulnerabilities unchanged.
