# Lab 2 — Submission

## Task 1
### Top 5 Risks (baseline)

Ranking uses: Composite score = Severity*100 + Likelihood*10 + Impact (desc).

| Severity | Category | Asset | Likelihood | Impact |
|---|---|---|---|---|
| elevated | unencrypted-communication | user-browser | likely | high |
| elevated | unencrypted-communication | reverse-proxy | likely | medium |
| elevated | missing-authentication | juice-shop | likely | medium |
| elevated | cross-site-scripting | juice-shop | likely | medium |
| medium | cross-site-request-forgery | juice-shop | very-likely | low |

## Task 2

| Category | Baseline | Secure | Δ |
|---|---:|---:|---:|
| container-baseimage-backdooring | 1 | 1 | 0 |
| cross-site-request-forgery | 2 | 2 | 0 |
| cross-site-scripting | 1 | 1 | 0 |
| missing-authentication | 1 | 1 | 0 |
| missing-authentication-second-factor | 2 | 2 | 0 |
| missing-build-infrastructure | 1 | 1 | 0 |
| missing-hardening | 2 | 2 | 0 |
| missing-identity-store | 1 | 1 | 0 |
| missing-vault | 1 | 1 | 0 |
| missing-waf | 1 | 1 | 0 |
| server-side-request-forgery | 2 | 2 | 0 |
| unencrypted-asset | 2 | 1 | -1 |
| unencrypted-communication | 2 | 0 | -2 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

* **Change made:**  
switched all HTTP links to HTTPS and enabled transparent encryption for Persistent Storage.  

* **Result:**  
“Unencrypted Communication” risks disappeared from the risk list, "Unencrypted Asset" risk decreased by one.
* **Why:**  
 "Unencrypted Asset" decreased because we add an encryption for Persistant storage, but there is left other asset(App, Webhook or browser) without encryption.  
“Unencrypted Communication” disappears, because we switched all channels to HTTPS and it starts use TSL and encrypted channels.