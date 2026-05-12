# Lab 2 Submission — Threat Modeling with Threagile

## Scope

- **Target application:** OWASP Juice Shop
- **Image/version:** `bkimminich/juice-shop:v19.0.0`
- **Model source:** [`labs/lab2/threagile-model.yaml`](lab2/threagile-model.yaml)
- **Secure variant:** [`labs/lab2/threagile-model.secure.yaml`](lab2/threagile-model.secure.yaml)
- **Scenario modeled:** local deployment with optional reverse proxy, persistent host-mounted storage, and optional outbound webhook integration

---

## Task 1 — Threagile Baseline Model

### Baseline generation

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure

docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### Generated baseline artifacts

- [Baseline report PDF](lab2/baseline/report.pdf)
- [Baseline data-flow diagram](lab2/baseline/data-flow-diagram.png)
- [Baseline data-asset diagram](lab2/baseline/data-asset-diagram.png)
- [Baseline risks.json](lab2/baseline/risks.json)
- [Baseline stats.json](lab2/baseline/stats.json)
- [Baseline technical-assets.json](lab2/baseline/technical-assets.json)

### Baseline risk summary

Baseline Threagile output produced **23 unchecked risks** in total:

- `4` elevated
- `14` medium
- `5` low
- `0` high
- `0` critical

### Risk ranking methodology

I ranked risks with the composite score required by the lab:

- Severity weights: `critical=5`, `elevated=4`, `high=3`, `medium=2`, `low=1`
- Likelihood weights: `very-likely=4`, `likely=3`, `possible=2`, `unlikely=1`
- Impact weights: `high=3`, `medium=2`, `low=1`
- **Composite score** = `Severity*100 + Likelihood*10 + Impact`

Example:

- `unencrypted-communication` on direct browser access = `4*100 + 3*10 + 3 = 433`
- `cross-site-scripting` at Juice Shop = `4*100 + 3*10 + 2 = 432`

### Top 5 risks

| Rank | Score | Severity | Category | Asset / Link | Likelihood | Impact |
|---|---:|---|---|---|---|---|
| 1 | 433 | elevated | unencrypted-communication | `User Browser -> Direct to App (no proxy)` | likely | high |
| 2 | 432 | elevated | cross-site-scripting | `Juice Shop Application` | likely | medium |
| 3 | 432 | elevated | missing-authentication | `Reverse Proxy -> Juice Shop Application` | likely | medium |
| 4 | 432 | elevated | unencrypted-communication | `Reverse Proxy -> Juice Shop Application` | likely | medium |
| 5 | 241 | medium | cross-site-request-forgery | `Juice Shop Application via Direct to App` | very-likely | low |

Note: the second CSRF finding (`via To App`) has the same score as rank 5; I kept the direct browser path in the top 5 because it is the more exposed flow.

### Analysis of baseline concerns

The baseline model shows that the most important weaknesses are concentrated around **transport security** and **browser-facing application risks**.

First, the highest-scoring issue is **unencrypted communication** on the direct browser-to-app path. That makes session identifiers and authentication material vulnerable to interception or manipulation if traffic is exposed beyond a tightly local-only setup.

Second, **XSS** remains one of the strongest application-level risks. This matches the nature of Juice Shop as a deliberately vulnerable training target: once malicious script executes in the browser, it can target sessions, tokens, DOM content, and user actions.

Third, the model flags a **missing-authentication** issue on the reverse-proxy-to-app hop. Even though that link is internal to the modeled stack, the app still implicitly trusts traffic that arrives from the proxy path, which keeps the trust boundary weak.

Other medium risks, such as **CSRF**, **missing hardening**, and **SSRF**, reinforce that the baseline architecture is intentionally minimal and still depends heavily on stronger transport and runtime controls.

### Baseline diagram references

- [Baseline data-flow diagram](lab2/baseline/data-flow-diagram.png)
- [Baseline data-asset diagram](lab2/baseline/data-asset-diagram.png)
- [Baseline full PDF report](lab2/baseline/report.pdf)

---

## Task 2 — HTTPS Variant and Risk Comparison

### Secure model changes

I created a secure variant in [`labs/lab2/threagile-model.secure.yaml`](lab2/threagile-model.secure.yaml) with the exact changes required by the lab:

- `User Browser -> Direct to App (no proxy)` changed to `protocol: https`
- `Reverse Proxy -> To App` changed to `protocol: https`
- `Persistent Storage` changed to `encryption: transparent`

### Secure generation

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

### Generated secure artifacts

- [Secure report PDF](lab2/secure/report.pdf)
- [Secure data-flow diagram](lab2/secure/data-flow-diagram.png)
- [Secure data-asset diagram](lab2/secure/data-asset-diagram.png)
- [Secure risks.json](lab2/secure/risks.json)
- [Secure stats.json](lab2/secure/stats.json)
- [Secure technical-assets.json](lab2/secure/technical-assets.json)

### Secure risk summary

The secure variant produced **20 unchecked risks** in total:

- `2` elevated
- `13` medium
- `5` low
- `0` high
- `0` critical

### Risk category delta table

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

### Delta run explanation

The model changes had a clear and measurable effect on the threat landscape.

The two HTTPS updates removed **both unencrypted-communication findings**:

- `User Browser -> Direct to App (no proxy)`
- `Reverse Proxy -> Juice Shop Application`

Changing persistent storage to `encryption: transparent` removed **one unencrypted-asset finding**:

- `Persistent Storage`

As a result, the total number of risks dropped from **23 to 20**, and elevated findings dropped from **4 to 2**.

These changes reduce exposure in exactly the way we would expect:

- HTTPS protects credentials, sessions, and application traffic in transit
- storage encryption reduces the impact of host-level disk compromise or offline access to stored data
- the remaining top risks are now mostly application-layer issues such as XSS, CSRF, missing authentication assumptions, and runtime hardening gaps

### Diagram comparison

The regenerated diagrams reflect the security-control changes while keeping the same overall architecture.

- [Baseline data-flow diagram](lab2/baseline/data-flow-diagram.png)
- [Secure data-flow diagram](lab2/secure/data-flow-diagram.png)
- [Baseline data-asset diagram](lab2/baseline/data-asset-diagram.png)
- [Secure data-asset diagram](lab2/secure/data-asset-diagram.png)

Observed difference:

- the **data-flow diagram** changes meaningfully because the browser/app and proxy/app links are now modeled as HTTPS
- the **data-asset diagram** changes only slightly, because the same logical data assets remain in scope even after hardening

---

## Bonus Analysis

### Hardening impact at a glance

- Total risks: `23 -> 20` (`-3`, about `13.0%` reduction)
- Elevated risks: `4 -> 2` (`-50%`)
- Unencrypted communication findings: `2 -> 0`
- Unencrypted asset findings: `2 -> 1`

### Risks removed by the secure variant

- `unencrypted-communication@user-browser>direct-to-app-no-proxy`
- `unencrypted-communication@reverse-proxy>to-app`
- `unencrypted-asset@persistent-storage`

### Residual high-priority themes after hardening

Even after the HTTPS and storage-encryption changes, the secure model still keeps important application risks:

- **XSS** remains elevated because transport security does not remove client-side injection flaws
- **Missing authentication** between proxy and app remains elevated because this is a trust and access-control concern, not just an encryption concern
- **CSRF**, **missing hardening**, and **SSRF** remain because they depend on application behavior and runtime design choices

This is a useful result: the secure variant proves that **infrastructure controls lower the transport/storage risk floor**, but **application security flaws still dominate the residual exposure** in Juice Shop.
