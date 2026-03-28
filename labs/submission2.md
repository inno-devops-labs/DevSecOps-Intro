# Lab 2 Submission — Threat Modeling with Threagile

## Task 1 — Threagile Baseline Model

### 1.1 Baseline generation command

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure

docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 1.2 Generated baseline outputs

`labs/lab2/baseline/` contains:

- `report.pdf`
- `data-flow-diagram.png`
- `data-asset-diagram.png`
- `risks.json`
- `stats.json`
- `technical-assets.json`

Baseline stats summary:

- Total risks: `23`
- Severity distribution: `elevated=4`, `medium=14`, `low=5`, `high=0`, `critical=0`

### 1.3 Risk ranking methodology

Composite scoring formula:

`Composite score = Severity*100 + Likelihood*10 + Impact`

Weight mapping used:

- Severity: `critical=5`, `elevated=4`, `high=3`, `medium=2`, `low=1`
- Likelihood: `very-likely=4`, `likely=3`, `possible=2`, `unlikely=1`
- Impact: `high=3`, `medium=2`, `low=1`

Example calculations:

- `unencrypted-communication` (User Browser): `4*100 + 3*10 + 3 = 433`
- `cross-site-scripting` (Juice Shop Application): `4*100 + 3*10 + 2 = 432`

### Top 5 risks (baseline)

| Rank | Composite | Severity | Category | Asset | Likelihood | Impact |
|---:|---:|---|---|---|---|---|
| 1 | 433 | elevated | unencrypted-communication | User Browser | likely | high |
| 2 | 432 | elevated | cross-site-scripting | Juice Shop Application | likely | medium |
| 3 | 432 | elevated | missing-authentication | Juice Shop Application | likely | medium |
| 4 | 432 | elevated | unencrypted-communication | Reverse Proxy | likely | medium |
| 5 | 241 | medium | cross-site-request-forgery | Juice Shop Application | very-likely | low |

### Baseline risk analysis

- No `critical` risks were generated, but there are `4` `elevated` findings.
- Highest-score risks are dominated by lack of transport encryption (`unencrypted-communication`).
- `cross-site-scripting` remains one of the most significant application-layer risks.
- `missing-authentication` on the proxy-to-app path indicates insufficient trust hardening for internal communication.
- `cross-site-request-forgery` still appears as very likely, indicating browser-driven attack exposure.

### Baseline diagram references

- `labs/lab2/baseline/data-flow-diagram.png`
- `labs/lab2/baseline/data-asset-diagram.png`
- `labs/lab2/baseline/report.pdf`

## Task 2 — HTTPS Variant & Risk Comparison

### 2.1 Secure variant model changes

File created: `labs/lab2/threagile-model.secure.yaml`

Changes applied:

- `User Browser -> Direct to App (no proxy)`: `protocol: http -> https`
- `Reverse Proxy -> To App`: `protocol: http -> https`
- `Persistent Storage`: `encryption: none -> transparent`

### 2.2 Secure generation command

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

Secure stats summary:

- Total risks: `20`
- Severity distribution: `elevated=2`, `medium=13`, `low=5`, `high=0`, `critical=0`

### 2.3 Risk category delta table (Baseline vs Secure)

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

- Net change is `-3` risks (`23 -> 20`) and `elevated` risks reduced from `4 -> 2`.
- Removed risks:
  - `unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop`
  - `unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop`
  - `unencrypted-asset@persistent-storage`
- No new risks were introduced in the secure variant.
- Why the reduction happened:
  - Setting both relevant communication links to HTTPS removed transport-layer plaintext findings.
  - Setting persistent storage encryption to transparent removed one unencrypted-at-rest finding.
- Why many categories did not change:
  - Controls added in this variant target transport and storage encryption only.
  - Risks tied to authn/authz design, app hardening, WAF, vaulting, and SSRF remained outside this specific change set.

### Diagram comparison references

- Baseline: `labs/lab2/baseline/data-flow-diagram.png`, `labs/lab2/baseline/data-asset-diagram.png`
- Secure: `labs/lab2/secure/data-flow-diagram.png`, `labs/lab2/secure/data-asset-diagram.png`
- Full reports: `labs/lab2/baseline/report.pdf`, `labs/lab2/secure/report.pdf`

