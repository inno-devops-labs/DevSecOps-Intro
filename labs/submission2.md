# Lab 2 Submission — Threat Modeling with Threagile

## Task 1 - Threagile Baseline Model

### 1.1 Generate Baseline Threat Model

Executed commands:

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 1.2 Verify Generated Outputs

Artifacts created in `labs/lab2/baseline/`:
- `report.pdf`
- `data-flow-diagram.png`
- `data-asset-diagram.png`
- `risks.json`
- `stats.json`
- `technical-assets.json`

Verification output:

```bash
$ ls -la labs/lab2/baseline
total 5088
drwxr-xr-x@ 8 a89088  staff      256 Feb 16 16:06 .
drwxr-xr-x@ 5 a89088  staff      160 Feb 16 16:06 ..
-rw-r--r--  1 a89088  staff   111869 Feb 16 16:07 data-asset-diagram.png
-rw-r--r--  1 a89088  staff   232261 Feb 16 16:07 data-flow-diagram.png
-rw-r--r--  1 a89088  staff  1310911 Feb 16 16:07 report.pdf
-rw-r--r--  1 a89088  staff    15848 Feb 16 16:07 risks.json
-rw-r--r--  1 a89088  staff      536 Feb 16 16:07 stats.json
-rw-r--r--  1 a89088  staff     5694 Feb 16 16:07 technical-assets.json
```

### 1.3 Risk Ranking Methodology

Scoring model:
- Severity: critical=5, elevated=4, high=3, medium=2, low=1
- Likelihood: very-likely=4, likely=3, possible=2, unlikely=1
- Impact: high=3, medium=2, low=1
- Composite score = `Severity*100 + Likelihood*10 + Impact`

Tie-breaking rule for equal scores: sort by category name and then by risk title for deterministic ranking.

### 1.4 Top 5 Risks (Baseline)

| Rank | Composite | Severity | Category | Asset | Likelihood | Impact |
|---:|---:|---|---|---|---|---|
| 1 | 433 | elevated | unencrypted-communication | user-browser | likely | high |
| 2 | 432 | elevated | cross-site-scripting | juice-shop | likely | medium |
| 3 | 432 | elevated | missing-authentication | juice-shop | likely | medium |
| 4 | 432 | elevated | unencrypted-communication | reverse-proxy | likely | medium |
| 5 | 241 | medium | cross-site-request-forgery | juice-shop | very-likely | low |

### 1.5 Baseline Risk Posture Analysis

Risk distribution from `stats.json`:
- elevated: 4
- medium: 14
- low: 5
- high: 0
- critical: 0

Key security concerns:
- The highest-ranked risk is unencrypted client-to-application communication carrying authentication data, which exposes credentials/tokens to interception.
- Unencrypted reverse-proxy to app traffic keeps sensitive internal traffic vulnerable to sniffing/tampering.
- Missing authentication on the reverse-proxy to app link indicates weak trust boundaries between components.
- XSS remains one of the top elevated risks and can be chained with session/token theft in browser-facing flows.
- CSRF appears as a high-likelihood medium-severity risk, suggesting request origin protections are insufficient.

### 1.6 Diagram References

- Data-flow diagram: `labs/lab2/baseline/data-flow-diagram.png`
- Data-asset diagram: `labs/lab2/baseline/data-asset-diagram.png`
- Full baseline report: `labs/lab2/baseline/report.pdf`

---

## Task 2 - HTTPS Variant and Risk Comparison

Pending completion in the next step.
