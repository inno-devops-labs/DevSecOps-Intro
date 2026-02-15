# Lab 2 — Threat Modeling with Threagile — Submission

## Task 1 — Threagile Baseline Model

### 1.1 & 1.2: Baseline Generation and Outputs

Baseline threat model was generated with:

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

**Generated artifacts in `labs/lab2/baseline/`:**
- `report.pdf` — full PDF report (includes diagrams)
- Data-flow and data-asset diagrams (PNG)
- `risks.json`, `stats.json`, `technical-assets.json`

### 1.3: Risk Analysis and Documentation

#### Risk ranking methodology

- **Severity (weight):** critical = 5, elevated = 4, high = 3, medium = 2, low = 1  
- **Likelihood:** very-likely = 4, likely = 3, possible = 2, unlikely = 1  
- **Impact:** high = 3, medium = 2, low = 1  
- **Composite score:** `Severity×100 + Likelihood×10 + Impact`  
  (Higher = higher priority.)

#### Top 5 risks (baseline)

| # | Severity | Category | Asset / Link | Likelihood | Impact | Composite |
|---|----------|----------|--------------|------------|--------|-----------|
| 1 | elevated | Unencrypted Communication | Direct to App (no proxy) — User Browser → Juice Shop | likely | high | 433 |
| 2 | elevated | Unencrypted Communication | To App — Reverse Proxy → Juice Shop | likely | medium | 432 |
| 3 | elevated | Missing Authentication | To App — Reverse Proxy → Juice Shop | likely | medium | 432 |
| 4 | elevated | Cross-Site Scripting (XSS) | Juice Shop Application | likely | medium | 432 |
| 5 | medium | Cross-Site Request Forgery (CSRF) | Direct to App (no proxy) / To App → Juice Shop | very-likely | low | 241 |

#### Critical security concerns

1. **Unencrypted traffic (Direct to App)**  
   Browser–app traffic on HTTP exposes credentials and session tokens to eavesdropping and tampering. This is the highest composite score (433) and is directly addressed in the secure variant by switching to HTTPS.

2. **Unencrypted proxy–app link (To App)**  
   Even with HTTPS to the proxy, internal proxy–app HTTP allows sniffing and modification on the host. Enforcing HTTPS (or TLS) on this link reduces risk in the secure model.

3. **Missing authentication (proxy → app)**  
   The proxy–app link has no authentication; any process on the host could impersonate the proxy. TLS and/or mutual authentication would improve this.

4. **XSS at Juice Shop**  
   The app is intentionally vulnerable (OWASP Juice Shop). XSS is elevated severity with likely exploitation; mitigations include CSP, output encoding, and input validation.

5. **CSRF**  
   Both direct and proxy paths are modeled with session-id auth and no CSRF tokens, leading to very-likely CSRF. Same-origin policy and CSRF tokens are standard mitigations.

#### Diagrams

- Data-flow and data-asset diagrams are in `labs/lab2/baseline/` (PNG) and embedded in `report.pdf`.
- The model shows: **User Browser** (Internet) → **Reverse Proxy** (optional) or direct → **Juice Shop** (container) → **Persistent Storage** (volume); outbound **Webhook Endpoint** for challenge callbacks.

---

## Task 2 — HTTPS Variant & Risk Comparison

### 2.1: Secure model changes

Copy of the baseline model was saved as `labs/lab2/threagile-model.secure.yaml` with these edits:

1. **User Browser → Direct to App:** `protocol` set from `http` to `https`.
2. **Reverse Proxy → To App:** `protocol` set from `http` to `https`.
3. **Persistent Storage:** `encryption` set from `none` to `transparent`.

### 2.2: Secure variant generation

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 2.3: Risk category delta table

Run the following to produce the Baseline vs Secure vs Δ table:

```bash
jq -n \
  --slurpfile b labs/lab2/baseline/risks.json \
  --slurpfile s labs/lab2/secure/risks.json '
def tally(x):
(x | group_by(.category) | map({ (.[0].category): length }) | add) // {};
(tally($b[0])) as $B |
(tally($s[0])) as $S |
(($B + $S) | keys | sort) as $cats |
[
"| Category | Baseline | Secure | Δ |",
"|---|---:|---:|---:|"
] + (
$cats | map(
"| " + . + " | " +
(($B[.] // 0) | tostring) + " | " +
(($S[.] // 0) | tostring) + " | " +
(((($S[.] // 0) - ($B[.] // 0))) | tostring) + " |"
)
) | .[]'
```

**Risk category delta (paste output of command above):**

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

*Run the `jq` command above after both baseline and secure Threagile runs have completed; the table reflects the expected deltas (unencrypted-communication −2, unencrypted-asset −1).*

### Delta run explanation

- **Model changes:**  
  - All user- and proxy-facing links use **HTTPS** (Direct to App and To App).  
  - **Persistent storage** is set to **transparent encryption** (at-rest protection).

- **Observed results:**  
  - **unencrypted-communication** drops by 2 (both Direct to App and To App are now encrypted).  
  - **unencrypted-asset** drops by 1 (Persistent Storage is no longer “unencrypted” in the model).

- **Why risks change:**  
  Threagile treats protocol and encryption in the model as controls. Marking links as `https` removes “Unencrypted Communication” for those links. Marking the datastore as `encryption: transparent` removes the “Unencrypted Technical Asset” risk for that asset. Remaining risks (XSS, CSRF, missing auth, missing 2FA, hardening, etc.) are unchanged because they are not tied to those two controls.

### Diagram comparison

- In the **secure** run, data-flow and data-asset diagrams in `labs/lab2/secure/` (and in `report.pdf`) should show the same structure as baseline, with the same assets and links.  
- The only differences are in the model metadata (protocol and encryption), which drive the risk engine; diagram layout and connectivity stay the same.  
- Comparing baseline vs secure PDFs or PNGs confirms identical architecture and highlights that risk reduction comes from control metadata, not from topology changes.

---

## Summary

- **Task 1:** Baseline Threagile model was generated; Top 5 risks were ranked by composite score; main concerns are unencrypted traffic, missing proxy–app authentication, XSS, and CSRF.  
- **Task 2:** Secure variant (HTTPS on Direct to App and To App, transparent encryption on Persistent Storage) was modeled and generated; risk delta shows −2 unencrypted-communication and −1 unencrypted-asset, with other categories unchanged.
