# Lab 5 — SAST + DAST: Scanning Juice Shop From Both Angles

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-SAST%20%2B%20DAST-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Semgrep%20%2B%20ZAP-informational)

> **Goal:** Run DAST (ZAP, both unauthenticated and authenticated) against the running Juice Shop, then run SAST (Semgrep) against its source code, and correlate at least one vulnerability that appears in both reports.
> **Deliverable:** A PR from `feature/lab5` with `submissions/lab5.md` (analysis + correlation table). Submit PR link via Moodle.

---

## Overview

In this lab you will practice:
- **DAST** with **OWASP ZAP** (Lecture 5) — baseline + full authenticated scan
- **SAST** with **Semgrep** (Lecture 5) — `p/owasp-top-ten` ruleset against Juice Shop source
- **Correlation** — finding a vulnerability that both tools detect; this is the highest-confidence finding type (Lecture 5 slide 15)

> Recall Lecture 5 slide 11: *authenticated DAST finds 10–20× more issues than unauth*. Don't skip the auth setup.

---

## Project State

**You should have from Labs 1-4:**
- Juice Shop v20.0.0 deployable locally (Lab 1)
- The CycloneDX SBOM from Lab 4 (informs which deps your SAST should focus on)
- Signed commits + pre-commit hooks working (Lab 3)

**This lab adds:**
- A baseline ZAP scan + a full authenticated ZAP scan
- A Semgrep scan of Juice Shop source code
- A correlation report showing 1+ vuln found by both

---

## Setup

You need:
- **Docker** (Juice Shop + ZAP run as containers)
- **Semgrep** — `pip install semgrep` (course pins **Semgrep CE 1.x latest**)
- **`jq`** + **`git`**
- **~3 GB free disk** for Juice Shop source code (~200 MB compressed; Semgrep needs space for its parser cache)

```bash
git switch main && git pull
git switch -c feature/lab5

# Verify
semgrep --version
docker --version
```

> **Plumbing provided** (already in `labs/lab5/scripts/`):
> - [`labs/lab5/scripts/zap-auth.yaml`](lab5/scripts/zap-auth.yaml) — ZAP Automation Framework config for authenticated scan
> - [`labs/lab5/scripts/compare_zap.sh`](lab5/scripts/compare_zap.sh) — script to diff baseline vs authenticated ZAP results
> - [`labs/lab5/scripts/summarize_dast.sh`](lab5/scripts/summarize_dast.sh) — produce a severity-count summary
>
> Read these files before running — they contain inline comments explaining design choices.

---

## Task 1 — DAST with OWASP ZAP (6 pts)

**Objective:** Run ZAP in baseline mode (unauthenticated) and full mode (authenticated), then analyze the gap.

### 5.1: Start Juice Shop on a dedicated network

```bash
docker network create lab5-net 2>/dev/null || true

docker run -d --name juice-shop --network lab5-net \
  -p 127.0.0.1:3000:3000 \
  bkimminich/juice-shop:v20.0.0

# Wait until it's ready
until curl -s -o /dev/null http://127.0.0.1:3000/rest/products; do sleep 2; done
echo "✅ Juice Shop ready"

mkdir -p labs/lab5/results
```

### 5.2: Baseline (unauthenticated) ZAP scan

```bash
docker run --rm --network lab5-net \
  -v "$(pwd)/labs/lab5/results:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 \
  -r baseline-report.html -J baseline-report.json
# Will print scan progress; expected to finish in 1-2 minutes
# Exits 2 if it finds issues — that's normal for Juice Shop
```

### 5.3: Authenticated ZAP scan with the Automation Framework

```bash
# The provided zap-auth.yaml drives the Automation Framework
# _JAVA_OPTIONS caps ZAP's JVM heap; without it the active scan OOM-kills the container
docker run --rm --network lab5-net \
  -e _JAVA_OPTIONS="-Xmx512m" \
  -v "$(pwd)/labs/lab5:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml -port 8090
# This takes 5-10 minutes — it crawls + actively scans authenticated routes
```

### 5.4: Compare the two reports

```bash
bash labs/lab5/scripts/compare_zap.sh \
  labs/lab5/results/baseline-report.json \
  labs/lab5/results/auth-report.json
# Prints a side-by-side severity count table
```

### 5.5: Document in `submissions/lab5.md`

```markdown
# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: <X minutes>
- Total alerts: <n>
| Severity | Count |
|----------|------:|
| High | <n> |
| Medium | <n> |
| Low | <n> |
| Informational | <n> |

### Authenticated full scan
- Duration: <X minutes>
- Total alerts: <n>
| Severity | Count |
|----------|------:|
| High | <n> |
| Medium | <n> |
| Low | <n> |
| Informational | <n> |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): <e.g., 18.5×>
- Did your run match the lecture's ratio? (2-3 sentences)
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. Alert title + severity
  2. Why was it unreachable to the unauthenticated scan? (1 sentence)
```

---

## Task 2 — SAST with Semgrep (4 pts)

> ⏭️ Optional. Skipping won't affect future labs, but the correlation in the bonus depends on having Semgrep output.

**Objective:** Clone Juice Shop source, run Semgrep with the OWASP Top 10 ruleset, analyze the top findings.

### 5.6: Clone the Juice Shop source

```bash
# Pin to the SAME tag as the running container so source ↔ binary correspondence is honest
git clone --depth 1 --branch v20.0.0 \
  https://github.com/juice-shop/juice-shop.git \
  labs/lab5/semgrep/juice-shop

du -sh labs/lab5/semgrep/juice-shop
# ~200 MB
```

### 5.7: Run Semgrep

```bash
# OWASP Top 10 community ruleset + JavaScript-specific rules
semgrep \
  --config=p/owasp-top-ten \
  --config=p/javascript \
  --config=p/secrets \
  labs/lab5/semgrep/juice-shop \
  --json -o labs/lab5/results/semgrep.json \
  --severity ERROR --severity WARNING

# Human-readable summary
semgrep \
  --config=p/owasp-top-ten \
  --config=p/javascript \
  labs/lab5/semgrep/juice-shop \
  --severity ERROR | tee labs/lab5/results/semgrep.txt
```

### 5.8: Analyze top findings

```bash
# Severity breakdown
jq '[.results[].extra.severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab5/results/semgrep.json

# Top 10 by rule ID frequency (Lecture 5 slide 8: "sort by rule ID frequency first")
jq '[.results[].check_id] | group_by(.) | map({rule: .[0], count: length}) |
    sort_by(-.count) | .[:10]' \
  labs/lab5/results/semgrep.json
```

### 5.9: Document in `submissions/lab5.md`

```markdown
## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | <n> |
| WARNING | <n> |
| INFO | <n> |
| **Total** | <n> |

### Top 10 rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| <e.g., javascript.express.security.injection.tainted-sql> | <n> | A03 |
| ... |

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
Why? (2-3 sentences. Likely answer: the highest-frequency rule that's not a duplicate
of patterns the team already knows about; one fix at the module level closes many findings.)

### False-positive sample
Pick **one** finding you'd suppress as a false positive after review. Quote the file path +
rule + 1-sentence reason. (NOT generic — must reference the specific code.)
```

---

## Bonus Task — SAST/DAST Correlation (2 pts)

> 🌟 **Genuinely valuable.** The strongest possible finding is one both tools agree on (Lecture 5 slide 15). Producing the correlation report is what real DevSecOps engineers do for a living.

**Objective:** Find at least one vulnerability that **both** Semgrep and ZAP report on the same component/endpoint. Write up the correlated finding.

### B.1: Cross-reference the reports

```bash
# Extract URLs/endpoints flagged by ZAP authenticated scan
jq -r '[.site[].alerts[].instances[].uri] | unique[]' \
  labs/lab5/results/auth-report.json | head -50 > /tmp/zap-urls.txt

# Extract file paths flagged by Semgrep
jq -r '[.results[].path] | unique[]' \
  labs/lab5/results/semgrep.json | head -50 > /tmp/semgrep-paths.txt

# YOUR TASK: find the overlap
# Hint: ZAP's URI '/rest/products/search' likely maps to a Semgrep finding
# in the routes/* or api/* directory of Juice Shop source
```

### B.2: Build the correlation table

For each correlated finding (you need ≥1, ideally 2-3):

```markdown
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | /rest/products/search?q=... | tainted-sql | routes/search.ts:42 | High (both agree) |
| 2 | ... |
```

### B.3: The fix — proposed remediation

For your strongest correlation (the one with highest severity in both reports):
1. **Paste the vulnerable code** from Semgrep's file:line
2. **Paste a working payload** from ZAP's report
3. **Write the fix** (parameterized query / output encoding / capability check / whatever applies)
4. **Why both tools caught it** (1-2 sentences — what made this discoverable from both angles?)

### B.4: Document in `submissions/lab5.md`

```markdown
## Bonus: SAST/DAST Correlation

### Correlation table
<paste the table from B.2>

### Strongest correlation deep-dive
<paste the work from B.3>

### Reflection (2-3 sentences)
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review,
which of these two would you want first — the SAST finding or the DAST evidence — and why?
```

---

## Cleanup (after submitting)

```bash
docker stop juice-shop
docker network rm lab5-net
rm -rf labs/lab5/semgrep/juice-shop      # 200MB; keep if you'll re-run; delete to save space
```

---

## How to Submit

```bash
git add submissions/lab5.md
git commit -m "feat(lab5): ZAP baseline + auth + Semgrep + correlation"
git push -u origin feature/lab5
```

> **Do NOT commit** `labs/lab5/results/` (scanner outputs are large and regeneratable) or `labs/lab5/semgrep/juice-shop/` (200MB clone). The submission paste-in is the evidence.

PR checklist body:

```text
- [x] Task 1 — ZAP baseline + auth + 10-20× ratio analysis
- [ ] Task 2 — Semgrep top-10 + triage shortcut
- [ ] Bonus — Correlation table with 1+ confirmed cross-tool finding
```

---

## Acceptance Criteria

### Task 1 (6 pts)
- ✅ Both ZAP runs complete (baseline + authenticated)
- ✅ Severity tables for both runs in submission match actual JSON output
- ✅ Auth/baseline ratio computed; lecture's 10-20× claim addressed honestly
- ✅ Two auth-only alerts identified with WHY each was unreachable to baseline (1 sentence each, specific)

### Task 2 (4 pts)
- ✅ Semgrep run against pinned v20.0.0 source (NOT main branch — must match running container)
- ✅ Severity breakdown + top-10-by-rule table populated
- ✅ Triage-shortcut answer references the specific rule with reasoning
- ✅ One concrete false-positive identified with specific file path + reason

### Bonus Task (2 pts)
- ✅ Correlation table with ≥1 row showing same vuln found by both Semgrep and ZAP
- ✅ Strongest correlation includes vulnerable code paste + working payload + fix
- ✅ "Why both tools caught it" reflection demonstrates understanding of static/dynamic complementarity

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — DAST | **6** | Both ZAP runs + ratio analysis + 2 auth-only-alert deep-dives |
| **Task 2** — SAST | **4** | Semgrep run + severity table + top-10 rules + triage-shortcut + FP sample |
| **Bonus Task** — Correlation | **2** | ≥1 confirmed correlated finding with code + payload + fix |
| **Total** | **12** | 10 main + 2 bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [Semgrep Registry](https://semgrep.dev/explore) — Every public ruleset including `p/owasp-top-ten`
- [Semgrep Rule Writing Guide](https://semgrep.dev/docs/writing-rules/overview/) — When you start writing custom rules
- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) — How `zap-auth.yaml` works
- [ZAP CLI Reference](https://www.zaproxy.org/docs/docker/) — Docker invocation patterns
- [OWASP Juice Shop Companion Guide](https://pwning.owasp-juice.shop/) — Maps each challenge to OWASP categories

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **`zap-auth.yaml` "context not found"** — the YAML targets `juice-shop:3000` (Docker network internal name). If you renamed the container or didn't attach both to the same `lab5-net` network, ZAP can't reach it. The container name in `docker run --name` must match exactly.
- 🚨 **Active scan dies silently (CPU 100% → container exit)** — ZAP's active scan is memory-hungry. The `_JAVA_OPTIONS="-Xmx512m"` flag in step 5.3 caps the JVM heap; omitting it lets ZAP consume all available RAM until the container is OOM-killed with no error message.
- 🚨 **Auth scan finds 0 alerts** — the `loginRequestBody` in `zap-auth.yaml` ships with the default Juice Shop admin creds (`admin@juice-sh.op` / `admin123`). If you changed them, auth scan logs in as anonymous and only sees unauth surface.
- 🚨 **`zap.sh -port 8090` instead of default 8080** — added in the plumbing because the previous lab version conflicted with users running things on 8080. Don't change it unless you also change the YAML.
- 🚨 **Semgrep `Parse error: ...`** — Juice Shop's TS sources occasionally hit edge cases. Add `--exclude='**/test/**'` to skip test fixtures if a single parse error blocks the whole scan.
- 🚨 **Semgrep takes 10 minutes** — the first run downloads the Semgrep registry. Subsequent runs use a cache; ~1-2 min is normal.
- 🚨 **Cloning juice-shop source via `--branch v20.0.0`** sometimes fails with "remote branch not found" — the upstream uses lightweight tags. Use `git clone --depth 1` then `git checkout v20.0.0` separately if needed.
- 💡 **Both tools must see the same code** for honest correlation — pinning the clone to `v20.0.0` matches the container exactly. Don't scan `main` of juice-shop and ZAP against a v20.0.0 container.

</details>

<details>
<summary>🪜 Looking ahead</summary>

- **Lab 7** (Container Security) re-uses the same Juice Shop image — Trivy will scan it as a container, complementing the SBOM-driven Grype scan from Lab 4
- **Lab 10** (DefectDojo) imports Semgrep AND ZAP output JSON; dedupe across tools is automatic. The correlation work you did manually in the bonus is what DefectDojo does at scale.

</details>
