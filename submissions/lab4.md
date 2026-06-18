# Lab 4 — SBOM Generation & Software Composition Analysis on Juice Shop

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-SBOM%20%2B%20SCA-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Syft%20%2B%20Grype%20%2B%20Trivy-informational)

> **Goal:** Generate an SBOM of the Juice Shop image with Syft, scan it with Grype, compare against Trivy's all-in-one approach, and produce a signed-ready CycloneDX SBOM for Lab 8.
> **Deliverable:** A PR from `feature/lab4` with `submissions/lab4.md` + a `labs/lab4/juice-shop.cdx.json` SBOM committed to your fork. Submit PR link via Moodle.

---

## Overview

In this lab you will practice:
- Generating **CycloneDX** + **SPDX** SBOMs from a container image with **Syft**
- Scanning the same SBOM with **Grype** for CVEs (decoupled SCA)
- Running **Trivy** as an all-in-one alternative and comparing the result
- Producing a **CycloneDX SBOM** that Lab 8 will sign as an attestation

> Recall Lecture 4 slide 11: *"the SBOM is the answer to the next Log4Shell question — do my services depend on this library?"* The artifact you produce today is the operational instrument for incident response.

---

## Project State

**You should have from Labs 1-3:**
- Juice Shop v20.0.0 image pulled locally (Lab 1)
- A working `feature/labN` workflow with signed commits (Labs 1, 3)
- A pre-commit hook blocking secret leaks (Lab 3)

**This lab adds:**
- A CycloneDX SBOM of the Juice Shop image, committed to your fork (becomes Lab 8 input)
- A reproducible Grype CVE scan
- A side-by-side comparison report Syft+Grype vs Trivy

---

## Setup

You need:
- **Docker** (Juice Shop image already pulled from Lab 1; if not: `docker pull bkimminich/juice-shop:v20.0.0`)
- **`syft`** — `brew install syft` or [GitHub releases](https://github.com/anchore/syft/releases) (course pins Syft 1.x latest stable)
- **`grype`** — `brew install grype` or [GitHub releases](https://github.com/anchore/grype/releases) (course pins Grype 0.x latest stable)
- **`trivy`** — `brew install trivy` (course pins **Trivy v0.69.x** as of April 2026)
- **`jq`** — for JSON inspection

```bash
git switch main && git pull
git switch -c feature/lab4

# Verify tools are installed
syft version && grype version && trivy --version && jq --version

# Make a working dir for output (gitignored)
mkdir -p labs/lab4
```

---

## Task 1 — SBOM Generation & SCA with Syft + Grype (6 pts)

**Objective:** Generate two SBOM formats with Syft, run Grype against the CycloneDX SBOM, analyze the CVE findings.

### 4.1: Generate SBOMs with Syft

```bash
# CycloneDX JSON (the format Lab 8 will sign)
syft bkimminich/juice-shop:v20.0.0 \
  -o cyclonedx-json=labs/lab4/juice-shop.cdx.json

# SPDX JSON (for compliance contexts — covered in Lecture 4 slide 11)
syft bkimminich/juice-shop:v20.0.0 \
  -o spdx-json=labs/lab4/juice-shop.spdx.json

# Sanity check — both files exist and have content
ls -la labs/lab4/juice-shop.*.json
jq '.components | length' labs/lab4/juice-shop.cdx.json
# Should print a number like 200-500 (depends on Juice Shop v20 image contents)
```

### 4.2: Run Grype against the CycloneDX SBOM

> **Why scan the SBOM, not the image?** Decoupling the inventory (Syft) from the scanning (Grype) means: one SBOM → many scans over time. When a new CVE drops next month, re-running Grype on the same SBOM tells you instantly whether you're affected — no re-pulling the image.

```bash
# Scan via SBOM (the modern decoupled pattern)
grype sbom:labs/lab4/juice-shop.cdx.json \
  -o json --file labs/lab4/grype-from-sbom.json
grype sbom:labs/lab4/juice-shop.cdx.json \
  -o table | tee labs/lab4/grype-from-sbom.txt

# Severity breakdown
jq '[.matches[].vulnerability.severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab4/grype-from-sbom.json
```

### 4.3: Analyze the top findings

```bash
# Top 10 CVEs by severity, with fix availability
jq '[.matches[] | {cve: .vulnerability.id, severity: .vulnerability.severity,
                    package: .artifact.name, version: .artifact.version,
                    fix: (.vulnerability.fix.versions // [] | join(","))}] |
    sort_by(.severity) | .[:10]' \
  labs/lab4/grype-from-sbom.json
```

### 4.4: Document in `submissions/lab4.md`

```markdown
# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: <jq '.components | length' output>
- `juice-shop.cdx.json` size: <ls output>
- `juice-shop.spdx.json` component count: <jq '.packages | length' output>

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical | <n> |
| High | <n> |
| Medium | <n> |
| Low | <n> |
| Negligible | <n> |
| **Total** | <n> |

### Top 10 CVEs (paste from jq output)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| <CVE-id> | <Sev> | <pkg> | <ver> | <fix or empty> |
| ... |

### Fix-available rate
Out of the top 10 CVEs, how many have a fix available? What does that say about your
patch cadence priorities? (2-3 sentences. Reference Lecture 4's triage shortcut:
*sort by fix-available AND severity ≥ HIGH first*.)
```

---

## Task 2 — Trivy All-in-One Comparison (4 pts)

> ⏭️ Optional. Skipping won't affect future labs, but the comparison is interview-relevant: every DevSecOps engineer is asked "Syft+Grype or Trivy?" at some point.

**Objective:** Run Trivy directly against the image (not via SBOM), compare CVE counts to Grype, explain the differences.

### 4.5: Trivy image scan

```bash
# Direct image scan — Trivy's all-in-one mode
trivy image bkimminich/juice-shop:v20.0.0 \
  --severity LOW,MEDIUM,HIGH,CRITICAL \
  --format json --output labs/lab4/trivy.json

trivy image bkimminich/juice-shop:v20.0.0 \
  --severity HIGH,CRITICAL \
  --format table | tee labs/lab4/trivy.txt
```

### 4.6: Comparison table

```bash
# Trivy severity breakdown
jq '[.Results[].Vulnerabilities[]? | .Severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab4/trivy.json
```

### 4.7: Document in `submissions/lab4.md`

```markdown
## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | <a> | <b> | <b-a> |
| High | <a> | <b> | <b-a> |
| Medium | <a> | <b> | <b-a> |
| Low | <a> | <b> | <b-a> |
| **Total** | <a> | <b> | <b-a> |

### Why the difference?
Pick **two specific CVEs** that ONE tool found and the other didn't. For each:
1. CVE ID + tool that found it + tool that missed it
2. Why (likely): different CVE database refresh cadence? Different package matching rules? Different fix-version awareness?

(Lecture 4 mentioned that Grype and Trivy use slightly different DBs; this is where you see it.)

### When would you pick each?
2-3 sentences each:
- When does Syft+Grype's **decoupled** model win? (hint: SBOM-as-an-attestation, Lecture 4 + Lab 8)
- When does Trivy's **all-in-one** win? (hint: simpler CI step, broader scope including IaC + secrets + misconfig)
```

---

## Bonus Task — Sign-Ready SBOM for Lab 8 (2 pts)

> 🌟 **Genuinely useful.** Lab 8 will sign this SBOM as a Cosign attestation. Whatever you produce here goes directly into your Lab 8 work — get the format right.

**Objective:** Produce a CycloneDX SBOM that conforms to Cosign's expected predicate format and verify it's importable into DefectDojo (preview for Lab 10).

### B.1: Verify CycloneDX schema compliance

```bash
# CycloneDX spec version (Lab 8 + Cosign expect 1.5 or 1.6 in 2026)
jq '.specVersion, .bomFormat' labs/lab4/juice-shop.cdx.json
# Should print:
# "1.5" (or "1.6")
# "CycloneDX"

# CycloneDX requires a metadata.timestamp and metadata.tools section — verify
jq '.metadata.timestamp, .metadata.tools' labs/lab4/juice-shop.cdx.json
```

### B.2: Re-run Syft if needed

If `specVersion` came back below 1.5 (older Syft versions defaulted to 1.4), force a newer version:

```bash
syft bkimminich/juice-shop:v20.0.0 \
  -o "cyclonedx-json@1.5=labs/lab4/juice-shop.cdx.json"
```

### B.3: Validate the attestation predicate shape

```bash
# YOUR TASK: Produce labs/lab4/juice-shop-attestation.json
# Shape required by Cosign (in-toto v1 envelope, see Lecture 8 slide 9):
#
# {
#   "_type": "https://in-toto.io/Statement/v1",
#   "subject": [
#     { "name": "<your image ref>",
#       "digest": { "sha256": "<digest of juice-shop:v20.0.0>" } }
#   ],
#   "predicateType": "https://cyclonedx.org/bom/v1.5",
#   "predicate": <the FULL contents of juice-shop.cdx.json>
# }
#
# Hints:
#   - Get the image digest: docker inspect bkimminich/juice-shop:v20.0.0 \
#       --format '{{index .RepoDigests 0}}'  → returns sha256:abc...
#   - You can build this with `jq` in a one-liner; no need for python
#   - This file is what Lab 8 Task 2 will feed into `cosign attest --predicate ...`
```

### B.4: Document in `submissions/lab4.md`

```markdown
## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: <output>
- `bomFormat`: <output>

### Image digest captured
- `docker inspect ... RepoDigests`: <output — should be sha256:...>

### Attestation predicate (paste first 30 lines of juice-shop-attestation.json)
```
<paste — must show _type, subject (with digest), predicateType, predicate (truncated)>
```

### What this enables in Lab 8
1 paragraph: when Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`,
what specifically is being signed and what claim does it prove? (Reference Lecture 8 slide 9.)
```

---

## How to Submit

```bash
# Commit the SBOM (so Lab 8 can use it) but NOT the scan output files (too large, regenerable)
git add labs/lab4/juice-shop.cdx.json
git add labs/lab4/juice-shop.spdx.json
git add labs/lab4/juice-shop-attestation.json  # Bonus only
git add submissions/lab4.md
git commit -m "feat(lab4): juice-shop SBOM + Grype/Trivy comparison + sign-ready attestation"
git push -u origin feature/lab4
```

> **Do NOT commit** `labs/lab4/grype-from-sbom.*` and `labs/lab4/trivy.*` — they're regeneratable and large. Add them to your fork's `.gitignore` if helpful. The submission paste-in is the evidence.

PR checklist body:

```text
- [x] Task 1 — Syft SBOMs + Grype scan + top-10 CVE analysis
- [ ] Task 2 — Trivy comparison + when-to-pick-each tradeoff
- [ ] Bonus — sign-ready CycloneDX attestation for Lab 8
```

---

## Acceptance Criteria

### Task 1 (6 pts)
- ✅ `labs/lab4/juice-shop.cdx.json` and `juice-shop.spdx.json` exist in the PR
- ✅ Grype scan completes; severity breakdown table in submission matches actual JSON
- ✅ Top-10 CVE table populated with real CVE IDs (no placeholders); fix-availability shown
- ✅ Fix-available analysis (2-3 sentences) references Lecture 4's triage shortcut

### Task 2 (4 pts)
- ✅ Trivy scan output present in submission
- ✅ Side-by-side count table with deltas
- ✅ Two specific CVEs identified as tool-divergent; explained with 1-2 sentence reasoning each
- ✅ When-to-pick-each discussion shows understanding of decoupled vs all-in-one trade-offs

### Bonus Task (2 pts)
- ✅ `labs/lab4/juice-shop-attestation.json` exists in PR
- ✅ File has correct `_type`, `subject.digest`, `predicateType: cyclonedx`, `predicate` shape
- ✅ Image digest matches actual `docker inspect` output for the v20.0.0 tag
- ✅ Lab 8 paragraph correctly identifies *what's being signed* and *what claim is being made*

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — Syft + Grype | **6** | Both SBOM formats + Grype severity table + top-10 CVE table + fix-availability triage analysis |
| **Task 2** — Trivy comparison | **4** | Diff table + 2 tool-divergent CVEs explained + when-to-pick-each tradeoff |
| **Bonus Task** — Sign-ready attestation | **2** | Correct in-toto v1 shape + image digest captured + Lab 8 connection articulated |
| **Total** | **12** | 10 main + 2 bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [Syft documentation](https://github.com/anchore/syft/wiki) — Supported formats, image targets, output options
- [Grype documentation](https://github.com/anchore/grype/wiki) — Including the SBOM-input pattern
- [Trivy documentation](https://trivy.dev/) — Six targets including image, fs, sbom, k8s
- [CycloneDX 1.5 spec](https://cyclonedx.org/specification/overview/) — What `specVersion: "1.5"` actually requires
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) — The envelope shape for the bonus

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **`syft: failed to parse image source`** — usually a missing `bkimminich/` prefix or you forgot to pull the image first.
- 🚨 **Grype prints 0 vulnerabilities** — Juice Shop v20.0.0 has CVEs; if Grype reports 0, your DB is fresh-empty. Run `grype db update` and re-scan.
- 🚨 **Grype results differ between runs** — the CVE DB updates daily. Lock down with `--by-cve` or take a snapshot and reference the exact db checksum in your submission.
- 🚨 **Trivy "image not found" but the image is in `docker images`** — Trivy uses a local cache too. `trivy image --download-db-only` first.
- 🚨 **CycloneDX `specVersion: "1.4"`** — older Syft versions default to 1.4; Lab 8 + Cosign expect 1.5+. Use `cyclonedx-json@1.5` syntax.
- 🚨 **`docker inspect ... RepoDigests` is empty** — happens when you built the image locally instead of pulling it. Re-pull with `docker pull bkimminich/juice-shop:v20.0.0` to get the registry digest.
- 💡 **Top-10 by severity is alphabetic ordering** — `jq 'sort_by(.severity)'` sorts strings, so "Critical" comes before "High" alphabetically (which is correct), but "Negligible" sorts before "Critical" because of the N. Use a manual ordering or `--severity-cutoff` filter.

</details>

<details>
<summary>🪜 Looking ahead</summary>

The SBOM you commit today travels with you for three more labs:
- **Lab 5** — SAST/DAST against the same Juice Shop image
- **Lab 7** — container scan + Pod Security Standards on Juice Shop deploy
- **Lab 8** — `cosign attest --type cyclonedx --predicate juice-shop-attestation.json` (the bonus output here)
- **Lab 10** — DefectDojo ingests the Grype + Trivy reports + this SBOM for unified triage

If you skip the bonus, Lab 8 Task 2 will require you to regenerate the attestation predicate. Doing it now saves time later.

</details>
