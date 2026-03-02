# Lab 2 — Threat Modeling with Threagile

![difficulty](https://img.shields.io/badge/difficulty-beginner–intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Threat%20Modeling%20(Threagile)-blue)
![points](https://img.shields.io/badge/points-10-orange)

> **Goal:** Model the **OWASP Juice Shop `bkimminich/juice-shop:v19.0.0`** deployment and generate an **automation-first** threat model with Threagile.  
> **Deliverable:** A PR from `feature/lab2` to the course repo with `labs/submission2.md` containing Threagile outputs and risk analysis. Submit the PR link via Moodle.

---

## Overview

In this lab you will practice:
- Creating an **as-code** model with **Threagile** and automatically generating **risk reports + diagrams** from YAML.
- Making security-relevant model changes and demonstrating how they **impact the risk landscape**.
- Analyzing threat model outputs and documenting security findings systematically.

These skills are essential for automated threat modeling and integrating security analysis into CI/CD pipelines.

> Keep using the Juice Shop from Lab 1 (`:19.0.0`) as your target application.

---

## Tasks

### Task 1 — Threagile Baseline Model (6 pts)

**Objective:** Use the provided Threagile model to generate a PDF report + diagrams and analyze the baseline risk posture.

#### 1.1: Generate Baseline Threat Model

1. **Setup and Execute Threagile:**

   ```bash
   mkdir -p labs/lab2/baseline labs/lab2/secure
   docker run --rm -v "$(pwd)":/app/work threagile/threagile \
     -model /app/work/labs/lab2/threagile-model.yaml \
     -output /app/work/labs/lab2/baseline \
     -generate-risks-excel=false -generate-tags-excel=false
   ```

2. **Verify Generated Outputs:**

   - `report.pdf` — full PDF report (includes diagrams)
   - Diagrams: data-flow & data-asset diagrams (PNG)
   - Risk exports: `risks.json`, `stats.json`, `technical-assets.json`

#### 1.2: Risk Analysis and Documentation

1. **Analyze Top 5 Risks:**

   Calculate composite scores using these weights:
   - Severity: critical (5) > elevated (4) > high (3) > medium (2) > low (1)
   - Likelihood: very-likely (4) > likely (3) > possible (2) > unlikely (1)
   - Impact: high (3) > medium (2) > low (1)
   - **Composite score** = `Severity*100 + Likelihood*10 + Impact`

In `labs/submission2.md`, document:
- **Top 5 Risks** table with Severity, Category, Asset, Likelihood, Impact
- Risk ranking methodology and composite score calculations
- Analysis of critical security concerns identified
- Screenshots or references to generated diagrams

---

### Task 2 — HTTPS Variant & Risk Comparison (4 pts)

**Objective:** Create a secure variant of the model and demonstrate how security controls affect the threat landscape.

#### 2.1: Create Secure Model Variant

1. **Modify Security Controls:**

   Copy the baseline model and make these specific changes:
   - **User Browser → communication_links → Direct to App**: set `protocol: https`
   - **Reverse Proxy → communication_links**: set `protocol: https`
   - **Persistent Storage**: set `encryption: transparent`
   - Save as: `labs/lab2/threagile-model.secure.yaml`

#### 2.2: Generate Secure Variant Analysis

1. **Execute Secure Model Analysis:**

   ```bash
   docker run --rm -v "$(pwd)":/app/work threagile/threagile \
     -model /app/work/labs/lab2/threagile-model.secure.yaml \
     -output /app/work/labs/lab2/secure \
     -generate-risks-excel=false -generate-tags-excel=false
   ```

2. **Generate Risk Comparison:**

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

In `labs/submission2.md`, document:
- **Risk Category Delta Table** (Baseline vs Secure vs Δ)
- **Delta Run Explanation** covering:
  - Specific changes made to the model
  - Observed results in risk categories
  - Analysis of why these changes reduced/modified risks
- Comparison of diagrams between baseline and secure variants

---

## Acceptance Criteria

- ✅ Branch `feature/lab2` exists with commits for each task.
- ✅ File `labs/submission2.md` contains required analysis for Tasks 1-2.
- ✅ Threagile baseline and secure models successfully generated.
- ✅ Both `labs/lab2/baseline/` and `labs/lab2/secure/` folders contain complete outputs.
- ✅ Top 5 risks analysis and risk category delta comparison documented.
- ✅ PR from `feature/lab2` → **course repo main branch** is open.
- ✅ PR link submitted via Moodle before the deadline.

---

## How to Submit

1. Create a branch for this lab and push it to your fork:

   ```bash
   git switch -c feature/lab2
   # create labs/submission2.md with your findings
   git add labs/submission2.md labs/lab2/
   git commit -m "docs: add lab2 submission"
   git push -u origin feature/lab2
   ```

2. Open a PR from your fork's `feature/lab2` branch → **course repository's main branch**.

3. In the PR description, include:

   ```text
   - [x] Task 1 done
   - [x] Task 2 done
   ```

4. **Copy the PR URL** and submit it via **Moodle before the deadline**.

---

## Rubric (10 pts)

| Criterion                                                    | Points |
| ------------------------------------------------------------ | -----: |
| Task 1 — Threagile baseline model + risk analysis           |  **6** |
| Task 2 — HTTPS variant + risk comparison analysis           |  **4** |
| **Total**                                                    | **10** |

---

## Guidelines

- Use clear Markdown headers to organize sections in `submission2.md`.
- Include both command outputs and written analysis for each task.
- Document threat modeling process and security findings systematically.
- Ensure all generated artifacts are properly committed to the repository.

> **Threat Modeling Notes**  
> 1. Model exactly the architecture you're running from Lab 1 (localhost deployment).  
> 2. Use consistent asset/link names between baseline and secure models for accurate diffs.  
> 3. Focus on actionable security insights rather than comprehensive risk catalogs.

> **Technical Tips**  
> 1. Verify report PDFs open correctly and diagrams render properly.  
> 2. Use the provided jq command exactly as shown for consistent delta tables.  
> 3. Keep explanations concise—one-page summaries are more valuable than detailed reports.  
> 4. Check that Threagile Docker container has proper file permissions for output generation.