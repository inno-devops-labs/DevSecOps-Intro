# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-Threat%20Modeling-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Threagile%20%2B%20STRIDE-informational)

> **Goal:** Generate a STRIDE-based threat model of OWASP Juice Shop with Threagile, then produce a secure-variant model and diff the risk reports.
> **Deliverable:** A PR from `feature/lab2` with `submissions/lab2.md` (risk count tables + analysis) and any updated/added Threagile YAML files. Submit PR link via Moodle.

---

## Overview

In this lab you will practice:
- Reading a real **Threagile YAML model** (assets, communication links, trust boundaries, data assets)
- Running **Threagile v0.9.1** in a container and reading its PDF + JSON risk reports
- Producing a **secure variant** by tightening a handful of fields (HTTPS, encrypted DB, prepared statements)
- **Diffing the risk reports** — the same model exercise you'd do in a real architectural review

> The skill is **reading + modifying** a declarative threat model and observing how each change moves the risk count. The Threagile rules themselves are the plumbing.

---

## Project State

**You should have from Lab 1:**
- A working `feature/lab2` branch (forked from `main` of your fork, see Lab 1 setup)
- `submissions/` directory in your fork
- A PR template that auto-fills your description

**This lab adds:**
- A reviewed/modified Threagile YAML for the baseline Juice Shop architecture
- A second YAML for the secure variant
- Risk-count tables + analysis in `submissions/lab2.md`

---

## Setup

```bash
# Verify you're on a fresh branch off main
git switch main && git pull
git switch -c feature/lab2

# Verify the lab plumbing is present
ls labs/lab2/threagile-model.yaml      # ~430 lines — read it before starting

# Pull the Threagile container image (course pins v0.9.1, March 2026)
docker pull threagile/threagile:0.9.1

# Make a working directory for generated reports (gitignored)
mkdir -p labs/lab2/output
```

> **Plumbing provided** (don't rewrite it; modify it for tasks below):
> - [`labs/lab2/threagile-model.yaml`](lab2/threagile-model.yaml) — baseline Juice Shop architecture (assets, comms, trust boundaries, data assets, abuse cases, security requirements)

---

## Task 1 — Baseline Threat Model (6 pts)

**Objective:** Run Threagile on the provided baseline model, read the risk report, and identify the top 5 risks the tool flags.

### 1.1: Generate the baseline report

```bash
# Run Threagile against the provided model
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml \
  -output /app/work/output

# Verify outputs exist
ls labs/lab2/output/
# Should see: report.pdf, risks.xlsx, risks.json, data-asset-diagram.png, data-flow-diagram.png
```

The DFD images (`*.png`) are useful — open them to visualize the architecture and trust boundaries from Lecture 2.

### 1.2: Read the risk report

Open `labs/lab2/output/report.pdf` (any PDF reader). Note:
- **Total risks** identified (front-matter summary)
- Risks grouped by **severity** (Critical / High / Elevated / Medium / Low)
- Each risk maps to a **rule ID** (e.g., `unencrypted-communication-link`, `missing-authentication`)

### 1.3: Top 5 risks table

Open `labs/lab2/output/risks.json` — it has the same data in machine-readable form. Generate a baseline summary:

```bash
# Count risks per severity (paste this output into your submission)
jq '[.[] | .severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab2/output/risks.json

# Top 5 risks by severity + technical asset
jq '[.[] | {severity, category, title, technical_asset: .most_relevant_technical_asset}] |
    sort_by(.severity) | .[:5]' \
  labs/lab2/output/risks.json
```

### 1.4: Document in `submissions/lab2.md`

Add a section like:

```markdown
## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical | <n> |
| High | <n> |
| Elevated | <n> |
| Medium | <n> |
| Low | <n> |
| **Total** | <n> |

### Top 5 risks (paste from `jq` output)
1. **<rule-id>** — <title>; severity <X>; affecting <asset>
2. ...

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **<S/T/R/I/D/E>** — <why, 1 sentence>
- Risk 2: ...

### Trust boundary observation
Looking at `data-flow-diagram.png`, name one arrow crossing a trust boundary that
appears in your top-5 risks. Why is that arrow particularly attractive to an attacker?
```

---

## Task 2 — Secure Variant & Risk Diff (4 pts)

> ⏭️ Optional. Skipping it won't affect future labs — but the diff is what makes threat modeling persuasive in PR review.

**Objective:** Create a hardened variant of the model (HTTPS + encrypted DB + prepared statements declared) and compare the two risk reports.

### 2.1: Create the secure variant

```bash
cp labs/lab2/threagile-model.yaml labs/lab2/threagile-model-secure.yaml
# YOUR TASK: edit threagile-model-secure.yaml to harden the architecture
```

**Required changes** (each is one field):

| Change | Where | What |
|---|---|---|
| Force HTTPS into the app | `communication_links` for user→app traffic | `protocol: https` (was `http`) |
| Encrypt at rest | the database asset under `technical_assets` | `encryption: data-with-symmetric-shared-key` (or stronger) |
| TLS for outbound calls | external integration link (`WebHook` or similar) | `protocol: https` |
| Declare prepared statements | the DB communication link | add a comment in the description that the app uses parameterized queries (Threagile reads the description for some heuristics) |
| Disable plain log writes | any logging link | encrypt the destination or remove the link |

> **Hint:** Threagile's full list of valid protocol values is in its documentation (the [Resources](#resources) section). Common ones for this lab: `https`, `mqtt-encrypted`, `jdbc-encrypted`, `nrpe-encrypted`.

### 2.2: Generate the secure-variant report

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml \
  -output /app/work/output-secure
```

### 2.3: Diff the risk counts

```bash
# Baseline counts
jq '[.[] | .severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab2/output/risks.json > /tmp/baseline-counts.json

# Secure-variant counts
jq '[.[] | .severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab2/output/output-secure/risks.json > /tmp/secure-counts.json

# Diff
diff -u /tmp/baseline-counts.json /tmp/secure-counts.json || true
```

### 2.4: Document in `submissions/lab2.md`

```markdown
## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | <a> | <b> | <b-a> |
| High | <a> | <b> | <b-a> |
| Elevated | <a> | <b> | <b-a> |
| Medium | <a> | <b> | <b-a> |
| Low | <a> | <b> | <b-a> |
| **Total** | <a> | <b> | <b-a> |

### Which rules are GONE in the secure variant?
List 3 rule IDs that fired in baseline but not in secure-variant:
1. `<rule-id>` — fixed by `<field change you made>`
2. ...

### Which rules are STILL THERE in the secure variant?
Threat modeling never reaches zero risk. List 2 rules that still fire and explain why
your changes didn't eliminate them (2-3 sentences each).

### Honesty check
Did the total drop more than 50%? If yes, what does that say about the cost-benefit
of these particular hardening changes vs. the work you'd need to fully eliminate the rest?
```

---

## Bonus Task — Model the Juice Shop Auth Flow (2 pts)

> 🌟 **Genuinely challenging.** This is the kind of focused threat model you'd do in a real architectural review of a specific feature.

**Objective:** Build a **new, smaller** Threagile model focused on Juice Shop's authentication flow (login → JWT → session → admin endpoints). Run it, identify auth-specific risks the baseline model missed.

### B.1: Build the focused model

Create `labs/lab2/threagile-model-auth.yaml`. You'll write this **from scratch** (don't copy-paste the baseline — the point is to think through which assets and links actually matter for auth).

```yaml
# YOUR TASK: Auth-focused Threagile model
# Required assets (minimum):
#   - Browser (external entity, in 'Internet' trust boundary)
#   - Juice Shop Auth API endpoint (process, in 'Container' trust boundary)
#   - Token signing/verification component (process, in 'Container' trust boundary)
#   - User DB credential store (data store, in 'Container' trust boundary)
#   - Admin endpoint (process, in 'Container' trust boundary)
#
# Required data assets (minimum):
#   - Credentials (username + password)
#   - JWT token (issued, returned, used)
#   - User session state
#   - Admin operation requests
#
# Required communication links (minimum):
#   - Browser → Auth API (login + register)
#   - Auth API → Token signer (request a JWT)
#   - Browser → API endpoints with JWT in Authorization header
#   - JWT verification on each protected request
#   - Browser → Admin endpoint (the JWT-must-have-admin-role flow)
#
# Hints:
#   - Look at Threagile docs: https://threagile.io/docs/model/
#   - Start with the smallest possible model; add complexity only where it reveals a risk
#   - The auth flow is mostly STRIDE-S (Spoofing) and STRIDE-E (Elevation) territory
#   - JWT signing keys are sensitive data assets — declare them
```

### B.2: Run + report

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-auth.yaml \
  -output /app/work/output-auth
```

### B.3: Document in `submissions/lab2.md`

```markdown
## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | <n> |
| High | <n> |
| ... |

### Three auth-specific risks (NOT in the baseline model's top 5)
For each, name:
- The rule ID Threagile fires
- The STRIDE letter
- A 1-2 sentence mitigation in plain English

1. **<rule-id>** — STRIDE: <X> — Mitigation: <...>
2. ...

### Reflection (2-3 sentences)
What did building the focused model surface that the baseline architecture model missed?
(Hint: feature-level threat models often find what architecture-level ones can't.)
```

---

## How to Submit

```bash
git add labs/lab2/threagile-model-secure.yaml      # Task 2
git add labs/lab2/threagile-model-auth.yaml        # Bonus (if done)
git add submissions/lab2.md
git commit -m "feat(lab2): Threagile threat model + secure variant + auth flow"
git push -u origin feature/lab2
```

> **Don't commit** `labs/lab2/output/` or `labs/lab2/output-*/` — they're regenerated outputs (already in `.gitignore`). The PR is the YAML files + the submission analysis.

PR checklist body:

```text
- [x] Task 1 — Baseline risk table + top-5 with STRIDE mapping
- [ ] Task 2 — Secure variant + risk diff table
- [ ] Bonus — Auth-flow model + 3 auth-specific risks
```

---

## Acceptance Criteria

### Task 1 (6 pts)
- ✅ Baseline Threagile run completes; `report.pdf` + `risks.json` exist
- ✅ Severity breakdown table in submission matches the actual `risks.json` counts
- ✅ Top 5 risks listed with rule ID + severity + asset (no placeholders)
- ✅ Each top-5 risk mapped to a STRIDE letter with a 1-sentence justification
- ✅ One trust-boundary-crossing arrow identified and explained

### Task 2 (4 pts)
- ✅ `threagile-model-secure.yaml` exists in the PR and shows ≥4 of the 5 required hardening changes
- ✅ Secure-variant Threagile run completes
- ✅ Diff table compares baseline vs secure-variant counts per severity
- ✅ ≥3 rule IDs identified as fixed; ≥2 still-firing rules explained
- ✅ Honesty check answered (no skipping the cost-benefit question)

### Bonus Task (2 pts)
- ✅ `threagile-model-auth.yaml` written from scratch (NOT a copy of baseline + edits)
- ✅ Model has ≥5 communication links and ≥4 data assets
- ✅ Threagile run completes; risks generated
- ✅ Three auth-specific risks identified that are NOT in baseline's top-5
- ✅ Each named with rule ID + STRIDE letter + 1-2 sentence mitigation

---

## Rubric

| Task | Points | Criteria |
|------|-------:|----------|
| **Task 1** — Baseline | **6** | Risk counts table + top-5 + STRIDE mapping + trust-boundary observation (all from real Threagile output) |
| **Task 2** — Secure variant | **4** | 4+ required hardening changes + diff table + 3 fixed + 2 still-firing explained + honesty check |
| **Bonus Task** — Auth flow | **2** | Custom YAML written from scratch, 3 auth-specific risks identified beyond baseline |
| **Total** | **12** | 10 main + 2 bonus |

---

## Resources

<details>
<summary>📚 Documentation</summary>

- [Threagile official site](https://threagile.io/) — Project + docs
- [Threagile model reference](https://threagile.io/docs/model/) — Every YAML field with examples
- [Threagile risk rules reference](https://threagile.io/docs/risks/) — All ~50 built-in rules
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) — STRIDE walkthrough
- [STRIDE on Wikipedia](https://en.wikipedia.org/wiki/STRIDE_model) — Quick recap (lecture 2 slide 7)

</details>

<details>
<summary>⚠️ Common Pitfalls</summary>

- 🚨 **`docker: invalid reference format`** — make sure you wrote `threagile/threagile:0.9.1` not `threagile:v0.9.1` (no namespace).
- 🚨 **Output directory empty after run** — Threagile needs write access. Verify the volume mount `-v "$(pwd)/labs/lab2":/app/work` and that `output/` exists with write perms before running.
- 🚨 **`undefined protocol: xyz`** — Threagile validates protocol enums. Common typo: `JDBC-encrypted` (capitalized) — use lowercase `jdbc-encrypted`.
- 🚨 **`the sheet name length exceeds the 31 characters limit`** — Threagile uses your model's `title:` as the Excel sheet name in `risks.xlsx`; Excel caps sheet names at 31 characters. Keep `title:` short (≤ 31 chars). The run dies at the Excel step, so you get JSONs and diagrams but no `risks.xlsx`/`report.pdf`. (The `Fontconfig error` lines are harmless noise — ignore them.)
- 🚨 **PDF is huge / slow to open** — that's normal. Use `risks.json` + `jq` for fast iteration; open the PDF only for the final report.
- 🚨 **Secure variant has MORE risks than baseline** — usually means you added a new asset without declaring its security requirements. Threagile rules can fire on new assets you accidentally introduced; review your diff carefully.
- 🚨 **"My auth-flow model has 50 risks!"** — that's usually because you copied the baseline model and trimmed it. Build the auth model **from scratch** — minimum viable assets + links + data. Threagile rules multiply on under-specified models.
- 💡 **PDF report front matter** shows the EXACT counts the rubric expects. If your submission says different numbers, re-run Threagile and check you opened the right output dir.

</details>

<details>
<summary>🪜 Looking ahead</summary>

The threat model you build here surfaces priorities for the rest of the course:
- **Lab 3** (Secure Git) — STRIDE-R (Repudiation) → signed commits + audit trail
- **Lab 5** (SAST/DAST) — focuses on the categories your top-5 highlighted
- **Lab 6** (IaC) — over-privileged IAM and network exposure (top hits Threagile usually finds)
- **Lab 9** (Runtime) — Falco rules for the behaviors your threat model said were highest-impact

Keep your `threagile-model.yaml` in mind through the semester. A good threat model is a guide for what to scan + monitor first.

</details>
