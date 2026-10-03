# Lab 10 — Vulnerability Management: The Capstone

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Vuln%20Management-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-DefectDojo-informational)

> **Goal:** Put nine weeks of scanner output into one system, make the duplicates collapse, decide what the deadlines are, and write the report a manager would act on.
> **Deliverable:** A PR from `feature/lab10` with `submissions/lab10.md` and, for the bonus, `submissions/lab10-walkthrough.md`. Submit the PR link via Moodle.
> **Builds on:** the scan outputs from Labs 4 to 7. Labs 8 and 9 produce evidence DefectDojo has no parser for; you will account for that in Task 1.

## Setup

- Docker Compose and about 4 GB of free memory: DefectDojo runs six containers.
- `jq` and `curl`.
- The reports from Labs 4 to 7. Regenerate any you deleted; the importer skips what it cannot find and tells you which.

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab10
mkdir -p labs/lab10/work
```

## Task 1 — Stand it up and load it (6 pts)

### 10.1 Start DefectDojo

<!-- verify:skip clones and starts six containers; run once by hand -->
```bash
cd labs/lab10/work
git clone --branch 2.58.3 --depth 1 https://github.com/DefectDojo/django-DefectDojo.git dd
cd dd
./docker/setEnv.sh release
docker compose up -d
docker compose logs -f initializer | grep -i 'admin password'
cd -
```

Pin the clone. `main` is 3.x, which renames importer parsers and will not match the names below.

Use `release`, not `dev`. The dev profile publishes PostgreSQL on port 5432, so if anything else on your machine already uses it, the stack fails with `Bind for 0.0.0.0:5432 failed: port is already allocated` and you get a half-started DefectDojo.

Startup takes several minutes. The admin password appears once, in the initializer log.

### 10.2 Get an API token

<!-- verify:skip needs the password from 10.1 -->
```bash
export DD_URL="http://localhost:8080"
export DD_TOKEN=$(curl -s -X POST "$DD_URL/api/v2/api-token-auth/" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password from the initializer log>"}' | jq -r .token)

curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/products/" | jq .count
```

The UI has the same token under Profile, but this is the scriptable path and the one CI would use.

### 10.3 Create the product and engagement

<!-- verify:skip needs the token from 10.2 -->
```bash
PT=$(curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/product_types/" \
  | jq -r '.results[0] | "\(.id) \(.name)"'); echo "product type: $PT"

PRODUCT_ID=$(curl -s -X POST "$DD_URL/api/v2/products/" \
  -H "Authorization: Token $DD_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"name\":\"OWASP Juice Shop\",\"description\":\"DevSecOps-Intro capstone\",\"prod_type\":${PT%% *}}" | jq -r .id)

ENGAGEMENT_ID=$(curl -s -X POST "$DD_URL/api/v2/engagements/" \
  -H "Authorization: Token $DD_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"name\":\"Course Semester Run\",\"product\":$PRODUCT_ID,\"target_start\":\"2026-09-01\",\"target_end\":\"2026-12-15\",\"engagement_type\":\"CI/CD\",\"status\":\"In Progress\"}" | jq -r .id)
echo "product=$PRODUCT_ID engagement=$ENGAGEMENT_ID"
```

Note the product type name that came back. On a stock instance the first one is `Research and Development`, and the importer has to agree with it or every import is rejected.

### 10.4 Import everything

<!-- verify:skip needs the token and the earlier labs' reports -->
```bash
bash labs/lab10/imports/run-imports.sh
```

`DD_URL` and `DD_TOKEN` from 10.2 are what the importer reads. Do not `source
env.sample` after that step: it would put the placeholder token back over yours.
The file is a reference for the variables the script accepts.

The importer discovers the parser names from your instance, imports every report it finds, prints the finding count per file, and exits non-zero if any import failed. Expect `SKIP` lines for reports you did not keep.

The parsers it maps to, in case you import by hand:

| Lab | File | Parser |
|---|---|---|
| 4 | `grype-from-sbom.json` | `Anchore Grype` |
| 4, 7 | `trivy.json`, `trivy-image.json` | `Trivy Scan` |
| 5 | `semgrep.json` | `Semgrep JSON Report` |
| 5 | `auth-report.json` | `ZAP Scan` |
| 6 | `checkov-terraform/results_json.json` | `Checkov Scan` |
| 6 | `kics-*/results.json` | `KICS Scan` |
| 7 | `trivy-k8s.json` | `Trivy Operator Scan` |

`Semgrep JSON Report` and `Semgrep Pro JSON Report` are different parsers and the Pro one does not read community output.

### 10.5 Look at what you have

<!-- verify:skip needs a loaded instance -->
```bash
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/tests/" \
  | jq -r '.results[] | "\(.id)\t\(.scan_type)"'

curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?active=true&limit=1000" \
  | jq -c '[.results[].severity] | group_by(.) | map({severity: .[0], count: length})'

curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?limit=1000" \
  | jq -c '[.results[].title] | group_by(.) | map(select(length > 1) | {title: .[0], n: length}) | .[:5]'
```

**Submit** in `submissions/lab10.md`, section `## Task 1`:

- The DefectDojo version, and the parser name for each file you imported, with its finding count.
- Active findings by severity, and the total.
- Two titles that appear more than once, and whether each is one issue counted twice or two separate findings. Say how you decided.
- Three or four sentences: you now have one number for the whole project. Which of the nine labs contributed findings you would act on this week, and which contributed noise? Be specific about why.

## Task 2 — Make it a program (4 pts)

Optional. Findings are not a program until someone owes someone else a date.

### 10.6 Set the deadlines

<!-- verify:skip needs a loaded instance -->
```bash
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/sla_configurations/" \
  | jq -r '.results[] | "\(.name): critical=\(.critical) high=\(.high) medium=\(.medium) low=\(.low)"'
```

A stock instance ships `critical=7 high=30 medium=90 low=120` days. Change it, in the UI under Configuration or through the API, to numbers you are prepared to defend, and record what you changed and why.

### 10.7 Report

**Submit**, section `## Task 2`:

- Your SLA numbers next to the defaults, with a sentence per row on why yours differ.
- Active findings by severity and by source tool.
- Three numbers, with the query or calculation you used for each: the median age of active findings, the age of the oldest one, and the share of active findings currently inside their SLA.
- One sentence on what Labs 8 and 9 produced that none of these numbers include, and what you would do about that.
- Any finding you would risk-accept, with an expiry date and the compensating control. "We will not fix this" without a date is not a decision.
- An executive summary of three sentences: where the project stands, the single biggest risk, and what you need in order to close it.

## Bonus — The five-minute walkthrough (2 pts)

Write `submissions/lab10-walkthrough.md`: the script you would use in an interview when asked "tell me about a security project you have worked on".

Constraints: five minutes spoken, roughly 700 words. It must cover what you built across the ten labs, one specific finding you traced from scanner output to a fix, one thing that did not work and what you did about it, and the number you would put on a slide. No tool list without a decision attached to it.

**Submit**: the file, plus three or four sentences in `submissions/lab10.md` on which part of the semester was hardest to explain concisely, and what that tells you about how you would document the next project.

## Acceptance criteria

- Task 1 (6): DefectDojo running at the pinned version; every available report imported with its parser and count; severity totals from the API; two duplicate titles judged with reasoning; the which-lab-mattered answer names labs and reasons.
- Task 2 (4): SLA numbers changed and defended against the defaults; findings broken down by severity and tool; median age, oldest age and SLA compliance each reported with the method used; the gap left by Labs 8 and 9 acknowledged; a risk acceptance with an expiry and a compensating control; a three-sentence summary that a manager could act on.
- Bonus (2): the walkthrough exists, fits five minutes, and contains a traced finding and a failure, not a tool list.
## Submit

<!-- verify:skip student fork files -->
```bash
git add <proof of work + lab10.md> (submissions/lab10.md, bonus: submissions/lab10-walkthrough.md, ...)
git commit -m "feat(lab10): defectdojo capstone + governance report"
git push -u origin feature/lab10
```

Do not commit `labs/lab10/work/` or the importer's response files. Clean up with `docker compose down -v` from inside `labs/lab10/work/dd`.


## Common pitfalls

- Cloning `main` gives DefectDojo 3.x, whose parser names differ from the table above. Pin to `2.58.3`.
- `./docker/setEnv.sh dev` publishes PostgreSQL on 5432 and collides with any local database. Use `release`.
- The importer sends a product type name. If it disagrees with the type of an existing product with the same name, every import fails with a product-type conflict. The default in `run-imports.sh` matches what 10.3 creates.
- A failed import still returns HTTP 400 with a JSON error, and `curl` exits 0. The shipped importer checks the status code; if you import by hand, read the response body.
- `Semgrep Pro JSON Report` will accept your file and find nothing useful. Use `Semgrep JSON Report`.
- The initializer prints the admin password exactly once. If you missed it, `docker compose logs initializer | grep -i password` still has it.
- DefectDojo takes several minutes to become usable. An HTTP 502 in the first minutes is the stack still starting.

## Resources

- [DefectDojo documentation](https://docs.defectdojo.com/) and the [supported parsers list](https://docs.defectdojo.com/en/connecting_your_tools/parsers/)
- [DefectDojo API v2](https://docs.defectdojo.com/en/api/api-v2-docs/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [EPSS](https://www.first.org/epss/) — for deciding what "critical" means to you
- [OWASP SAMM](https://owaspsamm.org/model/) — the maturity language for your governance report
