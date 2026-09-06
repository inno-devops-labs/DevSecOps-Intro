# Lab 5 — SAST and DAST: Reading the Code, Then Watching It Run

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-SAST%20%2B%20DAST-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Semgrep%20%2B%20ZAP-informational)

> **Goal:** Scan the running Juice Shop with ZAP, unauthenticated and then logged in, scan its source with Semgrep, and find one bug both tools agree on.
> **Deliverable:** A PR from `feature/lab5` with `submissions/lab5.md`. Submit the PR link via Moodle.
> **Builds on:** the image from Lab 1. **Used by:** Lab 10 imports both tools' reports into DefectDojo.

## Setup

- Docker, `jq`, `git`, about 1 GB of disk for the source clone.
- Semgrep: `pip install semgrep` (or `pipx install semgrep`); the course pins 1.176.
- ZAP runs from the `ghcr.io/zaproxy/zaproxy:stable` image, which is 2.4 GB. Pull it before the seminar, not during it.

ZAP is no longer an OWASP project: it moved to the Software Security Project in 2023 and its team is at Checkmarx since 2024. Search for "ZAP", not "OWASP ZAP", or you will land on outdated pages.

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab5
```

```bash
docker network create lab5-net 2>/dev/null || true
docker rm -f juice-shop 2>/dev/null || true
docker run -d --name juice-shop --network lab5-net -p 127.0.0.1:3000:3000 \
  bkimminich/juice-shop:v20.0.0
until curl -sf -o /dev/null http://127.0.0.1:3000/rest/admin/application-version; do sleep 2; done
mkdir -p labs/lab5/results && chmod 777 labs/lab5/results
```

`curl -sf` matters: without `-f`, curl treats an HTTP 500 as success and the loop exits before the app is up.

Provided in `labs/lab5/scripts/`: [`zap-auth.yaml`](lab5/scripts/zap-auth.yaml), the ZAP Automation Framework config for the authenticated scan, and [`compare_zap.sh`](lab5/scripts/compare_zap.sh), which prints both reports side by side. Read them before running them.

## Task 1 — DAST, twice (6 pts)

### 5.1 Unauthenticated baseline

<!-- verify:nonzero-ok zap-baseline exits non-zero when it finds anything -->
```bash
docker run --rm --network lab5-net -v "$(pwd)/labs/lab5/results:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -r baseline-report.html -J baseline-report.json
```

Two to three minutes. It ends with a `FAIL-NEW / WARN-NEW / PASS` line and exits non-zero when it finds anything, which is normal here. The baseline is passive: ZAP looks at traffic, it does not attack.

### 5.2 Authenticated full scan

<!-- produces: labs/lab5/results/auth-report.json for lab 10 -->
<!-- verify:skip a 10-20 minute active scan; run it by hand -->
```bash
docker run --rm --network lab5-net -e _JAVA_OPTIONS="-Xmx512m" \
  -v "$(pwd)/labs/lab5:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml -port 8090
```

Ten to twenty minutes: it logs in as `admin@juice-sh.op`, spiders the authenticated surface, then actively attacks it. `-Xmx512m` caps the JVM heap; without it the container is killed with no error at all.

### 5.3 Compare

<!-- verify:skip needs both reports from 5.1 and 5.2 -->
```bash
bash labs/lab5/scripts/compare_zap.sh \
  labs/lab5/results/baseline-report.json labs/lab5/results/auth-report.json
```

**Submit** in `submissions/lab5.md`, section `## Task 1`:

- Alert counts by risk level for both runs, and how long each took.
- **Which run reported more alerts in total, and which found the more serious ones?** Look at the highest risk level in each before you answer.
- Two alerts that only the authenticated run found, with their URLs, and one sentence each on why an anonymous request could not reach them.
- Three or four sentences: given your two numbers, why is "number of alerts" a bad way to compare two scans, and what would you report to a team lead instead? Then say what that implies for a pipeline whose only DAST step is `zap-baseline.py` against staging.

## Task 2 — SAST on the same version (4 pts)

Optional. Skipping it does not affect later labs, but the bonus needs it.

### 5.4 Clone the source at the tag you are running

```bash
git clone --depth 1 --branch v20.0.0 \
  https://github.com/juice-shop/juice-shop.git labs/lab5/semgrep/juice-shop
```

Pin the clone to the container's tag: scanning `main` while attacking v20.0.0 makes any correlation meaningless.

### 5.5 Scan

<!-- produces: labs/lab5/results/semgrep.json for lab 10 -->
<!-- verify:skip needs the clone from 5.4 and takes several minutes -->
```bash
semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets \
  --severity ERROR --severity WARNING \
  --json -o labs/lab5/results/semgrep.json \
  labs/lab5/semgrep/juice-shop
```

Three to five minutes. Parse timeouts and syntax errors on some files are expected here and do not invalidate the run.

<!-- verify:skip needs the scan output from 5.5 -->
```bash
jq '[.results[].extra.severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab5/results/semgrep.json
jq -r '[.results[].check_id] | group_by(.) | map({rule: .[0], n: length})
  | sort_by(-.n) | .[:10][] | "\(.n)\t\(.rule)"' labs/lab5/results/semgrep.json
jq '.errors | length' labs/lab5/results/semgrep.json
```

**Submit**, section `## Task 2`:

- The severity split, the rule table, and the error count.
- Semgrep flags files under `.github/workflows/` as well as application code. Name one such rule and connect it to Lecture 4.
- One finding you would suppress as a false positive: quote the file, line and rule, and say what about that specific code makes the rule wrong there. A generic answer scores zero.
- If you could fix exactly one rule's worth of findings this sprint, which and why?

## Bonus — One bug, two tools (2 pts)

The strongest finding is one both tools reach independently: a line of code and a working request against the running app.

<!-- verify:skip needs both reports -->
```bash
jq -r '[.site[].alerts[] | select(.riskcode|tonumber >= 2) | .name + " -> " + .instances[0].uri] | unique[]' \
  labs/lab5/results/auth-report.json
jq -r '[.results[] | .check_id + " -> " + .path + ":" + (.start.line|tostring)] | unique[]' \
  labs/lab5/results/semgrep.json | grep -v codefixes
```

**Submit**, section `## Bonus`:

- A table with at least one row: OWASP category, the ZAP alert and URL, the Semgrep rule and `file:line`.
- For your strongest row: the vulnerable source lines, the request ZAP used, and the fix you would open a PR with.
- Two or three sentences: which finding would you put first in the PR description, and why?

## Submit

<!-- verify:skip student fork files -->
```bash
git add submissions/lab5.md
git commit -m "feat(lab5): zap baseline and authenticated, semgrep, correlation"
git push -u origin feature/lab5
```

Do not commit `labs/lab5/results/` or the source clone; paste the numbers instead. Clean up with `docker rm -f juice-shop && docker network rm lab5-net && rm -rf labs/lab5/semgrep/juice-shop`.

## Acceptance criteria

- Task 1 (6): both reports exist; counts by risk level for each, taken from the JSON; the totals and the highest risk level compared across the two runs; two authenticated-only alerts with URLs and a reachability reason each; the CI answer addresses coverage, not tooling.
- Task 2 (4): severity split, rule table and error count from the actual run; a workflow-file rule connected to Lecture 4; a false positive identified by file, line and rule with code-specific reasoning; a one-rule fix argued.
- Bonus (2): at least one row where both tools point at the same behaviour, with the source lines, the request, and a concrete fix.

## Common pitfalls

- The wait loop needs `curl -sf`. Juice Shop answers 500 on some paths while starting, and plain `curl -s` accepts that as success.
- Without `_JAVA_OPTIONS="-Xmx512m"` the active scan is OOM-killed and the container simply disappears.
- `zap-auth.yaml` targets the hostname `juice-shop` on the Docker network. Rename the container, or drop `--network lab5-net`, and ZAP cannot reach it.
- The config logs in as `admin@juice-sh.op` / `admin123`. Change those and the authenticated scan silently becomes a second anonymous one.
- The ZAP image is 2.4 GB. On a seminar network, pull it in advance.
- Most Semgrep findings sit under `data/static/codefixes/`, the deliberately vulnerable teaching snippets. Filter them out before claiming you found something in the application itself.
- The authenticated run may report **fewer** alerts than the baseline. The passive baseline reports header and caching issues on every URL it sees, while the active run concentrates on a smaller authenticated surface. Read the risk levels, not the totals.

## Resources

- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) and [ZAP Docker guide](https://www.zaproxy.org/docs/docker/)
- [Semgrep registry](https://semgrep.dev/explore) and [rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
- [Pwning OWASP Juice Shop](https://pwning.owasp-juice.shop/) — which challenge each finding maps to
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/) for the categories in your correlation table
