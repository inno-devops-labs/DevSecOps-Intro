# Lab 10 — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo local setup

Cloned [django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) into `labs/lab10/setup/django-DefectDojo`. I didn’t commit that folder — it’s huge, it’s in `.gitignore`; clone it again locally if you need to run the stack.

From the repo root:

```bash
docker compose build
docker compose up -d
docker compose ps
```

Admin password:

```bash
docker compose logs initializer | grep "Admin password:"
```

UI: `http://localhost:8080`, user `admin`.

API token for scripts (no need to click through the UI):

```bash
docker compose exec -T uwsgi python manage.py drf_create_token admin
```

Put the printed string in `DD_TOKEN`; don’t commit it.

---

## Task 2 — Import prior findings

| Tool | File |
| ---- | ---- |
| ZAP | `labs/lab5/zap/zap-report-noauth.xml` |
| Semgrep | `labs/lab5/semgrep/semgrep-results.json` |
| Trivy | `labs/lab4/trivy/trivy-vuln-detailed.json` |
| Nuclei | `labs/lab5/nuclei/nuclei-results.json` |
| Grype | `labs/lab4/syft/grype-vuln-results.json` |

**ZAP:** Dojo only eats XML for the “ZAP Scan” type. I had JSON from the lab (`zap-report-noauth.json`), so I added `labs/lab10/scripts/zap_json_to_xml.py` and generated `zap-report-noauth.xml`:

`py -3 labs/lab10/scripts/zap_json_to_xml.py labs/lab5/zap/zap-report-noauth.json labs/lab5/zap/zap-report-noauth.xml`

**Trivy:** Same JSON as `juice-shop-trivy-detailed.json`, copied to `trivy-vuln-detailed.json` because the lab sheet names that path.

**Nuclei:** Small JSON file so the importer has something to parse.

**`run-imports.sh`:** Semgrep must use type **Semgrep JSON Report** — if the script grabs “Semgrep Pro JSON Report” first, the import comes out empty. ZAP path must be the `.xml` file.

```bash
export DD_API="http://localhost:8080/api/v2"
export DD_TOKEN="<token>"
export DD_PRODUCT_TYPE="Engineering"
export DD_PRODUCT="Juice Shop"
export DD_ENGAGEMENT="Labs Security Testing"
bash labs/lab10/imports/run-imports.sh
```

API responses land in `labs/lab10/imports/import-*.json`.

Last full run I care about: tests **16–20** in the engagement — ZAP 11, Semgrep 25, Trivy 147, Nuclei 1, Grype 122 (306 total). I re-ran the script a few times while debugging, so the engagement picked up extra tests; you can delete the old ones in the UI if the numbers look noisy.

---

## Task 3 — Reporting & metrics

Files under `labs/lab10/report/`:

- `metrics-snapshot.md` — counts and table
- `dojo-report.html` — short HTML summary
- `findings.csv` — 1163 rows, pulled with the REST API (same fields as the UI)

**Numbers (from that export):** 1163 active findings; **602** High, **84** Critical, **314** Medium, **102** Low, **61** Info. **572** verified, **591** not; nothing mitigated yet. **84** with SLA ≤ 14 days left. Heaviest CWEs: **1333**, **407**, **22**, **79**, **20** — mix of app issues and dependency CVEs from Trivy/Grype piling on top of each other.

---

## Files worth knowing

| File | What it is |
| ---- | ---------- |
| `labs/lab10/imports/run-imports.sh` | bulk import |
| `labs/lab10/scripts/zap_json_to_xml.py` | JSON → XML for ZAP |
| `labs/lab10/report/metrics-snapshot.md` | snapshot |
| `labs/lab10/report/dojo-report.html` | HTML |
| `labs/lab10/report/findings.csv` | CSV dump |

---

## Cleanup

```bash
cd labs/lab10/setup/django-DefectDojo
docker compose down
```
