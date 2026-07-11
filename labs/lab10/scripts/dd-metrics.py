#!/usr/bin/env python3
"""
Lab 10 Bonus: pull metrics from DefectDojo via API and print a compact dashboard.
Reads token from labs/lab10/results/api-token.txt.
"""
import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path

DD_URL = "http://localhost:8080"
TOKEN_FILE = Path("labs/lab10/results/api-token.txt")
ENGAGEMENT_ID = 1


def api_get(path: str) -> dict:
    token = TOKEN_FILE.read_text().strip()
    req = urllib.request.Request(
        f"{DD_URL}{path}",
        headers={"Authorization": f"Token {token}"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def fetch_all(path: str) -> list:
    results = []
    next_url = path
    while next_url:
        data = api_get(next_url)
        results.extend(data.get("results", []))
        next_page = data.get("next")
        next_url = next_page.replace(DD_URL, "") if next_page else None
    return results


def main() -> int:
    findings = fetch_all(f"/api/v2/findings/?engagement={ENGAGEMENT_ID}&limit=100")
    total = len(findings)
    if not total:
        print("No findings in engagement.", file=sys.stderr)
        return 1

    by_severity = Counter(f["severity"] for f in findings)
    active = sum(1 for f in findings if f["active"])
    risk_accepted = sum(1 for f in findings if f["risk_accepted"])
    false_p = sum(1 for f in findings if f["false_p"])
    mitigated = sum(1 for f in findings if f["is_mitigated"])

    print(f"=== DefectDojo dashboard: engagement {ENGAGEMENT_ID} ===")
    print(f"Total findings ingested: {total}")
    print()
    print("Severity breakdown:")
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        print(f"  {sev:>10}: {by_severity.get(sev, 0)}")
    print()
    print("Workflow status:")
    print(f"  Active:         {active}")
    print(f"  Risk accepted:  {risk_accepted}")
    print(f"  False positive: {false_p}")
    print(f"  Mitigated:      {mitigated}")
    print()

    parsers = Counter(f["test"] for f in findings)
    print("Findings per test (parser):")
    for test_id, count in parsers.most_common():
        print(f"  test={test_id}: {count}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
