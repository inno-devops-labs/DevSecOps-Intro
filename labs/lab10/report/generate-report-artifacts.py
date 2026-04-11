#!/usr/bin/env python3
"""Generate Lab 10 reporting artifacts from DefectDojo API exports."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
FINDINGS_JSON = BASE_DIR / "findings.json"
TESTS_JSON = BASE_DIR / "tests.json"
TEST_TYPES_JSON = BASE_DIR / "test_types.json"

METRICS_MD = BASE_DIR / "metrics-snapshot.md"
REPORT_HTML = BASE_DIR / "dojo-report.html"
FINDINGS_CSV = BASE_DIR / "findings.csv"
METRICS_JSON = BASE_DIR / "metrics-summary.json"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Informational"]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def normalize_severity(severity: str | None) -> str:
    if not severity:
        return "Informational"
    if severity == "Info":
        return "Informational"
    return severity


def tool_name_from_test_type(test_type_name: str) -> str:
    name = (test_type_name or "").lower()
    if "zap" in name:
        return "ZAP"
    if "semgrep" in name:
        return "Semgrep"
    if "trivy" in name:
        return "Trivy"
    if "nuclei" in name:
        return "Nuclei"
    if "grype" in name:
        return "Grype"
    return "Other"


def main() -> int:
    findings_data = load_json(FINDINGS_JSON)
    tests_data = load_json(TESTS_JSON)
    test_types_data = load_json(TEST_TYPES_JSON)

    findings = findings_data.get("results", [])
    tests = tests_data.get("results", [])
    test_types = test_types_data.get("results", [])

    test_type_by_id: dict[int, str] = {
        int(item["id"]): item.get("name", "") for item in test_types if "id" in item
    }
    test_to_type_name: dict[int, str] = {}
    for test in tests:
        test_id = test.get("id")
        test_type_id = test.get("test_type")
        if test_id is None or test_type_id is None:
            continue
        test_to_type_name[int(test_id)] = test_type_by_id.get(int(test_type_id), "Unknown")

    today = date.today()
    due_14_date = today + timedelta(days=14)

    active_counts = Counter()
    open_by_severity = Counter()
    closed_by_severity = Counter()
    tool_counts = Counter()
    cwe_counts = Counter()
    verified_count = 0
    mitigated_count = 0
    sla_breached = 0
    sla_due_14 = 0

    csv_rows: list[dict[str, Any]] = []

    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        is_open = bool(finding.get("active"))
        is_verified = bool(finding.get("verified"))
        is_mitigated = bool(finding.get("is_mitigated")) or bool(finding.get("mitigated"))

        if is_open:
            active_counts[severity] += 1
            open_by_severity[severity] += 1
        else:
            closed_by_severity[severity] += 1

        if is_verified:
            verified_count += 1
        if is_mitigated:
            mitigated_count += 1

        cwe = finding.get("cwe")
        if isinstance(cwe, int) and cwe > 0:
            cwe_counts[cwe] += 1

        test_id = finding.get("test")
        test_type_name = test_to_type_name.get(int(test_id), "Unknown") if test_id else "Unknown"
        tool_name = tool_name_from_test_type(test_type_name)
        tool_counts[tool_name] += 1

        sla_date = parse_date(finding.get("sla_expiration_date"))
        if is_open and sla_date:
            if sla_date < today:
                sla_breached += 1
            elif today <= sla_date <= due_14_date:
                sla_due_14 += 1

        csv_rows.append(
            {
                "id": finding.get("id"),
                "title": finding.get("title"),
                "severity": severity,
                "active": is_open,
                "verified": is_verified,
                "mitigated": finding.get("mitigated"),
                "test_id": test_id,
                "test_type": test_type_name,
                "tool": tool_name,
                "cwe": cwe or "",
                "sla_expiration_date": finding.get("sla_expiration_date") or "",
                "date": finding.get("date") or "",
                "url": finding.get("url") or "",
                "vuln_id_from_tool": finding.get("vuln_id_from_tool") or "",
                "component_name": finding.get("component_name") or "",
                "component_version": finding.get("component_version") or "",
            }
        )

    # Ensure all expected severities appear with 0 defaults.
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        active_counts.setdefault(sev, 0)
        open_by_severity.setdefault(sev, 0)
        closed_by_severity.setdefault(sev, 0)
    for tool in ["ZAP", "Semgrep", "Trivy", "Nuclei", "Grype"]:
        tool_counts.setdefault(tool, 0)

    top_cwes = cwe_counts.most_common(5)
    generated = datetime.now().isoformat(timespec="seconds")

    METRICS_MD.write_text(
        "\n".join(
            [
                "# Metrics Snapshot — Lab 10",
                "",
                f"- Date captured: {today.isoformat()}",
                "- Active findings:",
                f"  - Critical: {active_counts['Critical']}",
                f"  - High: {active_counts['High']}",
                f"  - Medium: {active_counts['Medium']}",
                f"  - Low: {active_counts['Low']}",
                f"  - Informational: {active_counts['Informational']}",
                (
                    "- Verified vs. Mitigated notes: "
                    f"{verified_count} verified findings; {mitigated_count} mitigated findings."
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )

    with FINDINGS_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "id",
                "title",
                "severity",
                "active",
                "verified",
                "mitigated",
                "test_id",
                "test_type",
                "tool",
                "cwe",
                "sla_expiration_date",
                "date",
                "url",
                "vuln_id_from_tool",
                "component_name",
                "component_version",
            ],
        )
        writer.writeheader()
        writer.writerows(csv_rows)

    cwe_rows = ""
    if top_cwes:
        cwe_rows = "\n".join(
            f"<li>CWE-{cwe}: {count} findings</li>" for cwe, count in top_cwes
        )
    else:
        cwe_rows = "<li>No CWE IDs present in imported findings.</li>"

    REPORT_HTML.write_text(
        f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>DefectDojo Report — Lab 10</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; line-height: 1.5; }}
    h1, h2 {{ margin-bottom: 0.4rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
    th {{ background: #f5f5f5; }}
    .muted {{ color: #666; font-size: 0.95rem; }}
  </style>
</head>
<body>
  <h1>DefectDojo Reporting Snapshot — Lab 10</h1>
  <p class="muted">Generated: {generated}</p>

  <h2>Open vs Closed by Severity</h2>
  <table>
    <thead><tr><th>Severity</th><th>Open</th><th>Closed</th></tr></thead>
    <tbody>
      <tr><td>Critical</td><td>{open_by_severity['Critical']}</td><td>{closed_by_severity['Critical']}</td></tr>
      <tr><td>High</td><td>{open_by_severity['High']}</td><td>{closed_by_severity['High']}</td></tr>
      <tr><td>Medium</td><td>{open_by_severity['Medium']}</td><td>{closed_by_severity['Medium']}</td></tr>
      <tr><td>Low</td><td>{open_by_severity['Low']}</td><td>{closed_by_severity['Low']}</td></tr>
      <tr><td>Informational</td><td>{open_by_severity['Informational']}</td><td>{closed_by_severity['Informational']}</td></tr>
    </tbody>
  </table>

  <h2>Findings by Tool</h2>
  <table>
    <thead><tr><th>Tool</th><th>Findings</th></tr></thead>
    <tbody>
      <tr><td>ZAP</td><td>{tool_counts['ZAP']}</td></tr>
      <tr><td>Semgrep</td><td>{tool_counts['Semgrep']}</td></tr>
      <tr><td>Trivy</td><td>{tool_counts['Trivy']}</td></tr>
      <tr><td>Nuclei</td><td>{tool_counts['Nuclei']}</td></tr>
      <tr><td>Grype</td><td>{tool_counts['Grype']}</td></tr>
    </tbody>
  </table>

  <h2>SLA Outlook</h2>
  <ul>
    <li>SLA breached (open findings): {sla_breached}</li>
    <li>SLA due in next 14 days (open findings): {sla_due_14}</li>
  </ul>

  <h2>Top CWE Categories</h2>
  <ul>
    {cwe_rows}
  </ul>
</body>
</html>
""",
        encoding="utf-8",
    )

    summary = {
        "generated_at": generated,
        "active_by_severity": dict(active_counts),
        "open_by_severity": dict(open_by_severity),
        "closed_by_severity": dict(closed_by_severity),
        "verified_count": verified_count,
        "mitigated_count": mitigated_count,
        "findings_per_tool": dict(tool_counts),
        "sla_breached": sla_breached,
        "sla_due_next_14_days": sla_due_14,
        "top_cwe": [{"cwe": cwe, "count": count} for cwe, count in top_cwes],
        "total_findings": len(findings),
    }
    METRICS_JSON.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
