#!/usr/bin/env python3
"""Generate Lab 10 metrics/report artifacts from a local DefectDojo instance."""

from __future__ import annotations

import csv
import html
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from pathlib import Path


SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


def api_get(base_url: str, token: str, path: str) -> dict:
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Token {token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def api_get_paginated(base_url: str, token: str, path: str) -> list[dict]:
    results: list[dict] = []
    next_url = base_url.rstrip("/") + "/" + path.lstrip("/")
    while next_url:
        request = urllib.request.Request(
            next_url,
            headers={"Authorization": f"Token {token}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(request) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if isinstance(payload, dict) and "results" in payload:
            results.extend(payload["results"])
            next_url = payload.get("next")
        elif isinstance(payload, list):
            results.extend(payload)
            next_url = None
        else:
            raise RuntimeError(f"Unexpected API payload for {path}: {type(payload)!r}")
    return results


def find_one(items: list[dict], key: str, expected: str) -> dict:
    for item in items:
        if item.get(key) == expected:
            return item
    raise RuntimeError(f"Could not find {key}={expected!r}")


def normalize_severity(value: str | None) -> str:
    if not value:
        return "Info"
    if value == "Informational":
        return "Info"
    return value


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def bool_value(item: dict, key: str, default: bool = False) -> bool:
    value = item.get(key, default)
    return bool(value)


def get_test_type_name(test: dict, test_type_map: dict[int, str]) -> str:
    name = test.get("test_type_name")
    if name:
        return name
    test_type = test.get("test_type")
    if isinstance(test_type, int):
        return test_type_map.get(test_type, f"TestType#{test_type}")
    return "Unknown"


def tool_bucket(name: str) -> str:
    lowered = name.lower()
    if "semgrep" in lowered:
        return "Semgrep"
    if "trivy" in lowered:
        return "Trivy"
    if "nuclei" in lowered:
        return "Nuclei"
    if "grype" in lowered:
        return "Grype"
    if "zap" in lowered:
        return "ZAP"
    return name


def summarize_findings(findings: list[dict], test_map: dict[int, dict], test_type_map: dict[int, str]) -> dict:
    active_by_severity = Counter()
    open_by_severity = Counter()
    closed_by_severity = Counter()
    tool_counts = Counter()
    cwe_counts = Counter()
    verified_count = 0
    mitigated_count = 0
    active_count = 0
    due_14_days = 0
    overdue = 0
    rows: list[dict] = []

    today = datetime.now(UTC).date()

    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        active = bool_value(finding, "active")
        verified = bool_value(finding, "verified")
        mitigated_at = parse_datetime(finding.get("mitigated"))
        mitigated = mitigated_at is not None
        test_id = finding.get("test")
        test = test_map.get(test_id, {})
        tool = tool_bucket(get_test_type_name(test, test_type_map))

        if active:
            active_by_severity[severity] += 1
            open_by_severity[severity] += 1
            active_count += 1
        else:
            closed_by_severity[severity] += 1

        if verified:
            verified_count += 1
        if mitigated:
            mitigated_count += 1

        tool_counts[tool] += 1

        cwe_value = finding.get("cwe")
        if cwe_value:
            cwe_counts[f"CWE-{cwe_value}"] += 1

        sla_days_remaining = finding.get("sla_days_remaining")
        if active and sla_days_remaining is not None:
            if sla_days_remaining < 0:
                overdue += 1
            elif sla_days_remaining <= 14:
                due_14_days += 1

        rows.append(
            {
                "id": finding.get("id"),
                "title": finding.get("title", ""),
                "severity": severity,
                "active": active,
                "verified": verified,
                "mitigated": finding.get("mitigated") or "",
                "status": finding.get("display_status") or ("Active" if active else "Closed"),
                "tool": tool,
                "test_title": test.get("title", ""),
                "cwe": cwe_value or "",
                "date": finding.get("date") or "",
                "sla_days_remaining": "" if sla_days_remaining is None else sla_days_remaining,
                "reporter": finding.get("reporter") or "",
            }
        )

    top_cwes = cwe_counts.most_common(5)
    top_findings = sorted(
        rows,
        key=lambda row: (SEVERITIES.index(row["severity"]) if row["severity"] in SEVERITIES else 99, row["id"]),
    )[:15]

    return {
        "today": today,
        "active_by_severity": active_by_severity,
        "open_by_severity": open_by_severity,
        "closed_by_severity": closed_by_severity,
        "tool_counts": tool_counts,
        "verified_count": verified_count,
        "mitigated_count": mitigated_count,
        "active_count": active_count,
        "due_14_days": due_14_days,
        "overdue": overdue,
        "top_cwes": top_cwes,
        "rows": rows,
        "top_findings": top_findings,
    }


def render_metrics_snapshot(path: Path, summary: dict) -> None:
    lines = [
        "# Metrics Snapshot — Lab 10",
        "",
        f"- Date captured: {summary['today'].isoformat()}",
        "- Active findings:",
    ]
    for severity in SEVERITIES:
        lines.append(f"  - {severity}: {summary['active_by_severity'][severity]}")
    notes = (
        f"{summary['verified_count']} findings are verified, "
        f"{summary['mitigated_count']} findings are mitigated, and "
        f"{summary['active_count']} remain active."
    )
    lines.append(f"- Verified vs. Mitigated notes: {notes}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_findings_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "id",
        "title",
        "severity",
        "status",
        "active",
        "verified",
        "mitigated",
        "tool",
        "test_title",
        "cwe",
        "date",
        "sla_days_remaining",
        "reporter",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def render_html_report(path: Path, engagement: dict, summary: dict) -> None:
    def severity_table_row(label: str, open_count: int, closed_count: int) -> str:
        return (
            f"<tr><td>{html.escape(label)}</td><td>{open_count}</td>"
            f"<td>{closed_count}</td></tr>"
        )

    severity_rows = "\n".join(
        severity_table_row(
            severity,
            summary["open_by_severity"][severity],
            summary["closed_by_severity"][severity],
        )
        for severity in SEVERITIES
    )
    tool_rows = "\n".join(
        f"<tr><td>{html.escape(tool)}</td><td>{count}</td></tr>"
        for tool, count in sorted(summary["tool_counts"].items())
    )
    cwe_rows = "\n".join(
        f"<li>{html.escape(cwe)}: {count}</li>" for cwe, count in summary["top_cwes"]
    ) or "<li>No CWE values were populated in the imported findings.</li>"
    finding_rows = "\n".join(
        (
            "<tr>"
            f"<td>{row['id']}</td>"
            f"<td>{html.escape(row['severity'])}</td>"
            f"<td>{html.escape(row['tool'])}</td>"
            f"<td>{html.escape(str(row['cwe']))}</td>"
            f"<td>{html.escape(row['status'])}</td>"
            f"<td>{html.escape(row['title'])}</td>"
            "</tr>"
        )
        for row in summary["top_findings"]
    )
    sla_sentence = (
        f"{summary['overdue']} overdue findings and {summary['due_14_days']} more due within 14 days."
        if summary["overdue"] or summary["due_14_days"]
        else "No findings are currently overdue or due within 14 days based on the SLA data returned by the local DefectDojo instance."
    )

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>DefectDojo Stakeholder Report</title>
  <style>
    :root {{
      --bg: #f6f3eb;
      --panel: #fffdf8;
      --ink: #202020;
      --muted: #6b6559;
      --accent: #9d3c1f;
      --border: #d8cfbf;
    }}
    body {{
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top right, #f2d7c2 0, rgba(242, 215, 194, 0) 35%),
        linear-gradient(180deg, #f8f5ee 0%, var(--bg) 100%);
    }}
    main {{
      max-width: 1080px;
      margin: 0 auto;
      padding: 40px 24px 64px;
    }}
    h1, h2 {{
      margin: 0 0 12px;
      line-height: 1.1;
    }}
    p, li {{
      font-size: 16px;
      line-height: 1.6;
    }}
    .hero, .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 20px 40px rgba(71, 46, 24, 0.08);
    }}
    .hero {{
      margin-bottom: 24px;
    }}
    .eyebrow {{
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 12px;
      font-weight: bold;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px;
      margin-top: 24px;
    }}
    .stat {{
      font-size: 34px;
      font-weight: bold;
      color: var(--accent);
      margin-top: 8px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 15px;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
    }}
    .section {{
      margin-top: 24px;
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="eyebrow">Lab 10 Report</div>
      <h1>DefectDojo Stakeholder Summary</h1>
      <p>
        Engagement: <strong>{html.escape(engagement.get('name', 'Unknown engagement'))}</strong><br>
        Date captured: <strong>{summary['today'].isoformat()}</strong>
      </p>
      <p>
        This report consolidates imported findings from ZAP, Semgrep, Trivy, Nuclei, and Grype
        into a single view for triage, communication, and basic governance tracking.
      </p>
    </section>

    <section class="grid">
      <div class="panel">
        <div class="eyebrow">Open Findings</div>
        <div class="stat">{summary['active_count']}</div>
        <p>Active findings currently requiring remediation or disposition.</p>
      </div>
      <div class="panel">
        <div class="eyebrow">Verified</div>
        <div class="stat">{summary['verified_count']}</div>
        <p>Findings confirmed by imported evidence or platform state.</p>
      </div>
      <div class="panel">
        <div class="eyebrow">Mitigated</div>
        <div class="stat">{summary['mitigated_count']}</div>
        <p>Findings already closed or mitigated in the current dataset.</p>
      </div>
    </section>

    <section class="grid section">
      <div class="panel">
        <h2>Severity Mix</h2>
        <table>
          <thead><tr><th>Severity</th><th>Open</th><th>Closed</th></tr></thead>
          <tbody>{severity_rows}</tbody>
        </table>
      </div>
      <div class="panel">
        <h2>Findings Per Tool</h2>
        <table>
          <thead><tr><th>Tool</th><th>Findings</th></tr></thead>
          <tbody>{tool_rows}</tbody>
        </table>
      </div>
    </section>

    <section class="grid section">
      <div class="panel">
        <h2>SLA Outlook</h2>
        <p>{html.escape(sla_sentence)}</p>
      </div>
      <div class="panel">
        <h2>Recurring CWE Categories</h2>
        <ul>{cwe_rows}</ul>
      </div>
    </section>

    <section class="panel section">
      <h2>Highest-Priority Findings</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Severity</th><th>Tool</th><th>CWE</th><th>Status</th><th>Title</th></tr>
        </thead>
        <tbody>{finding_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""
    path.write_text(html_doc, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "Usage: generate_artifacts.py <api_base> <token> <product_name> <engagement_name> <output_dir>",
            file=sys.stderr,
        )
        return 2

    api_base, token, product_name, engagement_name, output_dir = sys.argv[1:]
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    products = api_get_paginated(api_base, token, "/products/?limit=200")
    product = find_one(products, "name", product_name)

    engagements = api_get_paginated(
        api_base,
        token,
        f"/engagements/?limit=200&product={product['id']}",
    )
    engagement = find_one(engagements, "name", engagement_name)

    tests = api_get_paginated(
        api_base,
        token,
        f"/tests/?limit=500&engagement={engagement['id']}",
    )
    test_map = {test["id"]: test for test in tests}

    test_types = api_get_paginated(api_base, token, "/test_types/?limit=2000")
    test_type_map = {item["id"]: item["name"] for item in test_types}

    findings = api_get_paginated(
        api_base,
        token,
        f"/findings/?limit=2000&test__engagement={engagement['id']}",
    )
    if not findings:
        findings = [
            finding
            for finding in api_get_paginated(api_base, token, "/findings/?limit=2000")
            if finding.get("test") in test_map
        ]

    summary = summarize_findings(findings, test_map, test_type_map)
    render_metrics_snapshot(out_dir / "metrics-snapshot.md", summary)
    render_findings_csv(out_dir / "findings.csv", summary["rows"])
    render_html_report(out_dir / "dojo-report.html", engagement, summary)

    summary_payload = {
        "product": product,
        "engagement": engagement,
        "tests": tests,
        "findings_count": len(findings),
        "active_count": summary["active_count"],
        "verified_count": summary["verified_count"],
        "mitigated_count": summary["mitigated_count"],
        "active_by_severity": dict(summary["active_by_severity"]),
        "open_by_severity": dict(summary["open_by_severity"]),
        "closed_by_severity": dict(summary["closed_by_severity"]),
        "tool_counts": dict(summary["tool_counts"]),
        "top_cwes": summary["top_cwes"],
        "due_14_days": summary["due_14_days"],
        "overdue": summary["overdue"],
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary_payload, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary_payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
