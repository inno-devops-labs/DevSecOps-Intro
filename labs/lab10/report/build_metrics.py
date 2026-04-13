#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
CWE_NAMES = {
    20: "Improper Input Validation",
    22: "Path Traversal",
    79: "Cross-site Scripting",
    89: "SQL Injection",
    94: "Code Injection",
    400: "Uncontrolled Resource Consumption",
    407: "Inefficient Algorithmic Complexity",
    1321: "Prototype Pollution",
    1333: "Inefficient Regular Expression Complexity",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build Lab 10 metrics artifacts from an exported DefectDojo findings CSV."
    )
    parser.add_argument(
        "--csv",
        default="labs/lab10/report/findings.csv",
        type=Path,
        help="Source findings CSV exported from DefectDojo.",
    )
    parser.add_argument(
        "--json-out",
        default="labs/lab10/report/lab10-metrics.json",
        type=Path,
        help="Output JSON metrics file.",
    )
    parser.add_argument(
        "--snapshot-out",
        default="labs/lab10/report/metrics-snapshot.md",
        type=Path,
        help="Output stakeholder snapshot markdown file.",
    )
    parser.add_argument(
        "--captured-date",
        default=str(date.today()),
        help="Snapshot date in YYYY-MM-DD format.",
    )
    return parser.parse_args()


def is_true(value: str) -> bool:
    return value.strip().lower() == "true"


def parse_iso_date(value: str) -> date | None:
    value = value.strip()
    if not value:
        return None
    return date.fromisoformat(value)


def load_rows(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def build_metrics(rows: list[dict[str, str]], captured_date: date) -> dict[str, object]:
    active_by_severity = Counter()
    closed_by_severity = Counter()
    findings_per_tool = Counter()
    cwe_counts = Counter()
    tests: dict[int, dict[str, object]] = {}
    verified_findings = 0
    mitigated_findings = 0
    total_findings = len(rows)
    open_total = 0
    sla_overdue = 0
    sla_due_within_14_days = 0
    sla_due_within_14_days_by_severity = Counter()
    due_dates_by_severity: dict[str, Counter[date]] = defaultdict(Counter)

    product_id = None
    product_name = None
    engagement_id = None
    engagement_name = None

    for row in rows:
        severity = row.get("severity", "").strip() or "Info"
        scanner = row.get("found_by", "").strip() or "Unknown"
        active = is_true(row.get("active", ""))
        verified = is_true(row.get("verified", ""))
        mitigated = is_true(row.get("is_mitigated", ""))
        due_date = parse_iso_date(row.get("sla_expiration_date", ""))

        if verified:
            verified_findings += 1
        if mitigated:
            mitigated_findings += 1

        findings_per_tool[scanner] += 1

        if active and not mitigated:
            active_by_severity[severity] += 1
            open_total += 1
            if due_date is not None:
                due_dates_by_severity[severity][due_date] += 1
                if due_date < captured_date:
                    sla_overdue += 1
                elif due_date <= captured_date + timedelta(days=14):
                    sla_due_within_14_days += 1
                    sla_due_within_14_days_by_severity[severity] += 1
        else:
            closed_by_severity[severity] += 1

        cwe_raw = row.get("cwe", "").strip()
        if cwe_raw and cwe_raw != "0":
            cwe_counts[int(cwe_raw)] += 1

        test_id_raw = row.get("test_id", "").strip()
        if test_id_raw:
            test_id = int(test_id_raw)
            tests.setdefault(
                test_id,
                {
                    "id": test_id,
                    "title": None,
                    "test_type__name": scanner,
                },
            )

        if product_id is None and row.get("product_id", "").strip():
            product_id = int(row["product_id"])
        if product_name is None and row.get("product", "").strip():
            product_name = row["product"].strip()
        if engagement_id is None and row.get("engagement_id", "").strip():
            engagement_id = int(row["engagement_id"])
        if engagement_name is None and row.get("engagement", "").strip():
            engagement_name = row["engagement"].strip()

    next_due_dates = []
    for severity in SEVERITY_ORDER:
        if not due_dates_by_severity[severity]:
            continue
        earliest = min(due_dates_by_severity[severity])
        next_due_dates.append(
            {
                "severity": severity,
                "sla_expiration_date": earliest.isoformat(),
                "count": due_dates_by_severity[severity][earliest],
            }
        )

    top_cwe = [
        {
            "cwe": cwe,
            "name": CWE_NAMES.get(cwe),
            "count": count,
        }
        for cwe, count in cwe_counts.most_common(5)
    ]

    return {
        "captured_date": captured_date.isoformat(),
        "product_id": product_id,
        "product_name": product_name,
        "engagement_id": engagement_id,
        "engagement_name": engagement_name,
        "tests": [tests[key] for key in sorted(tests)],
        "total_findings": total_findings,
        "active_findings": open_total,
        "verified_findings": verified_findings,
        "mitigated_findings": mitigated_findings,
        "active_by_severity": {severity: active_by_severity[severity] for severity in SEVERITY_ORDER},
        "open_by_severity": {severity: active_by_severity[severity] for severity in SEVERITY_ORDER},
        "closed_by_severity": {severity: closed_by_severity[severity] for severity in SEVERITY_ORDER},
        "findings_per_tool": {
            tool: count
            for tool, count in sorted(
                findings_per_tool.items(), key=lambda item: (-item[1], item[0])
            )
        },
        "sla_overdue": sla_overdue,
        "sla_due_within_14_days": sla_due_within_14_days,
        "sla_due_within_14_days_by_severity": {
            severity: sla_due_within_14_days_by_severity[severity]
            for severity in SEVERITY_ORDER
        },
        "next_due_dates": next_due_dates,
        "top_cwe": top_cwe,
    }


def build_snapshot(metrics: dict[str, object]) -> str:
    active = metrics["active_by_severity"]
    findings_per_tool = metrics["findings_per_tool"]
    top_cwe = metrics["top_cwe"]
    next_due_dates = metrics["next_due_dates"]
    tests_list = ", ".join(f"`{test['test_type__name']}`" for test in metrics["tests"])
    lines = [
        "# Metrics Snapshot — Lab 10",
        "",
        f"- Date captured: `{metrics['captured_date']}`",
        (
            f"- Product / engagement: `{metrics['product_name']}` / "
            f"`{metrics['engagement_name']}`"
        ),
        (
            f"- Scope loaded into DefectDojo: `{len(metrics['tests'])}` tests "
            f"({tests_list})"
        ),
        "- Active findings:",
        f"  - Critical: `{active['Critical']}`",
        f"  - High: `{active['High']}`",
        f"  - Medium: `{active['Medium']}`",
        f"  - Low: `{active['Low']}`",
        f"  - Informational: `{active['Info']}`",
        (
            "- Verified vs. Mitigated notes: "
            f"`{metrics['verified_findings']}` findings are marked `Verified` and "
            f"`{metrics['mitigated_findings']}` are `Mitigated`, so this snapshot "
            "is a pre-remediation baseline rather than a post-fix state."
        ),
        (
            f"- Open vs. Closed summary: `{metrics['active_findings']}` open, "
            f"`{sum(metrics['closed_by_severity'].values())}` closed."
        ),
        "- Tool contribution:",
    ]

    for tool, count in findings_per_tool.items():
        lines.append(f"  - {tool}: `{count}`")

    if next_due_dates:
        first_due = next_due_dates[0]
        lines.append(
            (
                f"- SLA outlook as of `{metrics['captured_date']}`: "
                f"`{metrics['sla_overdue']}` overdue findings; "
                f"`{metrics['sla_due_within_14_days']}` "
                f"{first_due['severity'].lower()} findings are due within 14 days "
                f"and currently expire on `{first_due['sla_expiration_date']}`."
            )
        )
    else:
        lines.append(
            f"- SLA outlook as of `{metrics['captured_date']}`: no items are due within 14 days."
        )

    lines.append("- Top recurring non-zero CWE categories:")
    for item in top_cwe:
        lines.append(f"  - `CWE-{item['cwe']}` — `{item['count']}`")

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    captured_date = date.fromisoformat(args.captured_date)
    rows = load_rows(args.csv)
    metrics = build_metrics(rows, captured_date)

    args.json_out.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    args.snapshot_out.write_text(build_snapshot(metrics), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
