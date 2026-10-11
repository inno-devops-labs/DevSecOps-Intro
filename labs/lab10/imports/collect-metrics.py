#!/usr/bin/env python3
"""Read paginated product findings and write credential-free capstone metrics."""
import collections
from datetime import date
import json
import os
from pathlib import Path
import statistics
import sys
import urllib.parse
import urllib.request

base = os.environ.get("DD_URL", "http://127.0.0.1:8080").rstrip("/") + "/api/v2/"
product_id = int(os.environ["DD_PRODUCT_ID"])
token = os.environ["DD_TOKEN"]
today = date.fromisoformat(os.environ.get("DD_AS_OF", date.today().isoformat()))
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(path):
    url = urllib.parse.urljoin(base, path)
    if urllib.parse.urlsplit(url).netloc != urllib.parse.urlsplit(base).netloc:
        raise ValueError("Refusing to send credentials to a foreign pagination URL")
    request = urllib.request.Request(url, headers={"Authorization": "Token " + token})
    with opener.open(request, timeout=60) as response:
        return json.load(response)


def all_results(path):
    records = []
    while path:
        response = get(path)
        records.extend(response["results"])
        path = response["next"]
    return records


findings = all_results(f"findings/?test__engagement__product={product_id}&limit=1000")
tests = {t["id"]: t for t in all_results("tests/?limit=1000")}
product = get(f"products/{product_id}/")
sla = get(f"sla_configurations/{product['sla_configuration']}/")
active = [f for f in findings if f["active"] and not f["duplicate"]
          and not f["false_p"] and not f["out_of_scope"] and not f["is_mitigated"]]
ages = [(today - date.fromisoformat(f["date"])).days for f in active]
eligible = [f for f in active if f["sla_expiration_date"]]
within = [f for f in eligible if date.fromisoformat(f["sla_expiration_date"]) >= today]
result = {
    "as_of": today.isoformat(), "product_id": product_id,
    "raw_records": len(findings), "duplicate_records": sum(f["duplicate"] for f in findings),
    "active_total": len(active),
    "active_by_severity": dict(collections.Counter(f["severity"] for f in active)),
    "active_by_source": dict(collections.Counter(tests[f["test"]]["scan_type"] for f in active)),
    "per_test": [{"id": tid, "parser": tests[tid]["scan_type"],
                  "raw": sum(f["test"] == tid for f in findings),
                  "active": sum(f["test"] == tid for f in active)}
                 for tid in sorted({f["test"] for f in findings})],
    "median_age_days": statistics.median(ages) if ages else None,
    "oldest_age_days": max(ages) if ages else None,
    "sla": {key: sla[key] for key in ["critical", "high", "medium", "low"]},
    "inside_sla": len(within), "sla_eligible": len(eligible),
    "without_sla": len(active) - len(eligible),
    "inside_sla_percent": round(100 * len(within) / len(eligible), 2) if eligible else None,
    "inside_sla_share_of_all_active_percent": round(100 * len(within) / len(active), 2) if active else None,
    "overdue_by_severity": dict(collections.Counter(f["severity"] for f in eligible if f not in within)),
}
destination = Path(sys.argv[1])
destination.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
