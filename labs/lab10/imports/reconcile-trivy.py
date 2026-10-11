"""Use manage.py shell after confirming all supplied tests scan the same artifact.

DD_PRODUCT_ID, DD_CANONICAL_TESTS and DD_DUPLICATE_TESTS are mandatory.
Only exact advisory/component/version/path/severity matches are merged. Inspect
the JSON plan first; set DD_APPLY=true to apply it through Dojo's duplicate helper.
"""
import json
import os

from django.db import transaction
from dojo.finding.deduplication import set_duplicate
from dojo.models import Finding, Test

product = int(os.environ["DD_PRODUCT_ID"])
canonical_ids = json.loads(os.environ["DD_CANONICAL_TESTS"])
duplicate_ids = json.loads(os.environ["DD_DUPLICATE_TESTS"])
ids = set(canonical_ids + duplicate_ids)
tests = Test.objects.filter(pk__in=ids, engagement__product_id=product,
                            test_type__name="Trivy Scan")
if set(tests.values_list("pk", flat=True)) != ids:
    raise ValueError("All tests must be Trivy scans in the selected product")


def identity(finding):
    path = (finding.file_path or "").lstrip("/")
    # OS findings encode the image reference in file_path, rather than a file.
    if " (debian " in path and path.startswith("bkimminich/juice-shop"):
        path = "os:" + path.split(" (", 1)[1]
    return (finding.vuln_id_from_tool or finding.title,
            finding.component_name, finding.component_version,
            path, finding.severity)


originals = {}
for finding in Finding.objects.filter(test_id__in=canonical_ids,
                                       active=True, duplicate=False).order_by("date", "id"):
    originals.setdefault(identity(finding), finding)
plan = []
for finding in Finding.objects.filter(test_id__in=duplicate_ids,
                                       active=True, duplicate=False).order_by("id"):
    original = originals.get(identity(finding))
    if original:
        plan.append((finding, original))
print(json.dumps([{"duplicate": f.id, "canonical": c.id, "title": f.title}
                  for f, c in plan], indent=2))
if os.environ.get("DD_APPLY") == "true":
    with transaction.atomic():
        for finding, original in plan:
            set_duplicate(finding, original)
    print(f"Merged {len(plan)} confirmed repeated artifact findings")
