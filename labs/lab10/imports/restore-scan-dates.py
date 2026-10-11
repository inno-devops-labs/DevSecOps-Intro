"""Run via manage.py shell; restore evidenced dates without restarting SLA clocks.

DD_PRODUCT_ID selects the product. DD_TEST_DATES is a JSON object mapping test
IDs to original scan dates, verified against retained scanner/report provenance.
"""
import json
import os
from datetime import date

from django.db import transaction
from dojo.models import Finding, Test

product_id = int(os.environ["DD_PRODUCT_ID"])
dates = {int(key): date.fromisoformat(value)
         for key, value in json.loads(os.environ["DD_TEST_DATES"]).items()}
tests = Test.objects.filter(pk__in=dates, engagement__product_id=product_id)
if set(tests.values_list("id", flat=True)) != set(dates):
    raise ValueError("Every supplied test must belong to the specified product")
if any(value > date.today() for value in dates.values()):
    raise ValueError("Scan dates cannot be in the future")

with transaction.atomic():
    count = 0
    for test in tests:
        original = dates[test.id]
        test.target_start = original
        test.target_end = original
        test.save(update_fields=["target_start", "target_end"])
        for finding in Finding.objects.filter(test=test):
            finding.date = original
            finding.sla_start_date = original
            finding.set_sla_expiration_date()
            finding.save(update_fields=["date", "sla_start_date", "sla_expiration_date"])
            count += 1
print(f"Restored original scan/SLA dates on {count} findings")
