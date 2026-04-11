#!/usr/bin/env python3
"""Convert ZAP JSON report to DefectDojo-compatible ZAP XML."""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def add_text(parent: ET.Element, tag: str, value) -> None:
    child = ET.SubElement(parent, tag)
    child.text = text(value)


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: convert-zap-json-to-xml.py <input.json> <output.xml>",
            file=sys.stderr,
        )
        return 2

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    data = json.loads(in_path.read_text(encoding="utf-8"))

    root = ET.Element(
        "OWASPZAPReport",
        {
            "version": text(data.get("@version")),
            "generated": text(data.get("@generated")),
            "programName": text(data.get("@programName")),
        },
    )

    for site in as_list(data.get("site")):
        site_el = ET.SubElement(
            root,
            "site",
            {
                "name": text(site.get("@name")),
                "host": text(site.get("@host")),
                "port": text(site.get("@port")),
                "ssl": text(site.get("@ssl")),
            },
        )
        alerts_el = ET.SubElement(site_el, "alerts")

        for alert in as_list(site.get("alerts")):
            item_el = ET.SubElement(alerts_el, "alertitem")
            add_text(item_el, "pluginid", alert.get("pluginid"))
            add_text(item_el, "alertRef", alert.get("alertRef"))
            add_text(item_el, "alert", alert.get("alert") or alert.get("name"))
            add_text(item_el, "name", alert.get("name"))
            add_text(item_el, "riskcode", alert.get("riskcode"))
            add_text(item_el, "confidence", alert.get("confidence"))
            add_text(item_el, "riskdesc", alert.get("riskdesc"))
            add_text(item_el, "desc", alert.get("desc"))

            instances_el = ET.SubElement(item_el, "instances")
            for instance in as_list(alert.get("instances")):
                inst_el = ET.SubElement(instances_el, "instance")
                add_text(inst_el, "uri", instance.get("uri"))
                add_text(inst_el, "method", instance.get("method"))
                add_text(inst_el, "param", instance.get("param"))
                add_text(inst_el, "attack", instance.get("attack"))
                add_text(inst_el, "evidence", instance.get("evidence"))
                add_text(inst_el, "otherinfo", instance.get("otherinfo"))

            add_text(item_el, "count", alert.get("count"))
            add_text(item_el, "solution", alert.get("solution"))
            add_text(item_el, "otherinfo", alert.get("otherinfo"))
            add_text(item_el, "reference", alert.get("reference"))
            add_text(item_el, "cweid", alert.get("cweid"))
            add_text(item_el, "wascid", alert.get("wascid"))
            add_text(item_el, "sourceid", alert.get("sourceid"))

    ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(out_path, encoding="utf-8", xml_declaration=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
