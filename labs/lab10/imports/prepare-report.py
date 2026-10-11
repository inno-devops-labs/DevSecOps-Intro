#!/usr/bin/env python3
"""Adapt saved scanner evidence to DefectDojo 2.58.3's parser schemas."""
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def convert(kind, source, destination):
    data = json.loads(source.read_text())
    destination.parent.mkdir(parents=True, exist_ok=True)
    if kind == "zap":
        root = ET.Element("OWASPZAPReport", {
            key.removeprefix("@"): str(value)
            for key, value in data.items() if key.startswith("@")
        })
        for site in data["site"]:
            node = ET.SubElement(root, "site", {
                key.removeprefix("@"): str(value)
                for key, value in site.items() if key.startswith("@")
            })
            alerts = ET.SubElement(node, "alerts")
            for alert in site["alerts"]:
                item = ET.SubElement(alerts, "alertitem")
                for key, value in alert.items():
                    if key == "instances":
                        instances = ET.SubElement(item, key)
                        for instance in value:
                            child = ET.SubElement(instances, "instance")
                            for field, text in instance.items():
                                ET.SubElement(child, field).text = str(text)
                    else:
                        ET.SubElement(item, key).text = str(value)
        ET.indent(root)
        ET.ElementTree(root).write(destination, encoding="utf-8", xml_declaration=True)
    else:
        # This parser version understands Resources, not the newer Findings key.
        # Keep complete resource identity, Metadata and Results without filtering.
        if "Findings" in data:
            if "Resources" in data:
                raise ValueError("Both Findings and Resources present; refusing to overwrite")
            data["Resources"] = data.pop("Findings")
        destination.write_text(json.dumps(data, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["zap", "trivy-k8s"])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    convert(args.kind, args.source, args.destination)
