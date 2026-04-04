#!/usr/bin/env python3
"""Convert OWASP ZAP JSON report (modern format) to XML expected by DefectDojo ZAP Scan importer."""
import json
import sys
import xml.etree.ElementTree as ET


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: zap_json_to_xml.py <input.json> <output.xml>", file=sys.stderr)
        sys.exit(1)
    in_path, out_path = sys.argv[1], sys.argv[2]
    with open(in_path, encoding="utf-8") as f:
        data = json.load(f)

    root = ET.Element("OWASPZAPReport")
    root.set("version", "2.0")
    for site in data.get("site", []):
        site_el = ET.SubElement(root, "site")
        site_el.set("name", str(site.get("@name", "")))
        site_el.set("host", str(site.get("@host", "")))
        site_el.set("port", str(site.get("@port", "")))
        site_el.set("ssl", str(site.get("@ssl", "false")))
        alerts_el = ET.SubElement(site_el, "alerts")
        for alert in site.get("alerts", []):
            item = ET.SubElement(alerts_el, "alertitem")
            ET.SubElement(item, "pluginid").text = str(alert.get("pluginid", ""))
            ET.SubElement(item, "alert").text = alert.get("alert", "") or ""
            ET.SubElement(item, "name").text = alert.get("name", "") or ""
            ET.SubElement(item, "riskcode").text = str(alert.get("riskcode", "0"))
            ET.SubElement(item, "confidence").text = str(alert.get("confidence", "2"))
            ET.SubElement(item, "riskdesc").text = alert.get("riskdesc", "") or ""
            ET.SubElement(item, "desc").text = alert.get("desc", "") or ""
            ET.SubElement(item, "solution").text = alert.get("solution", "") or ""
            ET.SubElement(item, "reference").text = alert.get("reference", "") or ""
            cwe = alert.get("cweid", "0")
            ET.SubElement(item, "cweid").text = str(cwe) if cwe is not None else "0"
            instances_el = ET.SubElement(item, "instances")
            for inst in alert.get("instances", []):
                inst_el = ET.SubElement(instances_el, "instance")
                ET.SubElement(inst_el, "uri").text = inst.get("uri", "") or ""
                ET.SubElement(inst_el, "method").text = inst.get("method", "") or ""
                ET.SubElement(inst_el, "param").text = inst.get("param", "") or ""
                ET.SubElement(inst_el, "attack").text = inst.get("attack", "") or ""
                ET.SubElement(inst_el, "evidence").text = inst.get("evidence", "") or ""

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(out_path, encoding="utf-8", xml_declaration=True)


if __name__ == "__main__":
    main()
