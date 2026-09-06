#!/usr/bin/env python3
"""Consistency checks across a course repository.

Usage:  python3 tools/check-course.py [--quiet]

Checks, in order of how much breakage each one has actually caught:

  handoffs   a lab reads a file no earlier lab produces and that is not shipped
  plumbing   a shipped file under labs/labN/ that no lab spec mentions
  versions   a version string in a lab or the README that disagrees with
             tools/versions.yaml
  structure  missing sections, point totals that do not add up
  coverage   a task with no matching line in Acceptance criteria

Exit code 1 if anything is reported, so CI can act on it.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS = os.path.join(ROOT, "labs")
problems = []


def report(check, where, msg):
    problems.append((check, where, msg))


def lab_files():
    out = []
    for name in sorted(os.listdir(LABS)):
        m = re.fullmatch(r"lab(\d+)\.md", name)
        if m:
            out.append((int(m.group(1)), os.path.join(LABS, name)))
    return sorted(out)


def tracked_files():
    try:
        res = subprocess.run(["git", "ls-files", "labs"], cwd=ROOT,
                             capture_output=True, text=True, check=True)
    except Exception:
        return []
    return [p for p in res.stdout.split("\n") if p]


WRITE_RE = re.compile(
    r"(?:--output(?:-file-path)?[= ]+|--file[= ]+|-o[= ]+|tee\s+|>\s*|mv\s+\S+\s+|cp\s+\S+\s+)"
    r"(labs/lab\d+/[\w./-]+)")
PATH_RE = re.compile(r"labs/lab\d+/[\w./-]+\.\w+")
# A path the student is told to create: it appears in a YOUR TASK scaffold, or as
# the header comment of one. Those are not handoffs and have no producer.
STUDENT_RE = re.compile(r"#\s*(labs/lab\d+/[\w./-]+\.\w+)")
# Escape hatch for a file this script cannot see being produced, for example one
# a container writes into a mounted directory. Put it in the lab spec:
#   <!-- produces: labs/lab2/threagile-stub-model.yaml by threagile -create-stub-model -->
PRODUCES_RE = re.compile(r"<!--\s*produces:\s*(labs/lab\d+/[\w./-]+)")


def check_handoffs_and_plumbing(labs):
    """Cross-lab handoffs only.

    A path within one lab is that lab's own business: verify-lab.sh runs those
    commands. What breaks silently is a *later* lab, or a shipped script, reading
    a file an *earlier* lab was supposed to produce. Those must be declared:

        <!-- produces: labs/lab7/results/trivy-k8s.json for lab 10 -->

    Declaring it is the point. The alternative is a regex that tries to
    recognise every way a tool can be told to write a file, which is how a
    dropped handoff went unnoticed until the importer ran.
    """
    shipped = set(tracked_files())
    produced = {}
    for num, path in labs:
        text = open(path).read()
        for p in PRODUCES_RE.findall(text):
            produced[p.rstrip("/")] = num
        for p in WRITE_RE.findall(text):
            produced.setdefault(p.rstrip("/"), num)
        for d in re.findall(r"(?:--output-file-path|-o)[= ]+(labs/lab\d+/[\w./-]*/)", text):
            produced.setdefault(d.rstrip("/") + "/*", num)

    def has_producer(p, by_lab):
        if p in shipped:
            return True
        owner = produced.get(p)
        if owner is not None and owner <= by_lab:
            return True
        for d, lab in produced.items():
            if d.endswith("/*") and p.startswith(d[:-1]) and lab <= by_lab:
                return True
        return False

    referenced = set()
    for num, path in labs:
        text = open(path).read()
        name = os.path.basename(path)
        for p in sorted(set(PATH_RE.findall(text))):
            referenced.add(p)
            m = re.match(r"labs/lab(\d+)/", p)
            if not m or int(m.group(1)) == num:
                continue                      # same lab: its own business
            if not has_producer(p, num):
                report("handoffs", name,
                       f"reads {p} from lab{m.group(1)}, which nothing declares as produced")

    for rel in sorted(shipped):
        if rel.endswith(".md"):
            continue
        m = re.search(r"labs/lab(\d+)/", rel)
        if not m:
            continue
        owner = int(m.group(1))
        try:
            body = open(os.path.join(ROOT, rel)).read()
        except (OSError, UnicodeDecodeError):
            continue
        for p in sorted(set(PATH_RE.findall(body))):
            referenced.add(p)
            pm = re.match(r"labs/lab(\d+)/", p)
            if not pm or int(pm.group(1)) == owner:
                continue
            if not has_producer(p, owner):
                report("handoffs", rel,
                       f"reads {p}, which nothing declares as produced")

    all_text = "\n".join(open(path).read() for _, path in labs)
    for p in sorted(shipped):
        if p.endswith(".md") or p in referenced:
            continue
        if os.path.basename(p) in all_text:
            continue
        parent = os.path.dirname(p)
        covered = False
        while parent and parent != "labs":
            if parent in all_text or parent + "/" in all_text:
                covered = True
                break
            parent = os.path.dirname(parent)
        if not covered:
            report("plumbing", p, "shipped but no lab spec mentions it")


VERSION_HINTS = {
    "juice-shop": r"juice-shop:v(\d+\.\d+\.\d+)",
    "threagile": r"threagile:v?(\d+\.\d+\.\d+)",
    "cosign": r"[Cc]osign v?(\d+\.\d+)",
    "trivy": r"[Tt]rivy v?(\d+\.\d+)",
    "falco": r"falco:(\d+\.\d+\.\d+)",
    "defectdojo": r"--branch (\d+\.\d+\.\d+)",
    "kata": r"[Kk]ata (?:Containers )?v?(\d+\.\d+)",
    "k3d": r"k3s v?(\d+\.\d+)",
}


def check_versions(labs):
    try:
        import yaml
    except ImportError:
        report("versions", "tools/versions.yaml", "PyYAML missing; skipped")
        return
    manifest = yaml.safe_load(open(os.path.join(ROOT, "tools", "versions.yaml")))
    files = [(os.path.basename(p), p) for _, p in labs]
    files.append(("README.md", os.path.join(ROOT, "README.md")))
    for tool, spec in manifest.get("tools", {}).items():
        pat = VERSION_HINTS.get(tool)
        if not pat:
            continue
        pin = str(spec.get("k8s") or spec.get("pin", "")).lstrip("v")
        for name, path in files:
            for found in set(re.findall(pat, open(path).read())):
                if not pin.startswith(found) and not found.startswith(pin.split(".")[0] + "."):
                    report("versions", name,
                           f"{tool} appears as {found}, manifest pins {pin}")
                elif not pin.startswith(found):
                    report("versions", name,
                           f"{tool} appears as {found}, manifest pins {pin}")


REQUIRED_SECTIONS = ["## Setup", "## Task 1", "## Submit",
                     "## Acceptance criteria", "## Common pitfalls", "## Resources"]


def check_structure_and_coverage(labs):
    for num, path in labs:
        text = open(path).read()
        name = os.path.basename(path)
        for section in REQUIRED_SECTIONS:
            if section not in text:
                report("structure", name, f"missing section {section}")
        points = [int(x) for x in re.findall(r"^## (?:Task \d+|Bonus).*\((\d+) pts?\)",
                                             text, re.M)]
        if points:
            total = sum(points)
            expected = 12 if num <= 10 else 10
            if total != expected:
                report("structure", name,
                       f"task points add up to {total}, expected {expected}")
        tasks = re.findall(r"^## (Task \d+|Bonus)", text, re.M)
        acc = text.split("## Acceptance criteria", 1)
        if len(acc) == 2:
            acc_text = acc[1].split("\n## ", 1)[0].lower()
            for t in tasks:
                key = t.lower()
                if key not in acc_text:
                    report("coverage", name,
                           f"{t} has no line in Acceptance criteria")


def main():
    labs = lab_files()
    if not labs:
        sys.exit("no labs found under " + LABS)
    check_handoffs_and_plumbing(labs)
    check_versions(labs)
    check_structure_and_coverage(labs)

    if not problems:
        print("check-course: %d labs, nothing to report" % len(labs))
        return 0
    width = max(len(c) for c, _, _ in problems)
    for check, where, msg in problems:
        print("%-*s  %-14s %s" % (width, check, where, msg))
    print("\n%d problem(s)" % len(problems))
    return 1


if __name__ == "__main__":
    sys.exit(main())
