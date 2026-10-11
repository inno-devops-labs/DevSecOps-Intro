# 5-Minute DevSecOps Program Walkthrough — Juice Shop

## (0:00–0:30) Context

I built a DevSecOps program around **OWASP Juice Shop**, a deliberately vulnerable app we use as a realistic target, the same way a team would treat an internal product.

Across Labs 4–9 we scanned **code, dependencies, containers, IaC, and runtime**: Syft SBOM, then Grype/Trivy SCA, Semgrep SAST, ZAP DAST, Checkov/KICS on Terraform/Ansible/Pulumi, Cosign image signing with a Conftest policy gate, and Falco runtime alerts. Everything rolls up into **DefectDojo** with a **DevSecOps SLA matrix**.

## (0:30–2:00) Layers

Picture the pipeline as layers, left to right, shift-left to runtime:

- **Pre-commit:** Gitleaks blocks secrets before they land; commits are **SSH-signed** so we know who shipped what.
- **Build:** **Syft** builds the SBOM, **Grype** and **Trivy** scan it for known CVEs, **Semgrep** catches unsafe code patterns in the repo.
- **Pre-deploy:** **Checkov** and **KICS** lint our IaC; **Cosign** signs the container image and **Conftest** is the gate: no unsigned or non-compliant image goes out.
- **Runtime:** **Falco** watches the cluster with eBPF rules and fires on suspicious process/network behavior.
- **Program layer:** **DefectDojo** imports all nine scan types, deduplicates overlaps, applies the **DevSecOps SLA** (1 / 7 / 30 / 90 days), and gives us **MTTR, vuln-age, and backlog** numbers leadership can track.

That's the full loop: prevent, detect, gate, observe, govern.

## (2:00–3:00) Findings + Closures

After one clean import we have **401 findings** in DefectDojo; **400 are still active**. We haven't closed anything yet, so **zero Critical findings closed this term**. That's honest for a first baseline run.

Here's one I risk-accepted — **CVE-2026-42766** — expiring **2027-01-04**, why: demo environment for the course capstone only, not production. Documented expiry so it doesn't become silent debt.

For cross-tool signal: the best overlap story in our data is **SCA dedup**. Trivy K8s manifest import added **0 new rows** because Grype and Trivy image had already reported the same CVEs. On the app side, Semgrep and ZAP both flag **client-side XSS-style issues** in Juice Shop; Semgrep sees the unsafe pattern in source, ZAP proves it in the browser. Fix: input validation and output encoding in the affected route.

## (3:00–4:00) Metrics

From DefectDojo engagement **Final Submission Run**:

- **MTTR:** N/A, nothing remediated and closed yet. DORA Elite is **under 1 day**; we're at baseline, not elite, and that's the gap we'd close next quarter.
- **Vuln-age median:** **0 days**, everything was imported this week.
- **SLA compliance:** **100%**, all open items still inside the DevSecOps windows (Critical 1d, High 7d, Medium 30d, Low 90d on Product OWASP Juice Shop).
- **Backlog trend:** **Rising**, we went from 0 to **400 active** findings once the full toolchain lit up. Expected on first comprehensive scan; next step is prioritize High/Critical with available fixes.

Active breakdown: **17 Critical, 165 High, 176 Medium, 29 Low, 13 Info**.

## (4:00–4:30) Next Steps

If I had another quarter, I'd ship **automated DefectDojo import on every release** into one engagement per tag, and burn down **High findings with `fix_available`** from Grype/Trivy first.

That's the next step on the **OWASP SAMM Defect Management** ladder: from *measure everything* to *remediate with SLA discipline*, target **High MTTR under 7 days**.

## (4:30–5:00) Q&A Anticipation

**1. "How would you handle a Log4Shell scenario?"**

I'd start with the **SBOM we already generate with Syft**, query it for `log4j` coordinates and versions across every image and dependency tree. Anything in the affected range gets **blocked in CI** (Grype/Trivy fail the build), then we **rebuild and re-sign** clean images with Cosign, redeploy through the Conftest gate, and **re-import** into DefectDojo to prove the CVE dropped off. Runtime Falco rules catch exploitation attempts while patches roll out. SBOM is the inventory; scanners are the triage; DefectDojo is the audit trail.

**2. "Why didn't you use IAST/paid tools?"**

This course is **open-source end to end**: Semgrep, ZAP, Trivy, Grype, Checkov, Falco, DefectDojo, so any student can reproduce the pipeline locally. IAST and commercial suites add great runtime coverage but need agents, licenses, and ops overhead we don't have in a lab VM. Tradeoff: we get **breadth and repeatability** over **deep interactive tracing**; for production I'd add IAST on the highest-risk services once the baseline gates are stable.
