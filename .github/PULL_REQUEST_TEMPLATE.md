## Goal
Perform baseline threat modeling on OWASP Juice Shop, then implement a secure variant with risk reduction analysis, including an authentication-focused threat model.

## Changes
- Added `submissions/lab2.md` with baseline risk table, top‑5 risks, STRIDE mapping, and trust boundary observation
- Added secure variant risk comparison table and explanation of eliminated vs. remaining risks
- Added bonus section: authentication flow threat model with 3 auth‑specific risks (OWASP Top 10:2025)

## Testing
- Ran Threagile baseline: `threagile -model threagile-model.yaml -output output/`
- Applied hardening changes (HTTPS, encryption, prepared statements) and re‑ran Threagile on `threagile-model-secure.yaml`
- Compared `baseline-counts.json` vs `secure-counts.json` to verify risk reduction

## Artifacts & Screenshots
- Baseline report excerpt in `submissions/lab2.md` (risk counts, top‑5, STRIDE)
- Secure variant diff table and explanation
- Auth‑flow model description and 3 identified risks

## Checklist
- [x] Task 1 — Baseline risk table + top‑5 with STRIDE mapping
- [x] Task 2 — Secure variant + risk diff table (incl. Δ by severity)
- [ ] Bonus — Auth‑flow model + 3 auth‑specific risks mapped to OWASP Top 10:2025