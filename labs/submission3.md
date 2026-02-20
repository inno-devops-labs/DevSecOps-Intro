# Lab 3 — Secure Git

## Task 1 — SSH Commit Signing

### Summary of Benefits
Signed commits prove who authored a change and protect integrity by preventing tampering. In DevSecOps, this provides accountability, improves audit trails, and helps supply chain security by ensuring code provenance.

### SSH Key and Git Config
- SSH public key fingerprint: `SHA256:GbFyMrPqJtxv/LXd9O2mwVtgKxfX1f6b3Dcu0uoTRq4`
- Git config:
  - `user.signingkey=/Users/avgreensoup/.ssh/id_ed25519.pub`
  - `gpg.format=ssh`
  - `commit.gpgsign=true`

### Signed Commit Evidence
- Local verification:
  - `git log -1 --show-signature` shows a **Good "git" signature** for the latest signed commit.
- Commit used:
  - `docs: add commit signing summary` (signed via SSH)
- GitHub Verified badge screenshot:
  - `labs/lab3/verified.png`

### Why Commit Signing Is Critical in DevSecOps
Commit signing helps ensure code changes are authentic and not injected by unauthorized parties. It strengthens software supply chain integrity, supports compliance requirements, and reduces the risk of impersonation or compromised developer identities.

---

## Task 2 — Pre-commit Secret Scanning

### Hook Setup
- Hook file: `.git/hooks/pre-commit`
- Tools: Dockerized TruffleHog and Gitleaks
- Behavior: blocks commits if secrets are detected in non-lectures files

### Test: Blocked Commit (Secret Detected)
Attempted commit with a private key block in `labs/lab3/secret-test.txt`.

```text
[pre-commit] scanning staged files for secrets...
[pre-commit] Files to scan: labs/lab3/secret-test.txt
[pre-commit] Non-lectures files: labs/lab3/secret-test.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files...
[pre-commit] ok TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files...
[pre-commit] Scanning labs/lab3/secret-test.txt with Gitleaks...
Gitleaks found secrets in labs/lab3/secret-test.txt:
Finding:     -----BEGIN RSA PRIVATE KEY-----
...
RuleID:      private-key
...
ERROR: COMMIT BLOCKED: Secrets detected in non-excluded files.
```

### Test: Successful Commit (Secret Removed)
Replaced secret with safe placeholder and retried.

```text
[pre-commit] scanning staged files for secrets...
[pre-commit] Files to scan: labs/lab3/secret-test.txt
[pre-commit] Non-lectures files: labs/lab3/secret-test.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files...
[pre-commit] ok TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files...
[pre-commit] Scanning labs/lab3/secret-test.txt with Gitleaks...
[pre-commit] No secrets found in labs/lab3/secret-test.txt
...
OK: No secrets detected in non-excluded files; proceeding with commit.
```

### Analysis
Automated secret scanning prevents accidental leakage before commits reach the repo. This is a practical guardrail that reduces incident risk, especially in fast-moving teams.

---

## Artifacts
- `labs/lab3/signing-summary.txt`
- `labs/lab3/secret-test.txt`
- `.git/hooks/pre-commit` (local hook)
