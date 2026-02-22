# Lab 3 — Secure Git Submission

Branch: `feature/lab3`

---

## Task 1 — SSH Commit Signing

### Why commit signing matters
Commit signing ensures:
- Authenticity — confirms the commit author identity
- Integrity — ensures commits were not modified after signing
- Trust — strengthens security in DevSecOps and CI/CD pipelines

### SSH signing setup

Configured Git with SSH signing:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgSign true
```

Verification:

```bash
git config --global --get gpg.format
git config --global --get user.signingkey
git config --global --get commit.gpgSign
```

After pushing commits to GitHub, the commit shows a **Verified** badge.

### Why this matters in DevSecOps

Signed commits help:

- Prevent impersonation
- Protect repository integrity
- Strengthen CI/CD trust chain
- Improve audit and traceability

---

## Task 2 — Pre‑commit Secret Scanning

### Implementation

Created pre‑commit hook:

```
.git/hooks/pre-commit
```

Tools used:

- TruffleHog (Docker)
- Gitleaks (Docker)

The hook scans staged files and blocks commits containing secrets.

### Setup

```bash
chmod +x .git/hooks/pre-commit
```

### Testing

Tested secret detection:

Blocked commit test:

```bash
echo 'AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF' > secret_test.txt
git add secret_test.txt
git commit -m "test secret"
```

Commit was correctly blocked.

Successful commit test:

```bash
git reset secret_test.txt
rm secret_test.txt
git commit -m "clean commit"
```

Commit passed successfully.

### Security impact

Pre‑commit secret scanning:

- Prevents credential leaks
- Protects infrastructure access
- Reduces incident risk
- Enforces secure development practices

---

Lab 3 completed successfully.
