# Lab 3 — Secure Git

## Task 1 — SSH Commit Signature Verification

### Benefits of Commit Signing
- **Authentication** — confirms commit came from you
- **Integrity** — ensures content wasn't tampered with
- **Non-repudiation** — you can't deny making the commit
- **Trust** — creates verifiable chain of trust

### SSH Signing Configuration

Git was configured for SSH commit signing using the following commands:

```bash
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgSign true
git config --global gpg.format ssh
````

SSH key fingerprint:

```text
256 SHA256:QhGDXL27JKxL56Tb/6vf77VWm86R+N7DTYXeIkjMBpk
```

### DevSecOps Analysis

Commit signing is critical in DevSecOps workflows because it guarantees commit authenticity and protects the software supply chain from unauthorized or forged commits. Verified commits increase trust in collaborative environments and provide traceability for security audits and incident investigations.

### Verification Evidence

A signed commit was pushed to GitHub and verified using the GitHub “Verified” badge.

---

## Task 2 — Pre-commit Secret Scanning

### Pre-commit Hook Setup

A local Git pre-commit hook was configured in:

```text
.git/hooks/pre-commit
```

The hook uses Dockerized versions of:

* TruffleHog
* Gitleaks

The hook scans staged files before every commit and blocks commits if secrets are detected in non-excluded files.

Hook activation:

```bash
chmod +x .git/hooks/pre-commit
```

### Secret Detection Test

A test secret was added to a staged file to verify hook functionality.

Example test secret:

```text
AWS_SECRET_ACCESS_KEY=FAKESECRET123456789
```

When attempting to commit, the hook blocked the operation after detecting a potential secret.

Example output:

```text
[pre-commit] TruffleHog scan on non-lectures files…
[pre-commit] ✖ TruffleHog detected potential secrets in non-lectures files

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
```

After removing the secret, the commit completed successfully.

Example successful output:

```text
✓ No secrets detected in non-excluded files; proceeding with commit.
```

### Security Analysis

Automated secret scanning helps prevent accidental credential exposure in Git repositories. Integrating secret detection into pre-commit workflows shifts security checks earlier into development and reduces the risk of leaked API keys, passwords, and tokens reaching remote repositories.
