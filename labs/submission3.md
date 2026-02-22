# Lab 3 Submission — Secure Git

## Environment
- Date: 2026-02-22
- OS: macOS (Darwin 25.3.0)
- Branch: `feature/lab3`
- Docker CLI: `Docker version 29.2.0, build 0b9d198`

---

## Task 1 — SSH Commit Signature Verification

### 1.1 Why commit signing improves security

Signed commits provide cryptographic proof that:
1. the commit was authored by the expected identity (authenticity),
2. the commit content was not altered after signing (integrity),
3. the repository history is more trustworthy for audits and incident response.

In DevSecOps, this matters because CI/CD pipelines and production changes rely on Git history. Signed commits reduce the risk of supply-chain attacks through impersonation or tampered commits.

### 1.2 SSH key and Git signing configuration (evidence)

Used an existing SSH key:

```bash
$ ssh-keygen -lf ~/.ssh/id_ed25519.pub
256 SHA256:[redacted-for-scanner] e.torshin@innopolis.university (ED25519)
```

Configured Git for SSH signing (repository scope for this lab):

```bash
$ git config user.name 'Егор Торшин'
$ git config user.email 'e.torshin@innopolis.university'
$ git config gpg.format ssh
$ git config user.signingkey ~/.ssh/id_ed25519
$ git config commit.gpgsign true

$ git config --get user.name
Егор Торшин
$ git config --get user.email
e.torshin@innopolis.university
$ git config --get gpg.format
ssh
$ git config --get user.signingkey
/Users/a89088/.ssh/id_ed25519
$ git config --get commit.gpgsign
true
```

### 1.3 Signed commit evidence and verification

Created a signed commit for this submission:

```bash
$ git commit -S -m "docs(lab3): add secure git submission"
# commit SHA: d18c1eb39d5d8072a0247d50c847576bb991e308
```

Signature verification output:

```bash
$ git show --pretty=raw -s d18c1eb39d5d8072a0247d50c847576bb991e308
commit d18c1eb39d5d8072a0247d50c847576bb991e308
...
gpgsig -----BEGIN SSH SIGNATURE-----
 U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg96fv71WnPV4ruednJYvGMdSVWi...
 -----END SSH SIGNATURE-----

$ git show --show-signature --no-patch d18c1eb39d5d8072a0247d50c847576bb991e308
Good "git" signature for e.torshin@innopolis.university with ED25519 key SHA256:[redacted-for-scanner]
```

GitHub "Verified" badge evidence:
- Commit URL: `https://github.com/egorTorshin/DevSecOps-Intro/commit/d18c1eb39d5d8072a0247d50c847576bb991e308`
- Verification status from GitHub API:

```text
verified: False
reason: unknown_key
signature_present: True
```

Current status interpretation:
- The commit is cryptographically signed (signature is embedded in the commit object).
- GitHub still marks it as unverified because the signing key is not registered in GitHub account settings as an SSH signing key.
- To get the green "Verified" badge, add `~/.ssh/id_ed25519.pub` in GitHub: **Settings -> SSH and GPG keys -> New SSH key -> Key type: Signing Key**.

### 1.4 Analysis — Why commit signing is critical in DevSecOps workflows

- **Pipeline trust:** deployment automation can enforce "only verified commits" gates.
- **Non-repudiation:** authorship is tied to a cryptographic key, improving accountability.
- **Forensics readiness:** signed history helps incident responders distinguish legitimate commits from injected malicious changes.
- **Supply-chain hardening:** reduces risk of unauthorized actors pushing code under spoofed identities.

---

## Task 2 — Pre-commit Secret Scanning

### 2.1 Hook setup and configuration

Implemented local pre-commit hook at `.git/hooks/pre-commit` with:
- staged-file discovery (`git diff --cached --name-only --diff-filter=ACM`),
- TruffleHog scan for non-`lectures/` staged files,
- Gitleaks scan per staged file,
- conditional allow-list behavior for `lectures/` educational content,
- fail-fast commit blocking on detected secrets in non-lectures paths.

Hook was made executable:

```bash
$ chmod +x .git/hooks/pre-commit
$ ls -l .git/hooks/pre-commit
-rwxr-xr-x@ 1 a89088  staff  ... .git/hooks/pre-commit
```

### 2.2 Secret detection test results

#### Test A — blocked operation (secret present)

Added a staged test file with a private-key pattern in `labs/lab3-secret-test.env`.
Hook result excerpt:

```text
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: labs/lab3-secret-test.env
[pre-commit] TruffleHog scan on non-lectures files…
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
Gitleaks found secrets in labs/lab3-secret-test.env:
RuleID:      private-key
✖ Secrets found in non-excluded file: labs/lab3-secret-test.env
✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
```

Result: commit operation is blocked when a secret is present in non-excluded files.

#### Test B — successful operation (secret removed)

Removed secret content and staged a clean file `labs/lab3-safe-test.txt`.
Hook result excerpt:

```text
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: labs/lab3-safe-test.txt
[pre-commit] TruffleHog scan on non-lectures files…
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] No secrets found in labs/lab3-safe-test.txt
✓ No secrets detected in non-excluded files; proceeding with commit.
```

Result: commit can proceed after secrets are removed/redacted.

### 2.3 Analysis — How automated secret scanning prevents incidents

- **Prevents accidental leaks early:** secrets are stopped before entering repository history.
- **Reduces cleanup cost:** avoids emergency credential rotation and history rewriting.
- **Standardizes team behavior:** hook enforces security checks consistently across contributors.
- **Improves SDLC security posture:** codifies "shift-left" controls directly into developer workflow.

---

## Final Notes

- Docker daemon must be running for scanner containers to execute.
- The implemented hook and tests demonstrate both required outcomes: blocked and successful commit paths.
- This submission file documents both configuration and security rationale for secure Git practices.
