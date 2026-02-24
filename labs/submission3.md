# Lab 3 - Secure Git

## Task 1 - SSH Commit Signature Verification

### 1.1 Commit Signing Benefits (Summary)

Signed commits provide cryptographic proof of author identity and commit integrity.

- They help prevent commit spoofing (someone pushing commits that appear to come from another developer).
- They prove the commit content was not altered after signing.
- They improve auditability in CI/CD and incident investigations.
- They strengthen trust in pull requests and release history.

### 1.2 Local SSH Signing Configuration Evidence

This machine already had SSH commit signing configured globally.

#### Git config checks

```bash
git config --global --get user.signingkey
git config --global --get commit.gpgSign
git config --global --get gpg.format
```

Observed output:

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImmO2f5GJYMw/laMGVefJO9oyE1/GcamrEajqasditx egorserg2604@gmail.com
true
ssh
```

#### SSH key presence (public key evidence only)

```powershell
Get-ChildItem $HOME\.ssh -File | Select-Object Name,Length,LastWriteTime
ssh-keygen -lf $HOME\.ssh\id_ed25519.pub
```

Observed output (trimmed):

```text
Name            Length LastWriteTime
----            ------ -------------
id_ed25519         419 16.09.2025 16:23:34
id_ed25519.pub     105 16.09.2025 16:23:34
...

256 SHA256:9hYNAqBwH4TBGDDiCCJOuJwGgUgSdg9cydnRgP+fNgc egorserg2604@gmail.com (ED25519)
```

### 1.3 Why Commit Signing Is Critical in DevSecOps Workflows

- CI/CD pipelines rely on trusted source history; unsigned or spoofed commits can inject malicious code into automated delivery paths.
- Signed commits support non-repudiation during audits and post-incident forensics.
- Branch protection and code review are stronger when identity verification is enforced in addition to access control.
- In team environments, commit verification reduces supply-chain risk from compromised accounts or misattributed changes.

### GitHub Verified Badge Evidence

- Local SSH signing configuration is present and enabled.
- To capture the required GitHub evidence, create and push a signed commit, then take a screenshot of the `Verified` badge in the GitHub commit/PR UI.

Suggested command:

```bash
git commit -S -m "docs: add commit signing summary"
```

## Task 2 - Pre-commit Secret Scanning

### 2.1 Hook Setup

Created local hook:

- `.git/hooks/pre-commit`

Implementation details:

- Scans staged files only (`git diff --cached --name-only --diff-filter=ACM`)
- Splits `lectures/*` vs non-lectures files
- Runs TruffleHog (Docker) on non-lectures files
- Runs Gitleaks (Docker) on each staged file
- Blocks commit if secrets are detected in non-lectures files
- Allows lecture-only findings as educational content
- Added Windows Git Bash compatibility (`MSYS_NO_PATHCONV`) so Docker `-w /repo` and volume mounts work correctly on this host

### 2.2 Secret Detection Tests

Test environment notes:

- Docker Desktop was started and the Docker engine became available before final tests.
- Hook was executed via Git Bash on Windows to match Git hook runtime behavior.

#### Test A - Blocked commit (fake private key in staged file)

Test file:

- `labs/lab3-hook-test.txt` containing a fake `BEGIN PRIVATE KEY` block

Result:

- Hook returned exit code `1` (commit blocked)
- Gitleaks detected `RuleID: private-key`

Observed output (trimmed):

```text
[pre-commit] scanning staged files for secrets...
[pre-commit] Files to scan: labs/lab3-hook-test.txt
[pre-commit] TruffleHog scan on non-lectures files...
[pre-commit] OK TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files...
Gitleaks found secrets in labs/lab3-hook-test.txt:
RuleID:      private-key
File:        labs/lab3-hook-test.txt
Line:        1
...
FAIL Secrets found in non-excluded file: labs/lab3-hook-test.txt
...
FAIL COMMIT BLOCKED: Secrets detected in non-excluded files.
```

#### Test B - Successful scan after secret removal

Test file content after redaction:

```text
safe_content=true
```

Result:

- Hook returned exit code `0` (commit allowed)
- TruffleHog: no secrets
- Gitleaks: no secrets

Observed output (trimmed):

```text
[pre-commit] scanning staged files for secrets...
[pre-commit] Files to scan: labs/lab3-hook-test.txt
[pre-commit] TruffleHog scan on non-lectures files...
[pre-commit] OK TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files...
[pre-commit] No secrets found in labs/lab3-hook-test.txt
...
OK No secrets detected in non-excluded files; proceeding with commit.
```

### How Automated Secret Scanning Prevents Security Incidents

- It blocks accidental credential leaks before they enter Git history (which is costly to clean later).
- It reduces incident response overhead (secret rotation, audit, history rewrite, downstream revocation).
- It provides immediate feedback to developers during normal workflow (`git commit`), not only in CI.
- Using two scanners improves coverage because detection rules differ across tools.

## Submission Metadata

- Lab artifact file: `labs/submission3.md`
- Local hook path: `.git/hooks/pre-commit`

## Remaining Manual Steps for Final Submission

- Create branch `feature/lab3` (if not already created)
- Make a signed commit and push to GitHub
- Capture screenshot of the GitHub `Verified` badge
- Open PR and submit the PR URL in Moodle
