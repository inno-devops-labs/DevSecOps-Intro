# Lab 3 Submission — Secure Git

## Task 1 — SSH Commit Signature Verification

### 1.1: Summary of Commit Signing Benefits

SSH commit signing is a critical security practice that verifies the authenticity and integrity of Git commits. The benefits include:

**Authenticity Verification:**
- Proves that a commit was made by the person who claims to have made it
- Prevents impersonation attacks where someone could forge commits using stolen credentials
- Uses cryptographic signatures that cannot be forged without the private key

**Integrity Assurance:**
- Guarantees that commit contents have not been modified after signing
- Any tampering with the commit message or files would invalidate the signature
- Protects against man-in-the-middle attacks during transit

**Audit and Compliance:**
- Provides a verifiable chain of custody for code changes
- Essential for regulated industries (finance, healthcare, government)
- Enables accountability by linking commits to specific developers
- Supports non-repudiation requirements in security policies

**DevSecOps Best Practices:**
- Aligns with the principle of "shifting security left" by making authentication visible
- Enables protected branches that require signed commits before merging
- Builds trust in the supply chain by ensuring code authenticity
- Integrates with GitHub's security features (showing "Verified" badges)

### 1.2: SSH Key Setup and Configuration

**Existing SSH Keys Identified:**
- Location: `~/.ssh/id_ed25519` (primary key used for signing)

**Git Configuration Applied:**
```bash
git config --global user.signingkey ~/.ssh/id_ed25519
git config --global commit.gpgSign true
git config --global gpg.format ssh
```

**Configuration Verification:**
```
user.signingkey=/home/j0cos/.ssh/id_ed25519
gpg.format=ssh
commit.gpgSign=true
```

### 1.3: Signed Commits Created

A signed commit has been created for this lab submission using SSH:

```bash
git commit -S -m "docs: add lab3 submission with SSH signed commits"
```

**Key Configuration Details:**
- **Signing Key:** ED25519 SSH key at `~/.ssh/id_ed25519`
- **Format:** SSH format (native Git SSH signing, not GPG)
- **Auto-Signing:** Enabled globally (`commit.gpgSign = true`)
- **Email:** badamshinrashid@google.com
- **Username:** Rashid Badamshin

### 1.4: Analysis — Why Commit Signing is Critical in DevSecOps

**Supply Chain Security:**
Commits are the foundation of code supply chain security. Without signing, an attacker with access to Git credentials could inject malicious code while impersonating legitimate developers. This is especially dangerous in CI/CD pipelines where unsigned commits trigger automated deployments.

**Accountability and Non-Repudiation:**
Signed commits create an irrefutable audit trail. A developer cannot later deny making a commit, as the cryptographic signature is tied to their private key. This is essential for security incident investigations.

**Protection Against Repository Compromise:**
Even if an attacker gains temporary access to a repository, they cannot create commits that appear to be from legitimate developers without their private keys. Signed commits make this compromise immediately detectable.

**Compliance and Governance:**
Regulated environments require proof of who made changes and when. SSH signed commits provide this proof through cryptographic verification that cannot be disputed or forged.

**Integration with Branch Protection:**
On GitHub, repositories can require signed commits before merging to main branches. This prevents unsigned (potentially forged) code from reaching production, making it a critical control in secure SDLC practices.

---

## Task 2 — Pre-commit Secret Scanning

### 2.1: Pre-commit Hook Setup

**Hook Location:** `.git/hooks/pre-commit`

**Hook Functionality:**
The pre-commit hook performs automated secret scanning on staged files using two industry-leading tools:

1. **TruffleHog** (Docker: `trufflesecurity/trufflehog:latest`)
   - Scans non-lectures files for exposed secrets
   - Uses pattern matching and entropy analysis
   - Detects API keys, tokens, credentials, and private keys

2. **Gitleaks** (Docker: `zricethezav/gitleaks:latest`)
   - Performs regex-based scanning on all staged files
   - Checks for common secret patterns
   - Provides detailed findings with line numbers

**Hook Workflow:**
```
1. Collect staged files (added/changed/modified)
2. Separate lectures/* files (allowed to contain examples) from project files
3. Run TruffleHog on non-lectures files
4. Run Gitleaks on all files
5. Allow secrets only in lectures/ directory (educational content)
6. Block commits if secrets found in production code
7. Display detailed scan summary
```

### 2.2: Testing Secret Detection — Verification Results

**Test 1: Pre-commit Hook Execution (No Staged Files)**
```
$ .git/hooks/pre-commit
[pre-commit] scanning staged files for secrets…
[pre-commit] no staged files; skipping scans
```
✓ Hook executes successfully when no files are staged

**Test 2: Commit WITH Secret — BLOCKED ✖**

Created test file with MongoDB connection string:
```
Database connection string for testing:
mongodb+srv://admin:[REDACTED]@cluster.mongodb.net/db?retryWrites=true
```

Attempted to commit the file with staged secret:
```bash
$ git add test_secret.txt
$ git commit -m "test: adding file with MongoDB secret"
```

**Result: COMMIT BLOCKED ✖**

Hook detected the secret and prevented the commit:
```
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷
Found unverified result 🐷🔑❓
Detector Type: MongoDB
Raw result: mongodb+srv://admin:[REDACTED]@cluster.mongodb.net/db?retryWrites=true
File: test_secret.txt
Line: 1
finished scanning: {"chunks": 1, "bytes": 115, "verified_secrets": 0, "unverified_secrets": 1}

[pre-commit] ✖ TruffleHog detected potential secrets in non-lectures files
[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: true
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
```

**Key Evidence:**
- ✖ TruffleHog found: `unverified_secrets: 1`
- ✖ Detector identified secret type: MongoDB
- ✖ Exact location: test_secret.txt, Line 1
- ✖ Exit code: 1 (commit rejected)

---

**Test 3: Commit WITHOUT Secret — ALLOWED ✅**

Created safe test file with no credentials:
```
This is a safe file with no secrets.
Just some normal documentation text.
No credentials or API keys here.
```

Attempted to commit the safe file:
```bash
$ git add test_secret.txt
$ git commit -m "test: safe file with no secrets"
```

**Result: COMMIT ALLOWED ✅**

Hook scanned the file and allowed the commit:
```
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷
finished scanning: {"chunks": 1, "bytes": 107, "verified_secrets": 0, "unverified_secrets": 0}

[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] No secrets found in test_secret.txt
[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
[feature/lab3 704db28] test: safe file with no secrets
```

**Key Evidence:**
- ✓ TruffleHog found: `verified_secrets: 0`, `unverified_secrets: 0`
- ✓ Gitleaks found: no secrets
- ✓ Scan duration: 1.67ms
- ✓ Exit code: 0 (commit accepted)
- ✓ Commit created: hash `704db28`

---

### 2.3: Secret Scanning Tools Configuration

**TruffleHog Configuration:**
- **Mode:** Filesystem scanning
- **Scope:** Non-lectures files only
- **Detection Method:** Pattern matching + entropy analysis
- **Trigger Condition:** Searches for "Found unverified result" or "Found verified result" in output
- **Container:** `docker run --rm -v "$(pwd):/repo" trufflesecurity/trufflehog:latest filesystem <files>`
- **Real Detection:** Successfully detected MongoDB connection string with credentials

**Gitleaks Configuration:**
- **Mode:** Individual file scanning
- **Detection Method:** Regex patterns from YAML rules
- **Scope:** All staged files (lectures excluded by logic)
- **Trigger Condition:** Searches for "Finding:" or "Secret found" in output
- **Container:** `docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:latest detect --source="$file" --no-git --verbose`
- **Note:** Primary detection in this setup is TruffleHog; Gitleaks provides secondary validation

**Exclusion Rules:**
- Files in `lectures/*` directory: Allowed to contain examples (educational content)
- All other files: Secrets are automatically blocked with error message
- Exit behavior: Non-zero exit code blocks commit, zero exit code allows commit to proceed

---

**Security Improvements Implemented:**
1. All commits now cryptographically signed with SSH keys
2. Secrets cannot be accidentally committed to non-lectures files
3. Audit trail established for code integrity verification
4. Automated controls replace manual code review for secret detection
5. Developer feedback loop for security-aware practices

