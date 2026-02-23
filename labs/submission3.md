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



### 2.2: Testing Secret Detection

**Test 1: Pre-commit Hook Execution (No Staged Files)**
```
$ .git/hooks/pre-commit
[pre-commit] scanning staged files for secrets…
[pre-commit] no staged files; skipping scans
```
✓ Hook executes successfully when no files are staged

**Test 2: Secret Detection Process**

The hook is configured to:
- Detect AWS keys, API tokens, database credentials
- Allow educational examples in `lectures/` directory
- Block commits containing production secrets
- Provide detailed findings with context

**Expected Behavior:**

When a secret is staged:
```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: <file_list>
[pre-commit] TruffleHog scan on non-lectures files…
[pre-commit] Scanning <file> with Gitleaks...
Gitleaks found secrets in <file>:
  Finding: <secret_type>
  ...
✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
```

When secret is removed and file is restaged:
```
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] No secrets found in <file>
✓ No secrets detected in non-excluded files; proceeding with commit.
```

### 2.3: Secret Scanning Tools Configuration

**TruffleHog Configuration:**
- **Mode:** Filesystem scanning
- **Scope:** Non-lectures files only
- **Detection Method:** Pattern matching + entropy analysis
- **Exit Code:** Non-zero if secrets detected
- **Container:** `docker run --rm -v "$(pwd):/repo" trufflesecurity/trufflehog:latest`

**Gitleaks Configuration:**
- **Mode:** Individual file scanning
- **Detection Method:** Regex patterns from YAML rules
- **Scope:** All staged files (lectures excluded by logic)
- **Verbosity:** Detailed findings with locations
- **Container:** `docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:latest`

**Exclusion Rules:**
- Files in `lectures/*` directory: Allowed to contain examples
- All other files: Secrets are blocked

### 2.4: Analysis — How Automated Secret Scanning Prevents Security Incidents

**Shift-Left Security:**
Pre-commit hooks catch secrets before they enter the repository, eliminating the need for costly remediation after pushes. Secrets never make it to GitHub, reducing exposure window to zero.

**Prevents Accidental Exposure:**
Developers sometimes accidentally commit credentials (e.g., copying from documentation, temporary testing). Automated scanning catches these mistakes immediately before they're discoverable.

**Reduces Supply Chain Attacks:**
If repository credentials or secrets are exposed, attackers can:
- Impersonate CI/CD systems
- Access production infrastructure
- Steal customer data
- Modify code in transit

Pre-commit scanning prevents the first step of these attacks.

**Compliance Automation:**
Rather than relying on code reviews to spot secrets (error-prone), automated scanning provides deterministic security enforcement. No reviewer can approve a commit containing secrets—the hook rejects it automatically.

**Developer Education:**
When developers' commits are blocked, they learn what constitutes a secret and develop better habits for:
- Using environment variables and secrets managers
- Not committing configuration files with credentials
- Keeping credentials out of source control entirely

**Integration with CI/CD:**
While pre-commit is the first line of defense, similar scanning in CI/CD provides defense-in-depth:
- Catches commits pushed without running local hooks
- Scans entire repository for historical secrets
- Prevents code with secrets from deploying

**Real-World Impact:**
Many security breaches (e.g., GitHub token leaks, AWS key exposure) resulted from credentials committed to repositories. Automated pre-commit scanning is a proven control that prevents this category of incident entirely.

---


**Security Improvements Implemented:**
1. All commits now cryptographically signed with SSH keys
2. Secrets cannot be accidentally committed to non-lectures files
3. Audit trail established for code integrity verification
4. Automated controls replace manual code review for secret detection
5. Developer feedback loop for security-aware practices

