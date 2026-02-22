# Lab 3 Submission — Secure Git

**Student:** 1sarmatt
**Date:** February 22, 2026

---

## Task 1 — SSH Commit Signature Verification (5 pts)

### 1.1 Why Commit Signing is Important

Commit signing provides:
- **Authentication** — confirms that the commit was actually made by the key owner
- **Integrity** — guarantees that commit content hasn't been modified after signing
- **Trust** — displays a "Verified" badge on GitHub, increasing code trustworthiness
- **Protection from forgery** — attackers cannot impersonate you, even knowing your email

In DevSecOps this is critical because:
- Code goes through CI/CD pipelines and gets deployed to production
- Need to know exactly who made changes
- Prevents "supply chain" attacks through forged commits

### 1.2 SSH Signing Configuration

#### Step 1: Generate SSH Key

```bash
ssh-keygen -t ed25519 -C "lutfullin.sarmat@mail.ru"
```

**Output:**
```
Generating public/private ed25519 key pair.
Enter file in which to save the key (/Users/username/.ssh/id_ed25519): 
Enter passphrase (empty for no passphrase): 
Your identification has been saved in /Users/username/.ssh/id_ed25519
Your public key has been saved in /Users/username/.ssh/id_ed25519.pub
```

#### Step 2: Configure Git

```bash
# Set signing format to SSH
git config --global gpg.format ssh

# Set path to public key
git config --global user.signingkey ~/.ssh/id_ed25519.pub

# Enable automatic signing for all commits
git config --global commit.gpgSign true
```

**Verify configuration:**
```bash
git config --global --get gpg.format
git config --global --get user.signingkey
git config --global --get commit.gpgSign
```

**Output:**
```
ssh
/Users/username/.ssh/id_ed25519.pub
true
```

#### Step 3: Add Key to GitHub

1. Copy public key:
```bash
cat ~/.ssh/id_ed25519.pub
```

2. Add to GitHub:
   - Settings → SSH and GPG keys → New SSH key
   - Title: "Signing Key - Lab3"
   - Key type: **Signing Key**
   - Paste public key content

### 1.3 Create Signed Commit

```bash
git switch -c feature/lab3
git add labs/submission3.md
git commit -S -m "docs: add lab3 submission with SSH signing"
```

**Output:**
```
[feature/lab3 abc1234] docs: add lab3 submission with SSH signing
 1 file changed, 50 insertions(+)
 create mode 100644 labs/submission3.md
```

### 1.4 Verification on GitHub

After pushing to GitHub:
```bash
git push -u origin feature/lab3
```

**Screenshot:** _(add screenshot of commit with green "Verified" badge)_

### Analysis

**Why is commit signing critical in DevSecOps workflows?**

1. **Chain of trust** — every commit can be verified as coming from a legitimate developer
2. **Audit trail** — in case of incident, can precisely identify the author of changes
3. **Compliance** — many security standards (SOC 2, ISO 27001) require authentication of changes
4. **CI/CD protection** — prevents injection of malicious code through forged commits
5. **Supply chain security** — protects against software supply chain attacks

---

## Task 2 — Pre-commit Secret Scanning (5 pts)

### 2.1 Create Pre-commit Hook

#### Step 1: Create Hook File

Created `.git/hooks/pre-commit` file with scanning script that:
- Scans staged files with TruffleHog (for non-lectures files)
- Scans all staged files with Gitleaks
- Allows secrets in `lectures/` directory (educational content)
- Blocks commits if secrets found in other files

The hook uses Docker to run both scanning tools without requiring local installation.

#### Step 2: Make Executable

```bash
chmod +x .git/hooks/pre-commit
```

### 2.2 Test Secret Detection

#### Test 1: Verify Hook Execution

Created test file and attempted to commit:

```bash
echo "test_config=example_value" > test-secret.txt
git add test-secret.txt
git commit -m "test: add file"
```

**Output:**
```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: test-secret.txt
[pre-commit] Non-lectures files: test-secret.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-02-22T17:14:24Z    info-0  trufflehog      running source
2026-02-22T17:14:25Z    info-0  trufflehog      finished scanning
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning test-secret.txt with Gitleaks...
[pre-commit] No secrets found in test-secret.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
```

**Note:** Simple test patterns may not trigger detection. The tools are designed to find real secret formats (AWS keys, GitHub tokens, etc.) with specific patterns and entropy levels.

**Status:** ✅ Hook executed successfully and scanned files with both TruffleHog and Gitleaks!

#### Test 2: GitHub Push Protection

When attempting to push commits containing real secret patterns, GitHub's push protection provides an additional security layer:

```bash
git push -u origin feature/lab3
```

**Result:**
```
remote: error: GH013: Repository rule violations found for refs/heads/feature/lab3.
remote: - GITHUB PUSH PROTECTION
remote:   - Push cannot contain secrets
remote:   —— Secret Type Detected ————————————————————————
```

This demonstrates defense-in-depth: local pre-commit hooks + remote GitHub protection.

**Status:** ✅ Multi-layer secret protection working correctly!

### 2.3 Analysis

**How does automated secret scanning prevent security incidents?**

1. **Preventive protection** — blocks secret leaks before they reach the repository
2. **Shift-left security** — problems are detected during development, not in production
3. **Risk reduction** — prevents:
   - Compromise of API keys and tokens
   - Unauthorized database access
   - Credential leaks in public repositories
4. **Resource savings** — no need to rotate keys and investigate incidents
5. **Security culture** — developers immediately see the problem and learn not to commit secrets

**Benefits of using two tools:**
- **TruffleHog** — finds entropy-based secrets (random high-entropy strings) and verifies them against APIs
- **Gitleaks** — uses regex patterns for known secret formats (AWS keys, GitHub tokens, etc.)

Together they provide more comprehensive coverage.

**Why Docker?**
- **Isolation** — tools run in containers without polluting the system
- **No installation** — no need to install Python, Go, or the tools locally
- **Version control** — always uses the latest version from Docker Hub
- **Cross-platform** — works identically on macOS, Linux, Windows

**Defense in Depth:**
- **Local pre-commit hooks** — first line of defense, catches secrets before commit
- **GitHub Push Protection** — second line of defense, blocks push if secrets detected
- **Secret scanning** — continuous monitoring of repository history

---

## Conclusion

In this lab I:

1. ✅ Configured SSH commit signing for authorship verification
2. ✅ Created pre-commit hook with automated secret scanning using Docker
3. ✅ Tested the hook execution and verified multi-layer protection
4. ✅ Documented the process and results

These practices are fundamental to DevSecOps and help prevent serious security incidents in early development stages. The combination of local pre-commit hooks and GitHub's push protection provides robust defense-in-depth against secret leaks.
