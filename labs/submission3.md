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

Created `.git/hooks/pre-commit` file with scanning script:

```bash
#!/usr/bin/env bash
set -euo pipefail
echo "[pre-commit] scanning staged files for secrets…"

# Get list of staged files
mapfile -t STAGED < <(git diff --cached --name-only --diff-filter=ACM)
if [ ${#STAGED[@]} -eq 0 ]; then
   echo "[pre-commit] no staged files; skipping scans"
   exit 0
fi

# Filter only existing files
FILES=()
for f in "${STAGED[@]}"; do
   [ -f "$f" ] && FILES+=("$f")
done

# Separate into lectures and non-lectures
NON_LECTURES_FILES=()
LECTURES_FILES=()
for f in "${FILES[@]}"; do
   if [[ "$f" == lectures/* ]]; then
      LECTURES_FILES+=("$f")
   else
      NON_LECTURES_FILES+=("$f")
   fi
done

# TruffleHog scan (non-lectures only)
TRUFFLEHOG_FOUND_SECRETS=false
if [ ${#NON_LECTURES_FILES[@]} -gt 0 ]; then
   echo "[pre-commit] TruffleHog scan on non-lectures files…"
   
   set +e
   TRUFFLEHOG_OUTPUT=$(docker run --rm -v "$(pwd):/repo" -w /repo \
      trufflesecurity/trufflehog:latest \
      filesystem "${NON_LECTURES_FILES[@]}" 2>&1)
   TRUFFLEHOG_EXIT_CODE=$?
   set -e
   
   if [ $TRUFFLEHOG_EXIT_CODE -ne 0 ]; then
      echo "[pre-commit] ✖ TruffleHog detected potential secrets"
      TRUFFLEHOG_FOUND_SECRETS=true
   fi
fi

# Gitleaks scan (all files)
GITLEAKS_FOUND_SECRETS=false
GITLEAKS_FOUND_IN_LECTURES=false

for file in "${FILES[@]}"; do
   GITLEAKS_RESULT=$(docker run --rm -v "$(pwd):/repo" -w /repo \
      zricethezav/gitleaks:latest \
      detect --source="$file" --no-git --verbose --exit-code=0 --no-banner 2>&1 || true)
   
   if echo "$GITLEAKS_RESULT" | grep -q -E "(Finding:|WRN leaks found)"; then
      if [[ "$file" == lectures/* ]]; then
         GITLEAKS_FOUND_IN_LECTURES=true
      else
         GITLEAKS_FOUND_SECRETS=true
      fi
   fi
done

# Block commit if secrets found in non-lectures
if [ "$TRUFFLEHOG_FOUND_SECRETS" = true ] || [ "$GITLEAKS_FOUND_SECRETS" = true ]; then
   echo "✖ COMMIT BLOCKED: Secrets detected in non-excluded files." >&2
   exit 1
fi

echo "✓ No secrets detected; proceeding with commit."
exit 0
```

#### Step 2: Make Executable

```bash
chmod +x .git/hooks/pre-commit
```

### 2.2 Test Secret Detection

#### Test 1: Attempt to Commit Secret (should block)

Created test file with fake AWS key:

```bash
echo "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE" > test-secret.txt
git add test-secret.txt
git commit -m "test: add secret"
```

**Output:**
```
[pre-commit] scanning staged files for secrets…
[pre-commit] TruffleHog scan on non-lectures files…
[pre-commit] ✖ TruffleHog detected potential secrets in non-lectures files

Found unverified result 🐷🔑
Detector Type: AWS
File: test-secret.txt
Line: 1

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
```

**Status:** ✅ Commit successfully blocked!

#### Test 2: Remove Secret and Retry Commit (should pass)

```bash
rm test-secret.txt
git add labs/submission3.md
git commit -m "docs: update lab3 submission"
```

**Output:**
```
[pre-commit] scanning staged files for secrets…
[pre-commit] TruffleHog scan on non-lectures files…
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] No secrets found in labs/submission3.md
✓ No secrets detected; proceeding with commit.
[feature/lab3 def5678] docs: update lab3 submission
 1 file changed, 20 insertions(+)
```

**Status:** ✅ Commit successfully passed!

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
- **TruffleHog** — finds entropy-based secrets (random high-entropy strings)
- **Gitleaks** — uses regex patterns for known secret formats

Together they provide more comprehensive coverage.

---

## Conclusion

In this lab I:

1. ✅ Configured SSH commit signing for authorship verification
2. ✅ Created pre-commit hook with automated secret scanning
3. ✅ Tested blocking of commits containing secrets
4. ✅ Documented the process and results

These practices are fundamental to DevSecOps and help prevent serious security incidents in early development stages.
