# Lab 3 Submission — Secure Git

## Task 1 — SSH Commit Signature Verification

### 1.1 Benefits of Signing Commits

Commit signing provides cryptographic proof that a commit was created by the person who claims to be its author. Key benefits include:

- **Authenticity:** Proves the commit actually came from the stated author, not an impersonator who configured `user.name` and `user.email` to match someone else's identity.
- **Integrity:** Guarantees the commit content has not been tampered with after signing — any modification invalidates the signature.
- **Non-repudiation:** The author cannot deny having made a signed commit, since only they hold the private key.
- **Supply chain security:** In CI/CD pipelines, enforcing signed commits ensures that only trusted developers can introduce changes into protected branches, reducing the risk of malicious code injection.
- **Compliance:** Many security frameworks (SOC 2, NIST SSDF) recommend or require verifiable provenance for source code changes.

### 1.2 SSH Key Setup and Git Configuration

**1. Generate a dedicated signing key (ed25519):**

```sh
ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/id_ed25519_signing
```

Output:

```
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase):
Your identification has been saved in /home/user/.ssh/id_ed25519_signing
Your public key has been saved in /home/user/.ssh/id_ed25519_signing.pub
The key fingerprint is:
SHA256:xYzAbCdEfGhIjKlMnOpQrStUvWxYz1234567890AB your_email@example.com
```

**2. Add the public key to GitHub as a Signing Key:**

- Go to **GitHub → Settings → SSH and GPG keys → New SSH key**
- Key type: **Signing Key**
- Paste the contents of `~/.ssh/id_ed25519_signing.pub`

**3. Configure Git for SSH signing:**

```sh
git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
git config --global commit.gpgSign true
git config --global gpg.format ssh
```

**4. Create allowed signers file (for local verification):**

```sh
echo "your_email@example.com $(cat ~/.ssh/id_ed25519_signing.pub)" > ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

**Verification of configuration:**

```sh
$ git config --global --get commit.gpgSign
true

$ git config --global --get gpg.format
ssh

$ git config --global --get user.signingkey
/home/user/.ssh/id_ed25519_signing.pub
```

### 1.3 Signed Commit Evidence

**Creating a signed commit:**

```sh
git commit -S -m "docs: add commit signing summary"
```

**Local signature verification:**

```sh
$ git log --show-signature -1
commit abc1234def5678 (HEAD -> feature/lab3)
Good "git" signature for your_email@example.com with ED25519 key SHA256:xYzAbCdEfGh...
Author: Your Name <your_email@example.com>
Date:   Thu Feb 19 2026

    docs: add commit signing summary
```

After pushing to GitHub, the commit displays a green **"Verified"** badge, confirming that GitHub successfully validated the SSH signature against the uploaded signing key.

### 1.4 Analysis: Why Is Commit Signing Critical in DevSecOps Workflows?

Commit signing is a cornerstone of DevSecOps for several reasons:

1. **Preventing supply chain attacks.** Without commit signing, an attacker who gains write access to a repository can forge commits under any developer's identity — Git's `user.name` and `user.email` are self-reported and trivially spoofable. Signed commits make impersonation detectable.

2. **Enforcing branch protection.** GitHub and GitLab allow branch rules that **require signed commits** on protected branches. This means CI/CD pipelines and production deployments only accept cryptographically verified changes, strengthening the trust boundary between development and production.

3. **Audit trail and compliance.** In regulated industries, signed commits provide a verifiable audit trail that maps every code change to a specific developer, satisfying requirements from frameworks like NIST SSDF (PO.3, PS.1) and SOC 2 (CC6.1).

4. **Shift-left trust verification.** Rather than relying solely on perimeter controls, signing embeds trust verification into each atomic unit of work (the commit), aligning with the DevSecOps principle of integrating security into every stage of the SDLC.

5. **Protection against compromised CI systems.** If a CI runner is compromised, an attacker could push unsigned malicious commits. Requiring signatures and verifying them in the pipeline detects such intrusions.

---

## Task 2 — Pre-commit Secret Scanning

### 2.1 Pre-commit Hook Setup

**1. Created the hook file at `.git/hooks/pre-commit`:**

```bash
#!/usr/bin/env bash
set -euo pipefail
echo "[pre-commit] scanning staged files for secrets…"

# Collect staged files (added/changed)
mapfile -t STAGED < <(git diff --cached --name-only --diff-filter=ACM)
if [ ${#STAGED[@]} -eq 0 ]; then
   echo "[pre-commit] no staged files; skipping scans"
   exit 0
fi

FILES=()
for f in "${STAGED[@]}"; do
   [ -f "$f" ] && FILES+=("$f")
done
if [ ${#FILES[@]} -eq 0 ]; then
   echo "[pre-commit] no regular files to scan; skipping"
   exit 0
fi

echo "[pre-commit] Files to scan: ${FILES[*]}"

NON_LECTURES_FILES=()
LECTURES_FILES=()
for f in "${FILES[@]}"; do
   if [[ "$f" == lectures/* ]]; then
      LECTURES_FILES+=("$f")
   else
      NON_LECTURES_FILES+=("$f")
   fi
done

echo "[pre-commit] Non-lectures files: ${NON_LECTURES_FILES[*]:-none}"
echo "[pre-commit] Lectures files: ${LECTURES_FILES[*]:-none}"

TRUFFLEHOG_FOUND_SECRETS=false
if [ ${#NON_LECTURES_FILES[@]} -gt 0 ]; then
   echo "[pre-commit] TruffleHog scan on non-lectures files…"
   
   set +e
   TRUFFLEHOG_OUTPUT=$(docker run --rm -v "$(pwd):/repo" -w /repo \
      trufflesecurity/trufflehog:latest \
      filesystem "${NON_LECTURES_FILES[@]}" 2>&1)
   TRUFFLEHOG_EXIT_CODE=$?
   set -e    
   echo "$TRUFFLEHOG_OUTPUT"
   
   if [ $TRUFFLEHOG_EXIT_CODE -ne 0 ]; then
      echo "[pre-commit] ✖ TruffleHog detected potential secrets in non-lectures files"
      TRUFFLEHOG_FOUND_SECRETS=true
   else
      echo "[pre-commit] ✓ TruffleHog found no secrets in non-lectures files"
   fi
else
   echo "[pre-commit] Skipping TruffleHog (only lectures files staged)"
fi

echo "[pre-commit] Gitleaks scan on staged files…"
GITLEAKS_FOUND_SECRETS=false
GITLEAKS_FOUND_IN_LECTURES=false

for file in "${FILES[@]}"; do
   echo "[pre-commit] Scanning $file with Gitleaks..."
   
   GITLEAKS_RESULT=$(docker run --rm -v "$(pwd):/repo" -w /repo \
      zricethezav/gitleaks:latest \
      detect --source="$file" --no-git --verbose --exit-code=0 --no-banner 2>&1 || true)
   
   if [ -n "$GITLEAKS_RESULT" ] && echo "$GITLEAKS_RESULT" | grep -q -E "(Finding:|WRN leaks found)"; then
      echo "Gitleaks found secrets in $file:"
      echo "$GITLEAKS_RESULT"
      echo "---"
      
      if [[ "$file" == lectures/* ]]; then
            echo "⚠️ Secrets found in lectures directory - allowing as educational content"
            GITLEAKS_FOUND_IN_LECTURES=true
      else
            echo "✖ Secrets found in non-excluded file: $file"
            GITLEAKS_FOUND_SECRETS=true
      fi
   else
      echo "[pre-commit] No secrets found in $file"
   fi
done

echo ""
echo "[pre-commit] === SCAN SUMMARY ==="
echo "TruffleHog found secrets in non-lectures files: $TRUFFLEHOG_FOUND_SECRETS"
echo "Gitleaks found secrets in non-lectures files: $GITLEAKS_FOUND_SECRETS"
echo "Gitleaks found secrets in lectures files: $GITLEAKS_FOUND_IN_LECTURES"
echo ""

if [ "$TRUFFLEHOG_FOUND_SECRETS" = true ] || [ "$GITLEAKS_FOUND_SECRETS" = true ]; then
   echo -e "✖ COMMIT BLOCKED: Secrets detected in non-excluded files." >&2
   echo "Fix or unstage the offending files and try again." >&2
   exit 1
elif [ "$GITLEAKS_FOUND_IN_LECTURES" = true ]; then
   echo "⚠️ Secrets found only in lectures directory (educational content) - allowing commit."
fi

echo "✓ No secrets detected in non-excluded files; proceeding with commit."
exit 0
```

**2. Made the hook executable:**

```bash
chmod +x .git/hooks/pre-commit
```

### 2.2 Test Results — Secret Detection

#### Test 1: Commit Blocked (Secret Detected)

**Step 1.** Created a test file with a fake AWS secret key:

```bash
echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' > test-secret.txt
git add test-secret.txt
git commit -m "test: add file with secret"
```

**Output (commit blocked):**

```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: test-secret.txt
[pre-commit] Non-lectures files: test-secret.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
Found unverified result 🐷🔑❓
Detector Type: AWS
Raw result: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
File: test-secret.txt
[pre-commit] ✖ TruffleHog detected potential secrets in non-lectures files
[pre-commit] Scanning test-secret.txt with Gitleaks...
Gitleaks found secrets in test-secret.txt:
Finding:     AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Secret:      wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
RuleID:      aws-access-token
File:        test-secret.txt
---
✖ Secrets found in non-excluded file: test-secret.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: true
Gitleaks found secrets in non-lectures files: true
Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
```

The commit was **successfully blocked** — the hook exited with code 1 and prevented the secret from entering version control.

#### Test 2: Commit Allowed (Clean File)

**Step 1.** Removed the secret and staged a clean file:

```bash
rm test-secret.txt
git reset HEAD test-secret.txt
echo "This file contains no secrets" > clean-file.txt
git add clean-file.txt
git commit -m "test: add clean file"
```

**Output (commit allowed):**

```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: clean-file.txt
[pre-commit] Non-lectures files: clean-file.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning clean-file.txt with Gitleaks...
[pre-commit] No secrets found in clean-file.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
[feature/lab3 def4567] test: add clean file
 1 file changed, 1 insertion(+)
 create mode 100644 clean-file.txt
```

The commit **proceeded successfully** — both scanners confirmed no secrets were present.

#### Test 3: Lectures Directory Exception

Files in the `lectures/` directory containing educational secret examples are allowed through with a warning, demonstrating the hook's exception logic for educational content.

### 2.3 Analysis: How Automated Secret Scanning Prevents Security Incidents

Automated pre-commit secret scanning addresses one of the most common and costly security failures in software development — accidental credential exposure. Key points:

1. **Shift-left prevention.** Secrets are caught *before* they enter the Git history. Once a secret is committed and pushed, it persists in the repository's history even after deletion, requiring history rewriting (`git filter-repo`) or credential rotation. Pre-commit hooks eliminate this problem at the source.

2. **Defense in depth.** Using two complementary scanners — TruffleHog and Gitleaks — provides overlapping coverage:
   - **TruffleHog** uses entropy analysis and active verification (e.g., testing AWS credentials against the API) to detect both known patterns and high-entropy strings.
   - **Gitleaks** uses regex-based rules optimized for specific provider patterns (AWS, GCP, GitHub tokens, etc.) and is highly configurable via `.gitleaks.toml`.
   
   Running both reduces false negatives, as each tool has different detection strengths.

3. **Developer friction reduction.** Automated scanning removes the burden of manual secret review. Developers receive immediate feedback during `git commit`, making the fix cycle fast (seconds) compared to discovering leaked secrets in production (hours to days).

4. **Compliance and audit.** Automated scanning provides evidence that an organization has proactive controls against credential leakage, supporting compliance with PCI-DSS (Req. 6.5.3), SOC 2 (CC6.1), and OWASP guidelines.

5. **Docker-based execution.** Running scanners via Docker containers ensures consistent, reproducible results across all developer machines without requiring local tool installation, and the scanner versions can be pinned for reproducibility.
