# Lab 3 — Secure Git

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-Secure%20Git-blue)
![points](https://img.shields.io/badge/points-10-orange)

> **Goal:** Practice secure Git fundamentals: signed commits and pre-commit secret scanning.  
> **Deliverable:** A PR from `feature/lab3` to the course repo with `labs/submission3.md` containing secure Git practices implementation. Submit the PR link via Moodle.

---

## Overview

In this lab you will practice:
- Verifying commit authenticity with **SSH commit signing**
- Preventing secrets exposure with **pre-commit scanning** (TruffleHog + Gitleaks)
- Implementing automated security controls in development workflows

---

## Tasks

### Task 1 — SSH Commit Signature Verification (5 pts)

**Objective:** Configure SSH commit signing to verify commit authenticity and integrity.

#### 1.1: Research Commit Signing Benefits

Study why commit signing is crucial for verifying the integrity and authenticity of commits:
- [GitHub Docs on SSH Commit Verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
- [Atlassian Guide to SSH and Git](https://confluence.atlassian.com/bitbucketserver/sign-commits-and-tags-with-ssh-keys-1305971205.html)

#### 1.2: Configure SSH Commit Signing

1. **Generate SSH Key (Option A - Recommended):**

   ```sh
   ssh-keygen -t ed25519 -C "your_email@example.com"
   ```

2. **Use Existing SSH Key (Option B):**

   Use an existing SSH key and add it to GitHub

3. **Configure Git for SSH Signing:**

   ```sh
   git config --global user.signingkey <YOUR_SSH_KEY>
   git config --global commit.gpgSign true

   ```

#### 1.3: Create Signed Commit

```sh
git commit -S -m "docs: add commit signing summary"
```

In `labs/submission3.md`, document:
- Summary explaining the benefits of signing commits for security
- Evidence of successful SSH key setup and configuration
- Analysis: "Why is commit signing critical in DevSecOps workflows?"
- Screenshots or verification of the "Verified" badge on GitHub

---

### Task 2 — Pre-commit Secret Scanning (5 pts)

**Objective:** Implement local Git pre-commit hook that scans staged changes for secrets using Dockerized TruffleHog and Gitleaks.

#### 2.1: Create Pre-commit Hook

1. **Setup Pre-commit Hook File:**

   Create `.git/hooks/pre-commit` with the following content:

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

2. **Make Hook Executable:**

   ```bash
   chmod +x .git/hooks/pre-commit
   ```

#### 2.2: Test Secret Detection

Verify hook functionality:
- Add a test secret (e.g., fake AWS key) to a file and stage it
- Attempt to commit - should be blocked by TruffleHog or Gitleaks
- Remove/redact the secret, then commit again to confirm success

In `labs/submission3.md`, document:
- Pre-commit hook setup process and configuration
- Evidence of successful secret detection blocking commits
- Test results showing both blocked and successful commits
- Analysis of how automated secret scanning prevents security incidents

---

## How to Submit

1. Create a branch for this lab and push it to your fork:

   ```bash
   git switch -c feature/lab3
   # create labs/submission3.md with your findings
   git add labs/submission3.md
   git commit -m "docs: add lab3 submission"
   git push -u origin feature/lab3
   ```

2. Open a PR from your fork's `feature/lab3` branch → **course repository's main branch**.

3. In the PR description, include:

   ```text
   - [x] Task 1 done — SSH commit signing setup
   - [x] Task 2 done — Pre-commit secrets scanning setup
   ```

4. **Copy the PR URL** and submit it via **Moodle before the deadline**.

---

## Acceptance Criteria

- ✅ Branch `feature/lab3` exists with commits for each task
- ✅ File `labs/submission3.md` contains required analysis for both tasks
- ✅ At least one commit shows **"Verified"** (signed via SSH) on GitHub
- ✅ Local `.git/hooks/pre-commit` runs TruffleHog and Gitleaks via Docker and blocks secrets
- ✅ PR from `feature/lab3` → **course repo main branch** is open
- ✅ PR link submitted via Moodle before the deadline

---

## Rubric (10 pts)

| Criterion                                        | Points |
| ------------------------------------------------ | -----: |
| Task 1 — SSH commit signing setup + analysis    |  **5** |
| Task 2 — Pre-commit secrets scanning setup      |  **5** |
| **Total**                                        | **10** |

---

## Guidelines

- Use clear Markdown headers to organize sections in `submission3.md`
- Include both command outputs and written analysis for each task
- Document security configurations and testing procedures thoroughly
- Demonstrate both successful and blocked operations for secret scanning

<details>
<summary>Security Configuration Notes</summary>

- Ensure the email on your commits matches your GitHub account for proper verification
- Verify `gpg.format` is set to `ssh` for proper signing configuration
- Test pre-commit hooks thoroughly with both legitimate and test secret content
- Docker Desktop/Engine must be running for secret scanning tools
- Ensure all commits are properly signed for verification on GitHub

</details>
