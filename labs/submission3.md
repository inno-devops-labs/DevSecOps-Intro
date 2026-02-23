# Lab 3 — Secure Git

## Task 1 — SSH Commit Signature Verification (5 pts)

**Summary**

Signing commits with SSH ensures the authenticity and integrity of the code history. It cryptographically proves that a commit was created by you and hasn't been altered after signing. This protects against impersonation, tampering, and man‑in‑the‑middle attacks. Without signatures, anyone with write access could forge commits under another developer's name, undermining trust in the codebase.

**Evidence**
1. SSH Key Generation and Git Configuration
```
# Generate an ED25519 key pair
ssh-keygen -t ed25519 -C "stepansarantsev1@gmail.com"

# Configure Git to use SSH signing
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgSign true
```
2. Verification of Git Settings
```
commit.gpgsign=true
gpg.format=ssh
user.signingkey=/home/a/.ssh/id_ed25519.pub
```
3. SSH Key Added to GitHub as a Signing Key\
![SSH Key](/home/a/Desktop/devsecops/DevSecOps-Intro/labs/images/key)
4. Signed Commit\
git commit -S -m "docs: add commit signing summary"
5. Verified Badge on GitHub\
![Verified Badge](/home/a/Desktop/devsecops/DevSecOps-Intro/labs/images/verif)

**Analysis**\
In DevSecOps, trust in the software supply chain is paramount. Automated pipelines pull code from repositories and deploy it to production. If an attacker manages to inject malicious code under a trusted identity, the entire pipeline becomes compromised. Signed commits act as a cryptographic seal, allowing CI/CD systems to reject any change that lacks a valid signature from an authorised developer. This enforces non‑repudiation, simplifies audit trails, and ensures that every line of code can be traced back to its legitimate author. Combined with branch protection rules that require signatures, commit signing becomes a cornerstone of secure software delivery.
### Task 2 — Pre-commit Secret Scanning (5 pts)

#### Create Pre-commit Hook

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

#### Test Secret Detection
A test file test_aws_key.txt was created containing a fake AWS access key:\\
```
AKIAIOSFODNN7EXAMPLE
```
The file was staged and a commit attempted:

```
git add test_aws_key.txt
git commit -m "test: intentional secret"
```
Terminal output:
```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: test_secret.txt
[pre-commit] Non-lectures files: test_secret.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
Cannot connect to the Docker daemon at unix:///home/a/.docker/desktop/docker.sock. Is the docker daemon running?
[pre-commit] ✖ TruffleHog detected potential secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning test_secret.txt with Gitleaks...
[pre-commit] No secrets found in test_secret.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: true
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.

```
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