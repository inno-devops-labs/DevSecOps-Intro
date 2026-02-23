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
![SSH Key](/labs/images/key)
4. Signed Commit\
git commit -S -m "docs: add commit signing summary"
5. Verified Badge on GitHub\
![Verified Badge](/labs/images/verif)

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
aws_access_key_id = ...
aws_secret_access_key = ...
github_token = ...
stripe_test_key = ...

```
The file was staged and a commit attempted:

```
git add secrets.txt
git commit -m "test"
```
Terminal output:
```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: secrets.txt
[pre-commit] Non-lectures files: secrets.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-02-23T11:16:09Z    info-0  trufflehog      running source  {"source_manager_worker_id": "8T9hE", "with_units": true}
2026-02-23T11:16:10Z    info-0  trufflehog      finished scanning       {"chunks": 1, "bytes": 213, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "953.897647ms", "trufflehog_version": "3.93.4", "verification_caching": {"Hits":0,"Misses":2,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":1343}}
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning secrets.txt with Gitleaks...
Gitleaks found secrets in secrets.txt:
Finding:     stripe_test_key = ...
Secret:      ...
RuleID:      stripe-access-token
Entropy:     4.538910
File:        secrets.txt
Line:        4
Fingerprint: secrets.txt:stripe-access-token:4

11:16AM INF scanned ~213 bytes (213 bytes) in 91.4ms
11:16AM WRN leaks found: 1
---
✖ Secrets found in non-excluded file: secrets.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: true
Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.

```
Successful commit
```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: labs/submission3.md
[pre-commit] Non-lectures files: labs/submission3.md
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-02-23T11:20:36Z    info-0  trufflehog      running source  {"source_manager_worker_id": "JBEq3", "with_units": true}
2026-02-23T11:20:36Z    info-0  trufflehog      finished scanning       {"chunks": 0, "bytes": 0, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "2.605609ms", "trufflehog_version": "3.93.4", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning labs/submission3.md with Gitleaks...
[pre-commit] No secrets found in labs/submission3.md

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
[feature/lab3 abcd9e8] docs: complete lab3 submission
 1 file changed, 249 deletions(-)
 rewrite labs/submission3.md (100%)

```

**Analysis**\
Automated secret scanning in pre-commit hooks acts as a first line of defense against accidental credential exposure by intercepting secrets before they ever reach the remote repository, thereby eliminating the risks of public leaks (where a secret pushed to a public repository can be harvested by bots within minutes, leading to account compromise or financial loss), historical contamination (since even if a secret is later removed from the code, it remains in the Git history, making credential rotation costly and time‑consuming), and compliance violations (as standards like PCI‑DSS and HIPAA require that secrets never be stored in code repositories). This hook implements shift‑left security by giving developers immediate feedback to fix issues locally, avoiding the need for incident response teams to clean up after a leak. By combining TruffleHog, which uses entropy and pattern detection, with Gitleaks, which relies on a comprehensive rule set, the hook provides a robust defense against a wide variety of secret types. In a DevSecOps context, such automated controls are essential to maintain the integrity of the software supply chain and to build a culture of security awareness among developers.
