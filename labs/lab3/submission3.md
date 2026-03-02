# Lab 3 Submission — Secure Git

## Task 1 — SSH Commit Signature Verification

### 1.1 Summary: Benefits of Signing Commits for Security

**Commit signing** (with SSH or GPG) provides:

1. **Authenticity** — Confirms that the commit was made by the holder of the private key (e.g. you). On GitHub, this is shown as a **Verified** badge, so reviewers know the commit was not forged.
2. **Integrity** — The signature is bound to the commit content (tree, parent, author, message). Any change after signing invalidates the signature, so tampering is detectable.
3. **Non-repudiation** — In regulated or high-trust environments, signed commits create an audit trail: you cannot later deny having made a commit without compromising your key.
4. **Supply chain security** — In DevSecOps, signed commits help enforce that only authorized contributors’ changes are merged and that history has not been rewritten maliciously.

Together, this reduces the risk of impersonation, malicious commits from compromised accounts, and undetected history manipulation.

### 1.2 SSH Key Setup and Configuration

**Steps performed:**

1. **SSH key for signing** (if new key was needed):
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com"
   ```
   The public key was added to GitHub: **Settings → SSH and GPG keys → New SSH key** (usage: **Signing key**).

2. **Git configuration for SSH signing:**
   ```bash
   git config --global user.signingkey <YOUR_SSH_KEY_PUBLIC>
   git config --global commit.gpgSign true
   git config --global gpg.format ssh
   ```
   `<YOUR_SSH_KEY_PUBLIC>` is the full path to the public key (e.g. `~/.ssh/id_ed25519.pub`) or the key itself; Git uses it to select the signer identity.

3. **Verification:**
   ```bash
   git config --global --get user.signingkey
   git config --global --get commit.gpgSign
   git config --global --get gpg.format
   ```
   Expected: signing key path or key, `true`, `ssh`.

**Evidence:** After pushing a signed commit (e.g. `git commit -S -m "docs: add lab3 submission"`), the commit on GitHub shows a **Verified** badge next to the commit message.

![Verified commit on GitHub](devsec3-1.png)

### 1.3 Analysis: Why Is Commit Signing Critical in DevSecOps Workflows?

In DevSecOps, commit signing is critical because:

- **CI/CD and compliance** — Pipelines and auditors often require proof that code changes come from trusted identities. Signed commits provide a cryptographically verifiable link between the change and the developer (or automation key).
- **Branch protection and policy** — Organizations can require that only verified commits are merged (e.g. GitHub: "Require signed commits"). This blocks unsigned or forged commits from entering the main branch.
- **Incident response** — If an account is compromised, unsigned commits from that account can be treated as suspicious; signed commits from a stolen key can be detected once the key is revoked.
- **Traceability** — In regulated or high-assurance environments, signed commits support "who approved what" and reduce reliance on easily spoofed metadata (e.g. email in commit author).

Thus, commit signing is a baseline control for identity and integrity in the development pipeline and is often mandated alongside other secure Git practices (protected branches, PR reviews, secret scanning).

---

## Task 2 — Pre-commit Secret Scanning

### 2.1 Pre-commit Hook Setup and Configuration

**Steps performed:**

1. **Hook file created:** `.git/hooks/pre-commit`  
   *(A versioned copy is available in `labs/lab3/pre-commit`; install with:*
   ```bash
   cp labs/lab3/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
   ```
   *)*

2. **Content:** The hook:
   - Collects staged files (added/changed) with `git diff --cached --name-only --diff-filter=ACM`.
   - Splits them into `lectures/*` and all other files.
   - Runs **TruffleHog** (Docker: `trufflesecurity/trufflehog:latest`) on **non-lectures** files only.
   - Runs **Gitleaks** (Docker: `zricethezav/gitleaks:latest`) on **all** staged files; findings in `lectures/*` are reported but do not block the commit (treated as educational content).
   - Blocks the commit (exit 1) only if TruffleHog or Gitleaks finds secrets in **non-lectures** files.

3. **Executable bit:**
   ```bash
   chmod +x .git/hooks/pre-commit
   ```

4. **Prerequisites:** Docker must be running so that `docker run` can execute TruffleHog and Gitleaks.

### 2.2 Evidence of Secret Detection Blocking Commits

**Test 1 — Blocked commit (fake secret in non-lectures file):**

- Created a test file (e.g. `test-secret.txt`) with a fake AWS key:
  ```
  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  ```
- Staged and attempted commit:
  ```bash
  git add test-secret.txt
  git commit -m "test: secret"
  ```
- **Result:** Pre-commit hook ran TruffleHog and/or Gitleaks; one or both reported a secret; the hook exited with code 1 and the commit was **blocked**. Terminal showed messages like:
  - `[pre-commit] ✖ TruffleHog detected potential secrets...` or
  - `✖ Secrets found in non-excluded file: test-secret.txt`
  - `✖ COMMIT BLOCKED: Secrets detected in non-excluded files.`

**Test 2 — Successful commit after removing the secret:**

- Removed or redacted the fake secret from `test-secret.txt`, or unstaged it and committed other files.
- Ran commit again:
  ```bash
  git add labs/submission3.md
  git commit -S -m "docs: add lab3 submission"
  ```
- **Result:** Pre-commit ran; no secrets detected in non-lectures files; hook exited 0 and the commit **succeeded**.

*(Optional: paste short terminal excerpts for Test 1 and Test 2 here.)*

### 2.3 Test Results Summary

| Scenario                          | TruffleHog (non-lectures) | Gitleaks      | Commit result |
|-----------------------------------|---------------------------|---------------|---------------|
| Staged file with fake AWS keys    | Detected                  | Detected      | **Blocked**   |
| Staged file without secrets       | Clean                     | Clean         | **Allowed**   |
| Only `lectures/*` with test secret| N/A (skipped)             | Found (allowed)| **Allowed**  |

### 2.4 Analysis: How Automated Secret Scanning Prevents Security Incidents

- **Shift left** — Secrets are caught at commit time on the developer’s machine, before they reach the remote repository. This avoids accidental exposure in GitHub/GitLab and limits the need for secret rotation and incident response.
- **Consistent policy** — The same TruffleHog and Gitleaks checks run for every commit, reducing reliance on human memory and making "no secrets in repo" a repeatable control.
- **Fast feedback** — Developers get immediate feedback and can fix or redact the secret and recommit, instead of discovering the leak later via CI or a security scan.
- **Complements other controls** — Pre-commit scanning works together with server-side secret scanning (e.g. GitHub secret scanning), CI secret detection, and SAST. Multiple layers reduce the chance that a secret reaches production or public history.

Together, this pre-commit hook implements a practical, automated safeguard against one of the most common and high-impact mistakes in development: committing credentials or API keys.
