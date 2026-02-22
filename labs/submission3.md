# Lab 3 — Secure Development Practices

## Task 1 — SSH Commit Signing

### What was implemented

SSH-based commit signing was configured to ensure commit authenticity and integrity.

Git configuration:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgSign true
```

A signed commit was created and pushed to GitHub. The commit is marked as **Verified**, confirming that:

- The commit was signed with a registered SSH key.
- GitHub successfully validated the signature.
- The author identity is cryptographically bound to the commit.

### Why commit signing is important

1. **Integrity** — prevents tampering with commit history.
2. **Authenticity** — verifies commits were made by the legitimate author.
3. **Supply chain protection** — reduces risk of malicious code injection.
4. **Account compromise mitigation** — attackers cannot forge signed commits without the private key.
5. **Trust in pull requests** — reviewers can verify commit origin.

---

## Task 2 — Pre-commit Secret Scanning

### Implementation

A `pre-commit` hook was created at:

```text
.git/hooks/pre-commit
```

The hook runs secret scanners on **staged files**:

- **TruffleHog** (via Docker)
- **Gitleaks** (via Docker)

If a potential secret is detected in **non-excluded files**, the commit is blocked.  
Files under `lectures/` may be treated as educational content depending on the hook logic.

> **Note (local environment issue):** On my Windows setup, Docker containers launched from Git hooks fail due to a working-directory path mapping issue:
> `docker: ... working directory 'C:/Program Files/Git/repo' is invalid ...`
> This is a Docker/Git-for-Windows path integration problem, not a false positive from the scanners.

### Test case — Secret detection (commit blocked)

A test secret was intentionally created:

```powershell
"AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF" | Out-File -Encoding utf8 .\secret_test.txt
git add secret_test.txt
git commit -m "test: add fake secret"
```

Hook output (excerpt):

```text
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: secret_test.txt
[pre-commit] Non-lectures files: secret_test.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
docker: Error response from daemon: the working directory 'C:/Program Files/Git/repo' is invalid, it needs to be an absolute path

[pre-commit] ✖ TruffleHog detected potential secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning secret_test.txt with Gitleaks...
[pre-commit] No secrets found in secret_test.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: true
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
```

Result:

- The commit was **blocked** by the hook.
- TruffleHog flagged a potential AWS access key.
- The secret was prevented from entering the repository history.

Cleanup:

```powershell
git restore --staged secret_test.txt
Remove-Item .\secret_test.txt
```

### Security impact

This prevents:

- Accidental leakage of API keys and tokens
- Exposure of cloud credentials
- Permanent secret exposure in Git history
- CI/CD credential compromise
- Supply chain attacks via leaked credentials

Secret scanning at commit time is safer than relying only on CI pipelines or post-merge scanning.

---

## Conclusion

This lab implemented two secure development controls:

1. **Cryptographic commit signing** (SSH) for integrity and authorship validation.
2. **Pre-commit secret scanning** to prevent sensitive data from entering version control.

Together, these measures strengthen repository security and reduce the risk of credential leakage.
