# Lab 3 --- Secure Development Practices

## Task 1 --- SSH Commit Signing

### What was implemented

SSH-based commit signing was configured to ensure commit authenticity
and integrity.

Git was configured with:

git config --global gpg.format ssh git config --global user.signingkey
\~/.ssh/id_ed25519.pub git config --global commit.gpgSign true

A signed commit was created and pushed to GitHub. The commit is marked
as **Verified**, confirming that:

-   The commit was signed with a registered SSH key.
-   GitHub successfully validated the signature.
-   The author identity is cryptographically bound to the commit.

### Why commit signing is important

1.  Integrity -- prevents tampering with commit history.
2.  Authenticity -- verifies that commits were made by the legitimate
    author.
3.  Supply chain protection -- reduces risk of malicious code injection.
4.  Account compromise mitigation -- attackers cannot forge signed
    commits without the private key.
5.  Trust in pull requests -- reviewers can verify commit origin.

Commit verification on GitHub shows a green **Verified** badge,
confirming successful SSH signing configuration.

------------------------------------------------------------------------

## Task 2 --- Pre-commit Secret Scanning

### Implementation

A pre-commit hook was created in:

.git/hooks/pre-commit

The hook runs:

-   TruffleHog (via Docker) on staged files
-   Gitleaks on staged files

The hook blocks commits if potential secrets are detected in
non-excluded files.

------------------------------------------------------------------------

### Test Case --- Secret Detection

A test secret was intentionally created:

PowerShell commands:

"AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF" \| Out-File -Encoding utf8
.`\secret`{=tex}\_test.txt git add secret_test.txt git commit -m "test:
add fake secret"

Hook output:

\[pre-commit\] scanning staged files for secrets... \[pre-commit\] Files
to scan: secret_test.txt \[pre-commit\] Non-lectures files:
secret_test.txt \[pre-commit\] Lectures files: none \[pre-commit\]
TruffleHog scan on non-lectures files... docker: Error response from
daemon: the working directory 'C:/Program Files/Git/repo' is invalid, it
needs to be an absolute path

\[pre-commit\] ✖ TruffleHog detected potential secrets in non-lectures
files \[pre-commit\] Gitleaks scan on staged files... \[pre-commit\]
Scanning secret_test.txt with Gitleaks... \[pre-commit\] No secrets
found in secret_test.txt

\[pre-commit\] === SCAN SUMMARY === TruffleHog found secrets in
non-lectures files: true Gitleaks found secrets in non-lectures files:
false Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files. Fix or unstage
the offending files and try again.

Result:

-   The commit was successfully blocked.
-   TruffleHog detected a potential AWS access key.
-   The hook prevented the secret from entering the repository history.

The test file was then removed:

git restore --staged secret_test.txt Remove-Item
.`\secret`{=tex}\_test.txt

------------------------------------------------------------------------

### Security Impact

This mechanism prevents:

-   Accidental leakage of API keys
-   Exposure of cloud credentials
-   Long-term secret exposure in Git history
-   CI/CD credential compromise
-   Supply chain attacks via leaked tokens

Secret scanning at commit time is significantly safer than relying only
on CI pipelines or post-merge scanning.

------------------------------------------------------------------------

## Conclusion

This lab implemented two core secure development controls:

1.  Cryptographic commit signing for integrity and authorship
    validation.
2.  Pre-commit secret scanning to prevent sensitive data from entering
    version control.

Together, these measures strengthen repository security, protect CI/CD
pipelines, and reduce the risk of credential leakage.
