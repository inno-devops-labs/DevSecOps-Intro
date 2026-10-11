\# Lab 3 — Submission



\## Task 1: SSH Commit Signing



\### Local configuration



\* `git config --global gpg.format` → `ssh`

\* `git config --global user.signingkey` → `C:\\Users\\Karina\\.ssh\\id\_ed25519.pub`

\* `git config --global commit.gpgsign` → `true`



\### Local verification



Output of `git log --show-signature -1`:



```text

Good "git" signature for krotovakarina53@gmail.com with ED25519 key SHA256:JpjoKWQeTS7CvdnJwex0QJyl6cd4ZD8fw1pxPGGyonw

```



\### GitHub verification



\* Direct link to commit on GitHub: `<PASTE\_COMMIT\_URL>`

\* Screenshot of the Verified badge: `<attach screenshot in PR>`



\### Reflection



A repudiation attack happens when a developer denies creating a commit or claims that a malicious change was made by someone else. An attacker could forge authorship information and introduce harmful code while pretending to be another team member. Verified commit signatures make this attack visible because GitHub can verify that the commit was signed with the expected private key.



---



\## Task 2: Pre-commit + gitleaks



\### `.pre-commit-config.yaml`



```yaml

default\_stages: \[pre-commit]



repos:

&nbsp; - repo: https://github.com/gitleaks/gitleaks

&nbsp;   rev: v8.30.1

&nbsp;   hooks:

&nbsp;     - id: gitleaks

&nbsp;       args: \["--config", ".gitleaks.toml", "--redact"]



&nbsp; - repo: https://github.com/pre-commit/pre-commit-hooks

&nbsp;   rev: v5.0.0

&nbsp;   hooks:

&nbsp;     - id: check-added-large-files

```



\### `pre-commit install` output



```text

pre-commit installed at .git\\hooks\\pre-commit

```



\### Hook execution



```text

Detect hardcoded secrets.................................................Passed

check for added large files..............................................Passed

```



\### Notes



Gitleaks v8.30.1 was successfully installed and integrated with pre-commit. The hook executed during commit operations and scanned staged content. The provided test secret from the lab instructions was not detected by the current gitleaks rule set, which may differ from the version assumed by the lab documentation.



\### Tune-out exercise



\#### 1. Inline allowlist



An inline allowlist is appropriate when a specific fake credential is intentionally used for testing or documentation. It minimizes risk because only a known value is ignored while all other secrets continue to be scanned.



\#### 2. Path exclusion



Excluding an entire directory such as `docs/` reduces false positives but can be dangerous. If a real secret is accidentally committed in that directory, gitleaks will not scan it and the secret may remain unnoticed.



