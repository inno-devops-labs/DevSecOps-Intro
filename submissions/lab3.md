## Task 1: SSH Commit Signing

### Configuration

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

### Signature Verification

```text
commit 9e32bf2cf1980b4060f7491a48d221ad63ff189a
Good "git" signature for jsugarpork@gmail.com with ED25519 key 
Author: vanyaspapayas <jsugarpork@gmail.com>

test: first signed commit
```

### GitHub Verification

A screenshot showing the "Verified" badge on GitHub is attached separately.

### STRIDE-R Reflection

Commit signing mitigates the Repudiation threat in STRIDE. Without signatures, an attacker could impersonate another developer by using the same name and email address in commits. Signed commits provide authenticity and non-repudiation, allowing the origin of changes to be verified.

---

## Task 2: Secret Detection

### .pre-commit-config.yaml

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### Simulated Secret Leak

Attempting to commit a file containing a fake GitHub PAT triggered gitleaks:

```text
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding: GH_PAT=REDACTED
RuleID: github-pat
File: labs/submissions/leak-attempt.txt

WRN leaks found: 1
```

The commit was blocked successfully.

---

## Tune-out Exercise

### Inline Allowlist

Inline allowlists are useful when documentation or examples contain strings that resemble secrets. This approach is precise and only ignores specific patterns, minimizing the risk of missing real secrets.

### Path Exclusion

Path exclusions are useful when certain directories contain many false positives. However, excluding entire paths is riskier because a real secret committed into those directories would not be detected.

---

## Bonus: Secret Cleanup

The `git-filter-repo` tool was installed successfully:

```text
git filter-repo --version
a40bce548d2c
```

Removing secrets from Git history alone is insufficient. Leaked credentials must also be rotated or revoked because an attacker may already have copied them before the repository history was cleaned.

```
```

