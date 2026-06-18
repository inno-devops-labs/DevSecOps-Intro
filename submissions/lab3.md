# Lab 3 — Submission
 
## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → ~/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
commit ae7a16e8b91c2b5055f130824e4eafd12eec9290
Good "git" signature for a.gainutdinova@innopolis.university with ED25519 key SHA256:qO/fDJ4nxjz+JNQ7jr9eAboeEB0bSL4olSebdLXMC3E
Author: alilek a.gainutdinova@innopolis.university
Date: Thu Jun 18 15:51:01 2026 +0300
test: first signed commit for Lab 3
### GitHub verification
- Direct link to signed commit: https://github.com/inno-devops-labs/DevSecOps-Intro/commit/64b8d365af134c290e0b828d0a6590f702bf3e15
- Screenshot: 
<img width="509" height="117" alt="image" src="https://github.com/user-attachments/assets/e0b46d06-a508-48fa-ae62-09daebc34470" />


### STRIDE-R reflection
A forged-author commit enables a **Repudiation** attack where a malicious insider or attacker who compromises a developer's machine can push malicious code while pretending it came from a trusted team member. Without cryptographic signatures, the real author can later deny writing the code ("it wasn't me"), and the team has no way to prove otherwise. The "Verified" badge on GitHub makes this attack visible by cryptographically proving that only the holder of the private SSH key could have created that commit — any unsigned or badly-signed commit immediately raises suspicion and can be traced back to the actual key holder.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### `pre-commit install` output
```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of `git commit` after planting a fake AWS key:

```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     AWS_ACCESS_KEY_ID=REDACTED
Secret:      REDACTED
RuleID:      aws-access-token
Entropy:     3.684184
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:aws-access-token:1

8:41PM WRN leaks found: 1
```

### Tune-out exercise

**1. Inline allowlist** — `[allowlist]` block in `.gitleaks.toml`. When is this OK?

This approach is acceptable when you have legitimate example strings that must remain in the codebase (e.g., documentation showing API key formats, canonical test fixtures like `AKIAIOSFODNN7EXAMPLE`). The allowlist should be narrowly scoped to specific regex patterns or commit hashes, and reviewed by the security team to ensure it doesn't accidentally whitelist real secrets. It's the most precise method because it only exempts exact matches, not entire directories.

**2. Path exclusion** — `paths: [docs/]` in `.gitleaks.toml`. When is this risky?

Path exclusion is risky because it creates a blind spot where real secrets can hide. If a developer accidentally commits a real AWS key inside `docs/` (for example, in a tutorial or troubleshooting guide), gitleaks won't scan that directory at all and the leak will slip through to production. This approach should only be used for directories that are 100% documentation with no executable code or configuration examples, and should be combined with manual code review for those paths.
