# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → ~/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
git log --show-signature -1
commit 4cc054284fe36ba7e98deb1fbb63b35049ae993d (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for perekrestova.i@yandex.ru with ED25519 key SHA256:VFcU3cHVxkbc36re8h/tXzO8EoqQ4kiuLU5ojbEFUkQ
Author: ashuno <perekrestova.i@yandex.ru>
Date:   Fri Jun 19 22:35:42 2026 +0300

    first signed commit

### GitHub verification
Direct link to the most recent commit on GitHub: `https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1153/changes/14fd1fa5d4449d002762ef99e630e4048d96f1f4`
Screenshot of the Verified badge: `https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1153#issuecomment-4754425067`

### Reflection 
Without verification, a malicious commit becomes difficult to trace. With the Verified badge, every change is connected to a real person


## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks


### pre-commit install output
pre-commit installed at .git/hooks/pre-commit

### The blocked commit
detect private key.......................................................Passed
check for added large files..............................................Passed
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

11:29PM INF 0 commits scanned.
11:29PM INF scanned ~48 bytes (48 bytes) in 68.4ms
11:29PM WRN leaks found: 1


### Tune-out exercise

1) Inline allowlist — when is this OK?
Inline allowlist (using `allowlist` block in `.gitleaks.toml`) is acceptable when the secret-like string is explicitly part of the codebase as a test fixture, API example, or documentation snippet that must remain unchanged. However, the allowlist applies globally across all files, so if a real secret uses the same pattern later, gitleaks will silently ignore it. This approach should be used sparingly and only for well-known, explicitly documented example values.

2) Path exclusion — when is this risky?
Path exclusion (using `paths` block in `.gitleaks.toml`) is much riskier because it creates a permanent blind spot. This is especially dangerous in team environments where multiple developers contribute to documentation and might accidentally paste real API keys, tokens, or credentials.
