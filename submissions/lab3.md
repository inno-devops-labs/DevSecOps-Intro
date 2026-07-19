# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → <output>
- `git config --global user.signingkey` → <output>
- `git config --global commit.gpgsign` → <output>

### Local verification
Output of `git log --show-signature -1`:
```
commit 3981230e2cb6f39734f156b910ab6f0b775a147d (HEAD -> feature/lab3)
Good "git" signature for 47586934+err0r522@users.noreply.github.com with ED25519 key 
```
Although the key is public, I had to remove the fingerprint (gitleaks).
```
Author: err0r522 <47586934+err0r522@users.noreply.github.com>
Date:   Fri Jun 26 21:54:59 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: [Link](https://github.com/err0r522/DevSecOps-Intro/commit/3981230e2cb6f39734f156b910ab6f0b775a147d)
- Screenshot of the Verified badge: Link to image file in PR

### One-paragraph reflection (2-3 sentences)
A malicious actor can make a commit using a team member's name and email address to impersonate them and push malicious code on their behalf. However, such commit won't have the Verified badge, so if the team member normally signs their commits, the unverified commit will immediately stand out and allow them to prove they weren't the one who pushed it.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.24.2
    hooks:
      - id: gitleaks
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### `pre-commit install` output
```
pre-commit installed at .git\hooks\pre-commit
```

### The blocked commit
Output of the `git commit` that gitleaks blocked (the failing hook output):
```
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
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

10:36PM INF 1 commits scanned.
10:36PM INF scanned ~101 bytes (101 bytes) in 68.9ms
10:36PM WRN leaks found: 1
```

### Tune-out exercise
Suppose a teammate insists they need to commit `AKIA*` strings because they're documentation examples in `docs/`. Briefly describe two approaches:
1. **Inline allowlist** — `[allowlist]` block in `.gitleaks.toml`. This is OK when the strings are easily identifiable as fake and only show up in one place. However, it is not okay to make many of such exceptions as they tend to accumulate.
2. **Path exclusion** — `paths: [docs/]` in `.gitleaks.toml`. It is risky if the directory contains any leftover logs or dumps. Though human error is also a risk on it's own, whoever writes the docs can make an intentional or accidental mistake.
```