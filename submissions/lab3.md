# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/s1nner/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
commit 7122a78a4bab0a4eba87edc09a55e45775064815 (HEAD -> feature/lab3)
Good "git" signature for d.kim@innopolis.university with ED25519 key SHA256:/CCR/tTkADQLDBL9e4aPpkA6MaI5BVKudqrM0SBwiwM
Author: Dmitrii d.kim@innopolis.university
Date:   Fri Jul 10 21:57:11 2026 +0300
test: first signed commit

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/zeitrin/DevSecOps-Intro/commit/7122a78a4bab0a4eba87edc09a55e45775064815
- Screenshot of the Verified badge: <inline image OR link to image file in PR>

### One-paragraph reflection (2-3 sentences)
Without commit signing, anyone can forge the author field with `git commit --author="Trusted Dev
<trusted@corp.com>"`, making a malicious commit appear to come from a trusted maintainer — a
Repudiation attack (STRIDE-R): the real author denies writing it, and the framed developer cannot
prove they didn't. In a real codebase this lets an attacker slip a backdoor into a PR under a
respected name, and afterwards nobody can attribute it reliably. The Verified badge makes this
visible because it proves the commit was cryptographically signed by a key GitHub has bound to that
specific account — a forged-author commit shows "Unverified", so the mismatch between the claimed
author and the missing signature is immediately obvious to reviewers.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (full content)
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
        args: ["--maxkb=5000"]
```

### `pre-commit install` output
pre-commit installed at .git/hooks/pre-commit

### The blocked commit
Output of the `git commit` that gitleaks blocked (the failing hook output):
Detect hardcoded secrets.................................................Failed

hook id: gitleaks
exit code: 1
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
10:06PM INF 0 commits scanned.
10:06PM INF scanned ~101 bytes (101 bytes) in 41.7ms
10:06PM WRN leaks found: 1
The commit was aborted: gitleaks matched the `github-pat` rule on the planted
`ghp_...` token and returned exit code 1, so the secret never entered a commit.

### Tune-out exercise

**1. Inline allowlist** — a `[allowlist]` block (with `regexes` or `stopwords`) in
`.gitleaks.toml` tells gitleaks to ignore specific patterns everywhere. This is acceptable when the
allowlisted value is provably a non-secret — a canonical documentation example, a well-known dummy
key, or a value with no real-world validity (e.g. AWS's `AKIAIOSFODNN7EXAMPLE`). It is precise
because it targets the exact string, but it is global: if the same pattern later appears as a *real*
secret, it will also be silently allowed, so the allowlist must be narrow and reviewed.

**2. Path exclusion** — `paths: [docs/]` in `.gitleaks.toml` stops gitleaks scanning an entire
directory. This is convenient when a folder is known to contain only illustrative examples, but it
is risky because it is coarse: it disables *all* secret detection for that path, so a genuine
credential accidentally committed under `docs/` would sail through undetected. Path exclusion trades
away coverage for quiet, and the blind spot grows over time as the excluded directory accumulates
files nobody re-checks — inline allowlisting a specific string is almost always safer than excluding
a whole path.
