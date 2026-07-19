# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/yalmen/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
commit 1d676ad1a4034c9ac1aec08a732bf2a71fdafcdb (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for namespaces=git with ED25519 key SHA256:REDACTED
Author: yalmen <yalmen@kali.yalmen>
Date:   Thu Jun 18 09:14:42 2026 +0300

    test: first signed commit

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/lashmanovSergey/DevSecOps-Intro/commit/11f47153d89f944ab64471e1fdd0e4d40a82aef4
    - Sorry, I didn't have email address in my github config, so there was 3 attempt to get verified commit. But I did it :)
- Screenshot of the Verified badge:
![alt text](image.png)

### One-paragraph reflection (2-3 sentences)
What STRIDE-R (Repudiation) scenario would a forged-author commit enable in a real
team's codebase? How does the Verified badge make that attack visible?

The "Verified" badge effectively removes the ambiguity of authorship. A commit with a "Verified" badge provides undeniable proof that a commit came from the developer it claims to be from, directly preventing the repudiation attack.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files

### pre-commit install output
pre-commit installed at .git/hooks/pre-commit

### The blocked commit
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/yalmen/.cache/pre-commit/patch1781764944-44676.
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
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

9:42AM INF 0 commits scanned.
9:42AM INF scanned ~101 bytes (101 bytes) in 46.1ms
9:42AM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
[INFO] Restored changes from /home/yalmen/.cache/pre-commit/patch1781764944-44676.

### Tune-out exercise
Suppose a teammate insists they need to commit AKIA* strings because they're documentation examples in docs/. Briefly describe two approaches:

1. Inline allowlist — [allowlist] block in .gitleaks.toml. When is this OK?
    - It's OK when keys are fake
    - When files that never change (like documentation?)
    - And in case when you manullay review keys

2. Path exclusion — paths: [docs/] in .gitleaks.toml. When is this risky? (2-3 sentences each. No correct answer; both have tradeoffs.)
    - An attacker could hide a real AWS key in a docs file, and Gitleaks would ignore it
    - If someone copies code from docs into real code later, the secret escapes unnoticed

## PR checklist body:

- [x] Task 1 — SSH signing configured + Verified badge on commit
- [x] Task 2 — .pre-commit-config.yaml + gitleaks demonstrably blocking
- [ ] Bonus — filter-repo rewrite practice documented
