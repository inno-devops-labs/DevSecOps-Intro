lab3 signing test

# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/alisa_plafonova/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:

```bash
commit 7523596db2d15e352673b32368534449f94de9b7 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for namespaces=git with ED25519 key SHA256:nfTvjOGRCTg9/LsdXr27BMuK4+dUFQe1bA6Ko4giLW0
Author: Alisa <chepuhonka2345@gmail.com>
Date:   Fri Jun 19 15:28:48 2026 +0300

    test: first signed commit
```


### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/raylduk8/DevSecOps-Intro/commit/7523596db2d15e352673b32368534449f94de9b7
- Screenshot of the Verified badge: <inline image OR link to image file in PR>

### One-paragraph reflection (2-3 sentences)
What STRIDE-R (Repudiation) scenario would a forged-author commit enable in a real
team's codebase? How does the Verified badge make that attack visible?

An attacker can make a fake commit containing malicious code, impersonating someone else. A verified badge makes this attack visible. A commit signed with someone else's key or even unsigned is marked as unverified, so everyone can see the potential forgery.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)

```bash
repos:
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
    -   id: detect-private-key
    -   id: check-added-large-files
  
-   repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
    -   id: gitleaks
```

### pre-commit install output

```bash
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit

Output of the git commit that gitleaks blocked (the failing hook output):

```bash
- hook id: gitleaks
- exit code: 1
Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1
5:27PM INF 1 commits scanned.
5:27PM INF scan completed in 69.6ms
5:27PM WRN leaks found: 1
```

## Tune-out exercise

Suppose a teammate insists they need to commit AKIA* strings because they're documentation examples in docs/. Briefly describe two approaches:

- Inline allowlist — [allowlist] block in .gitleaks.toml. When is this OK?

This would be adequate if we were sure that the AKIA sample string was being used and not the real secret, then we could add an exception for that specific string.

- Path exclusion — paths: [docs/] in .gitleaks.toml. When is this risky? (2-3 sentences each. No correct answer; both have tradeoffs.)

This is easier to set up because developers can freely commit documentation. However, files containing real keys can accidentally end up there, and <b>geatleaks</b> will simply ignore them.