# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → ~/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`: Good "git" signature for its.rinsss@gmail.com

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/ironveils/DevSecOps-Intro/commit/27e8b2484be2fc28ab215a4d693d4deaf14b9bc0
- Screenshot of the Verified badge: ![alt text](image.png)

### One-paragraph reflection
A forged-author commit in a codebase could allow an attacker to inject malicious code while pretending a trusted developer. Without signatures, the team would have no way to prove who actually authored the change. The Verified badge makes this attack visible by showing that the commit was signed with a key that GitHub associates with a specific account, so an unsigned commit from the same author name would be suspicious.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.23.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=500']

### `pre-commit install` output
pre-commit installed at .git\hooks\pre-commit

### The blocked commit
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

9:21PM INF 1 commits scanned.
9:21PM INF scanned ~104 bytes (104 bytes) in 62.7ms
9:21PM WRN leaks found: 1

### Tune-out exercise
1. **Inline allowlist** (`[allowlist]` block in `.gitleaks.toml`) — This is OK when the secret is really a documentation example and the team is aware of it. However, the risk is that someone might accidentally copy a real secret into a file that is covered by the allowlist, and gitleaks would ignore it.

2. **Path exclusion** (`paths: [docs/]` in `.gitleaks.toml`) — This is risky because a developer could place a file with a real secret inside the docs/ folder, and gitleaks would skip scanning it entirely. It's safer to use inline allowlisting at the string level rather than excluding entire directories, as path exclusions create blind spots that attackers could exploit.