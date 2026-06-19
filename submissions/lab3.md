# Lab 3 - Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` -> `ssh`
- `git config --global user.signingkey` -> `~/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` -> `true`

### Local verification
Output of `git log --show-signature -1`:
commit 31d8292493e6a4a2f296ccb3fcc8bfc9c4c9f668 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for dudnyashka2006@gmail.com with ED25519 key SHA256:+FVa5orAeRvszaLrTd8BTnoGGkk2c0aMvcdOO1QkmPM
Author: Tatiana <dudnyashka2006@gmail.com>
Date:   Fri Jun 19 19:43:01 2026 +0300

    test: first signed commit

### GitHub verification
- Direct link to my most recent commit on github: https://github.com/witch2256/DevSecOps-Intro/commit/31d8292493e6a4a2f296ccb3fcc8bfc9c4c9f668
- Screenshot of the Verified badge:

### One-paragraph reflection
If an attacker can forde a commit author, they can inject malicious code and later deny having done so, causing confusion and undermining thust in the codebase. Signed commits protect the team from both external impersonation and internal disputes about who introduced a change.

## Task 2

### `.pre-commit-config.yaml`
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks

### `pre-commit install` output
pre-commit installed at .git/hooks/pre-commit

### The blocked commit
Output of `git commit` that git blocks:
git commit -m "test: should be blocked"
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/witch/.cache/pre-commit/patch1781891085-14212.
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

8:44PM INF 1 commits scanned.
8:44PM INF scan completed in 11.4ms
8:44PM WRN leaks found: 1

[INFO] Restored changes from /home/witch/.cache/pre-commit/patch1781891085-14212.


### Tune-out exercise

1. **Inline allowlist** – can be added to the `.gitleaks.toml`, block `[allowlist]` This is appropriate if you know for sure the string is a test inclusion, but dangerous because you ca naccidentallu publish a real secret.

2. **Path exclusion** – can be chenged`docs/`,to gitleaks not check files there. This is risky because the documentation may also require keys to be specified. Better to use whitelist with provided strings rather than checking entire directories.

