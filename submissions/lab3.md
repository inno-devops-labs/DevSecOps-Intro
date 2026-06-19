# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /Users/glebshvetsov/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification

Output of `git log --show-signature -1`:

    commit 445b42369135670e1c54e860934546c2ec25a962 (HEAD -> feature/lab3)
Good "git" signature for darkdeathinvader@gmail.com with ED25519 key SHA256:[REDACTED]
Author: Gleb Shvetsov <darkdeathinvader@gmail.com>
Date:   Fri Jun 19 20:16:12 2026 +0300

    feat(lab3): SSH signing + gitleaks pre-commit + history rewrite practice

### GitHub verification

- Direct link to your most recent commit on GitHub: WILL_PASTE_AFTER_PUSH
- Screenshot of the Verified badge: WILL_ADD_SCREENSHOT_IN_PR

### One-paragraph reflection

A forged-author commit could allow an attacker to make malicious code look like it was written by a trusted teammate, which creates a Repudiation problem because the real author can deny responsibility and the team cannot reliably prove who made the change. A Verified badge makes this attack visible because GitHub checks that the commit was signed by a key connected to that developer’s account. If the signature is missing or invalid, the team immediately sees that the commit identity should not be trusted.


## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`

    repos:
      - repo: https://github.com/gitleaks/gitleaks
        rev: v8.30.0
        hooks:
          - id: gitleaks

      - repo: https://github.com/pre-commit/pre-commit-hooks
        rev: v6.0.0
        hooks:
          - id: detect-private-key
            exclude: ^labs/lab6/vulnerable-iac/ansible/configure\.yml$
          - id: check-added-large-files

### `pre-commit install` output

    pre-commit installed at .git/hooks/pre-commit

### `pre-commit run --all-files` output

    Detect hardcoded secrets.................................................Passed
    detect private key.......................................................Passed
    check for added large files..............................................Passed

Note: I excluded `labs/lab6/vulnerable-iac/ansible/configure.yml` only for the `detect-private-key` hook because it is an existing vulnerable IaC example from the course repository. Without this narrow exclusion, `pre-commit run --all-files` fails on a file that is unrelated to Lab 3.

### The blocked commit

    Detect hardcoded secrets.................................................Failed
    - hook id: gitleaks
    - exit code: 1

    Finding:     GH_PAT=REDACTED
    Secret:      REDACTED
    RuleID:      github-pat
    Entropy:     4.143943
    File:        submissions/leak-attempt.txt
    Line:        2
    Fingerprint: submissions/leak-attempt.txt:github-pat:2

    8:02PM INF 0 commits scanned.
    8:02PM INF scanned ~101 bytes (101 bytes) in 22.8ms
    8:02PM WRN leaks found: 1

    detect private key.......................................................Passed
    check for added large files..............................................Passed

### Tune-out exercise

1. **Inline allowlist**

An inline allowlist in `.gitleaks.toml` is acceptable when the value is clearly fake, intentionally used for documentation or tests, and limited to a very specific pattern. This is safer than disabling scanning for a whole directory because gitleaks still checks the rest of the file and the rest of the repository.

2. **Path exclusion**

A path exclusion such as excluding `docs/` is risky because real secrets can still accidentally appear in documentation files. It may be acceptable only if the directory contains generated or third-party documentation with many known false positives, but it should be reviewed carefully and kept as narrow as possible.


## Bonus: History Rewrite

### Before

    77ab3d5 (HEAD -> main) docs: add usage notes
    f1afc5b feat: empty log
    6acc5e8 feat: add config
    3b8b86e init

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

    4405644 (HEAD -> main) docs: add usage notes
    b770ffb feat: empty log
    bface22 feat: add config
    a6df709 init

Output of `git log -p | grep -c 'ghp_'`: **0**

Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life

1. `git filter-repo --replace-text replacements.txt` — rewrite locally.
2. Rotate or revoke the leaked secret immediately. Rewriting Git history only removes the secret from the repository history, but it does not make the already leaked credential safe again.

### Two real-world gotchas you discovered

1. `git filter-repo` refused to run at first because the repository did not look like a fresh clone and showed the error about destructively overwriting history. Since this was only a sandbox repository in `/tmp`, I used `--force`, but in a real project this would require much more care and team coordination.

2. After the rewrite, all commit hashes changed. For example, the latest commit changed from `77ab3d5` to `4405644`, which means a real shared repository would require a force-push and other teammates would need to resynchronize their local clones.
