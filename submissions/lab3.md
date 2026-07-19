# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/semyon/.ssh/id_ed25519_git.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
```
commit ff6311a831ef1e473f1589df2e19050ac7882080 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for semyonnadutkin@gmail.com with ED25519 key SHA256:kHLu+8G6I6q2XCrYHNXtaLhp7Rx05rUAcef0UMej4FA
Author: Semyon Nadutkin <semyonnadutkin@gmail.com>
Date:   Sat Jun 13 10:24:54 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/semyonnadutkin/DevSecOps-Intro/commit/ff6311a831ef1e473f1589df2e19050ac7882080
- Screenshot of the Verified badge: https://drive.google.com/file/d/1y1cS3rJqtlGWfK_TYRhYxiaByKT_Z9l8/view?usp=sharing

### One-paragraph reflection
A forged-author commit could enable a repudiation attack by allowing a developer to falsely claim that another team member created a change, which makes it hard to find the person responsible for introducing a bug or malicious code. The "Verified" badge makes forged-authorship attempts visible because only the properly signed commits are marked with the badge.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`

```yaml
repos:
-   repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
    -   id: gitleaks
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
    -   id: detect-private-key
        exclude: ^(labs/lab6/)
    -   id: check-added-large-files
```

### `pre-commit install` output
```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
```
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/semyon/.cache/pre-commit/patch1781346060-253948.
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

1:21PM INF 0 commits scanned.
1:21PM INF scanned ~101 bytes (101 bytes) in 29.9ms
1:21PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
[INFO] Restored changes from /home/semyon/.cache/pre-commit/patch1781346060-253948.
```

### Tune-out exercise
Suppose a teammate insists they need to commit `AKIA*` strings because they're documentation examples in `docs/`. Briefly describe two approaches:
1. **Inline allowlist** — `[allowlist]` block in `.gitleaks.toml`.
An inline `[allowlist]` block is appropriate when the documented `AKIA*` examples are known and intentionally included for educational or documentation purposes. It keeps scanning enabled for the rest of the repository while suppressing only specific false positives, reducing the chance of missing real secrets elsewhere.
2. **Path exclusion** — `paths: [docs/]` in `.gitleaks.toml`.Excluding the entire `docs/` directory is riskier because Gitleaks will stop scanning all files under that path, including any accidentally committed real credentials. While it reduces maintenance overhead compared to managing individual allowlist entries, it creates a blind spot where genuine secret leaks may go undetected.

## Bonus: History Rewrite

### Before
```
1dd7de3 (HEAD -> master) docs: add usage notes
fdf08e7 feat: empty log
a0f8ffd feat: add config
2096790 init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```
ff9cb39 (HEAD -> master) docs: add usage notes
ed6f028 feat: empty log
2f386d9 feat: add config
7b61216 init
```
Output of `git log -p | grep -c 'ghp_'`: **0**  
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **Rotate the leaked secrets** — revoke the secrets and reissue.

### Two real-world gotchas you discovered
1. The SSH Authorization Keys do not sign commits on GitHub. After adding an SSH Signing Key, new commits are marked "Verified" and signed with the SSH key.
2. `git filter-repo` refused to run on a repository that was not a fresh clone. The use of `--force` option allowed the history rewrite to proceed in the sandbox repository.