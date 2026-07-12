# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/sato/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
commit b9d281f80474504ede2ab4a471930fd6cd1c4b57 (HEAD -> feature/lab3, origin/feature/lab3)
Good signature from my Git signing key
Author: Troshkins <troskin454@gmail.com>
Date:   Sat Jun 13 23:30:22 2026 +0300

    test: first signed commit


### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/inno-devops-labs/DevSecOps-Intro/commit/b9d281f80474504ede2ab4a471930fd6cd1c4b57
- Screenshot of the Verified badge: https://github.com/Troshkins/DevSecOps-Intro/tree/feature/lab3/submissions/lab3-screen.png

### One-paragraph reflection (2-3 sentences)
A forged-author commit could allow an attacker or careless teammate to push malicious code while making it look like another developer wrote it. This creates a STRIDE-R / Repudiation problem because the real author can deny responsibility and the team cannot rely on the Git author field alone. A Verified badge makes this attack visible because it proves whether the commit was signed by a trusted key connected to the claimed GitHub account.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.28.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-added-large-files
```

### `pre-commit install` output

```text
pre-commit installed at .git/hooks/pre-commit
```

### `pre-commit run --all-files` output

```text
Detect hardcoded secrets.................................................Passed
check for added large files..............................................Passed
```

Note: initially, `detect-private-key` was tested but removed because it failed on an existing file from another lab: `labs/lab6/vulnerable-iac/ansible/configure.yml`. Since this file is outside Lab 3 scope, I kept `check-added-large-files` as the required additional hook.

### The blocked commit

Output of the `git commit` that gitleaks blocked:

```text
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/sato/.cache/pre-commit/patch1781385202-2797103.
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

12:13AM INF 0 commits scanned.
12:13AM INF scanned ~101 bytes (101 bytes) in 93.3ms
12:13AM WRN leaks found: 1

check for added large files..............................................Passed
[INFO] Restored changes from /home/sato/.cache/pre-commit/patch1781385202-2797103.
```

### Tune-out exercise

1. **Inline allowlist**

Inline allowlist via .gitleaks.toml is appropriate when you need to permit a specific known secret example, such as a demonstration string used in training or documentation. This is acceptable as long as the allowlist is highly specific: a particular rule ID, a specific fake value, or another clearly safe example. The approach becomes risky if the allowlist is too broad, because real secrets with a similar format may bypass detection.

2. **Path exclusion**

Path exclusion, for example excluding the docs/ directory, is appropriate only when the directory truly contains documentation and regularly uses fake secrets as examples. This is riskier because gitleaks stops scanning the entire path. If someone accidentally commits a real token into docs/, the scanner will no longer detect it.

## Bonus: History Rewrite

### Before

```text
d0489be (HEAD -> master) docs: add usage notes
f38439a feat: empty log
b7bb2ec feat: add config
b0c1134 init
```

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

```text
b5075be (HEAD -> master) docs: add usage notes
889f164 feat: empty log
69d9a2f feat: add config
edfc8e8 init
```

Output of `git log -p | grep -c 'ghp_'`: **0**

Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life

1. `git filter-repo --replace-text replacements.txt` — rewrite locally.
2. Rotate the leaked secret. Rewriting history only removes the exposed value from Git history, but it does not make the leaked credential safe again. In a real incident, the old key must be revoked and replaced, because it may already have been copied from the repository.

### Two real-world gotchas I discovered

1. `git filter-repo` does not just edit files; it rewrites Git history. After the rewrite, all commit hashes changed, so this operation would require coordination in a real shared repository.

2. The bonus repo must stay outside the course fork. The sandbox contains a deliberately planted fake secret, so committing `/tmp/lab3-bonus` or its files into the course repository would defeat the purpose of the exercise.

