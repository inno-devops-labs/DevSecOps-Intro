# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/goga/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
```text
commit 7c9f4fa04ce4eb0f9d9977a3b788f0bc63d28159
Good "git" signature for entuacuzima06@gmail.com with ED25519 key SHA256:[REDACTED]
Author: d13-l1t3 <entuacuzima06@gmail.com>
Date:   Fri Jun 19 20:43:02 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/d13-l1t3/DevSecOps-Intro/commit/7c9f4fa04ce4eb0f9d9977a3b788f0bc63d28159
- Screenshot of the Verified badge: https://github.com/d13-l1t3/DevSecOps-Intro/commit/7c9f4fa04ce4eb0f9d9977a3b788f0bc63d28159

### One-paragraph reflection (2-3 sentences)
A forged-author commit could let an attacker make malicious code look like it came from a trusted teammate, creating a repudiation problem because the real author can deny making the change and reviewers may trust the wrong identity. GitHub’s Verified badge makes this attack more visible because it proves the commit was signed by a key associated with that user, so unsigned or incorrectly signed commits stand out during review.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: check-added-large-files
```

### `pre-commit install` output
```text
pre-commit installed at .git/hooks/pre-commit
```

### Sanity check
Output of `pre-commit run --all-files`:
```text
Detect hardcoded secrets.................................................Passed
check for added large files..............................................Passed
```

### The blocked commit
Output of the `git commit` that gitleaks blocked:
```text
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/goga/.cache/pre-commit/patch1781891614-14701.
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

8:53PM INF 0 commits scanned.
8:53PM INF scanned ~101 bytes (101 bytes) in 38.7ms
8:53PM WRN leaks found: 1

check for added large files..............................................Passed
[INFO] Restored changes from /home/goga/.cache/pre-commit/patch1781891614-14701.
```

After the test, I unstaged and removed `submissions/leak-attempt.txt` so the fake secret was not committed.

### Tune-out exercise
1. **Inline allowlist**: An inline allowlist in `.gitleaks.toml` is acceptable when the value is a known fake example and the exception is narrow, documented, and reviewable. This is safer than excluding a whole directory because gitleaks can still scan nearby files and other values.
2. **Path exclusion**: Excluding `docs/` is risky because real secrets are often pasted into documentation during troubleshooting or onboarding. I would only use a path exclusion for a tightly controlled generated-docs path, not for normal human-written documentation.

## Bonus: History Rewrite

### Before

```
a8509a9 (HEAD -> master) docs: add usage notes
57d3229 feat: empty log
8786169 feat: add config
b619a81 init
```

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **Rotate or revoke the leaked secret. Rewriting history removes it from Git history, but the secret must be treated as compromised once it was pushed.** — what's the MANDATORY second step in a real incident?
   (Hint: Lecture 3 slide 12 has this — it's the difference between cleanup and remediation.)

### Two real-world gotchas you discovered (2 sentences each)
1. After git filter-repo, the commit hashes changed because rewriting history creates new commits.
2. git filter-repo is meant for a fresh or sandbox repository; using it on a real shared branch would require coordination and a force push.
