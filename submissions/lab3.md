# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration

- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/home/demonit/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification

Output of `git log --show-signature -1`:

```text
commit 39bcbcf9af97afcf45a97fff0e3f49f60db01e5d (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for arsgames4028@gmail.com with ED25519 key SHA256:Y1hruybz/P3gY+m1MS5QWsu6nofEzm/nTPLX0fv/mCA
Author: arseniy <arsgames4028@gmail.com>
Date:   Wed Jun 17 18:38:21 2026 +0300

    test: first signed commit
```

### GitHub verification

- Direct link to your most recent commit on GitHub:

`https://github.com/demonit4028/DevSecOps-Intro/commit/39bcbcf9af97afcf45a97fff0e3f49f60db01e5d`

- Screenshot of the Verified badge:

![alt text](image.png)

### One-paragraph reflection

A forged-author commit could allow an attacker to push malicious code while impersonating another developer. This creates a STRIDE-R (Repudiation) problem because the real author may deny responsibility and the team cannot reliably prove who created the change. The Verified badge makes such attacks visible by cryptographically binding the commit to the developer's signing key.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### `pre-commit install` output

```text
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit

Output of the `git commit` that gitleaks blocked:

```text
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/demonit/.cache/pre-commit/patch1781711692-10516.

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

6:54PM INF 1 commits scanned.
6:54PM INF scan completed in 6.84ms
6:54PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed

[INFO] Restored changes from /home/demonit/.cache/pre-commit/patch1781711692-10516.
```

### Tune-out exercise

#### 1. Inline allowlist

An inline allowlist in `.gitleaks.toml` is acceptable when the secret-like value is a well-known example used for educational or documentation purposes. This approach is safer because it ignores only a specific value while continuing to scan the rest of the repository.

#### 2. Path exclusion

Excluding entire paths such as `docs/` is risky because real secrets may accidentally appear there and remain undetected. Path exclusions should only be used when the directory is guaranteed not to contain sensitive information and the team understands this tradeoff.

---

## Bonus: History Rewrite

### Before

```text
c084d19 docs: add usage notes
78f7f4a feat: empty log
f00bfd4 feat: add config
a7715c3 init
```

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

```text
8674eab docs: add usage notes
d546596 feat: empty log
f348e15 feat: add config
a7715c3 init
```

Output of `git log -p | grep -c 'ghp_'`: **0**

Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life

1. `git filter-repo --replace-text replacements.txt` — rewrite locally.
2. Rotate the leaked secret and force-push the rewritten history to the remote repository.

### Two real-world gotchas you discovered

1. `git filter-repo` refused to run because the repository was not considered a fresh clone. I had to use the `--force` flag to allow the history rewrite.

2. Installing `gitleaks` through `apt` on Kali repeatedly failed with HTTP 404 errors. I solved the problem by downloading the release archive directly from GitHub and placing the binary into `/usr/local/bin`.