# Lab 3 — Submission

  

## Task 1: SSH Commit Signing

  

### Local configuration

- `git config --global gpg.format` → `ssh`

- `git config --global user.signingkey` → `/home/sami/.ssh/id_ed25519.pub`

- `git config --global commit.gpgsign` → `true`

  

### Local verification

Output of `git log --show-signature -1`:

```

commit 035652a26e29b94fa6d9e76cc21369f9a4f63e0e (HEAD -> feature/lab3)

Good "git" signature for sami-k0@yandex.ru with ED25519 key SHA256:[REDACTED]

Author: SamiKO228 <sami-k0@yandex.ru>

Date: Thu Jun 18 02:21:54 2026 +0300

  

test: first signed commit

```

  
  

### GitHub verification

- Direct link to your most recent commit on GitHub:

`https://github.com/inno-devops-labs/DevSecOps-Intro/commit/035652a26e29b94fa6d9e76cc21369f9a4f63e0e`

- Screenshot of the Verified badge:![alt text](image.png)

  

### One-paragraph reflection (2-3 sentences)

#### Question:

What STRIDE-R (Repudiation) scenario would a forged-author commit enable in a real

team's codebase? How does the Verified badge make that attack visible?

#### Answer:

A forged-author commit could allow an attacker to make malicious or unauthorized changes while pretending to be another team member. This creates a repudiation risk because the real author may deny responsibility and the team may not be able to reliably determine who actually made the change. The GitHub Verified badge makes such attacks visible by proving that the commit was signed with a trusted key associated with the author's account.

  
  

## Task 2: Pre-commit + gitleaks

  

### `.pre-commit-config.yaml`

```

repos:

- repo: https://github.com/gitleaks/gitleaks

rev: v8.28.0

hooks:

- id: gitleaks

  

- repo: https://github.com/pre-commit/pre-commit-hooks

rev: v5.0.0

hooks:

- id: detect-private-key

- id: check-added-large-files

```

  

### `pre-commit install` output

`pre-commit installed at .git/hooks/pre-commit`

  
  

### The blocked commit [Output of the `git commit` that gitleaks blocked (the failing hook output)]:

  

```bash

Detect hardcoded secrets.................................................Failed

- hook id: gitleaks

- exit code: 1

  

Finding: GH_PAT=REDACTED

Secret: REDACTED

RuleID: github-pat

Entropy: 4.143943

File: submissions/leak-attempt.txt

Line: 2

Fingerprint: submissions/leak-attempt.txt:github-pat:2

  

INF 0 commits scanned.

INF scanned ~101 bytes (101 bytes)

WRN leaks found: 1

```

  

## Bonus: History Rewrite

  

### Before

  

```text

6eda8d1 (HEAD -> master) docs: add usage notes

419015a feat: empty log

2cae7de feat: add config

e722567 init

```

  

Output of `git log -p | grep -c 'ghp_'`: **2**

  

### After

  

```text

5a39a06 (HEAD -> master) docs: add usage notes

f8e27e7 feat: empty log

d996ff8 feat: add config

57f3711 init

```

  

Output of `git log -p | grep -c 'ghp_'`: **0**

Output of `git log -p | grep -c 'REDACTED'`: **2**

  

### The two-step pattern in real life

  

1. `git filter-repo --replace-text replacements.txt` — rewrite locally

2. Revoke or rotate the exposed credential and replace it with a new one. Rewriting Git history removes the secret from the repository, but it does not make the leaked credential safe to use again.

  

### Two real-world gotchas you discovered (2 sentences each)

  

1. `git filter-repo` refused to run on a normal repository because it was not a fresh clone. I had to use the `--force` option to allow the history rewrite in the sandbox repository.

  

2. After the rewrite, all commit hashes changed even though the commit messages stayed the same. This happens because Git recreates the affected commits when repository history is rewritten.