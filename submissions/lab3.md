# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/remnux/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
commit 7f777bf2b97dee0362254be52e4d9aba16948893 (HEAD -> main)
Good "git" signature for ralerrdirsardx@gmail.com with ED25519 key SHA256:Vx/BrUto3V98VwihBNG5+3bRywTdzxO+Ynyy/YBYrl8
Author: raller <ralerrdirsardx@gmail.com>
Date:   Thu Jun 18 15:29:27 2026 -0400

    test: first signed commit
### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/raaller/DevSecOps-Intro/commit/7f777bf2b97dee0362254be52e4d9aba16948893
- Screenshot of the Verified badge: <img width="1630" height="914" alt="image" src="https://github.com/user-attachments/assets/10b76282-d936-4a1d-ad7a-2be6f07ef213" />

### One-paragraph reflection (2-3 sentences)
Commit forgery lets an attacker inject malicious code and later deny responsibility. The Verified badge prevents this by cryptographically binding every commit to the author's SSH key, making any signature mismatch an immediate, visible indicator of compromise.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```
### pre-commit install output:
pre-commit installed at .git/hooks/pre-commit
### The blocked commit:
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

4:13PM INF 0 commits scanned.
4:13PM INF scanned ~101 bytes (101 bytes) in 49.5ms
4:13PM WRN leaks found: 1

detect private key.......................................................Failed
- hook id: detect-private-key
- exit code: 1

Private key found: labs/lab6/vulnerable-iac/ansible/configure.yml

check for added large files..............................................Passed

## Bonus: History Rewrite

### Before
```
2922c0d (HEAD -> master) docs: add usage notes
1b1bbe1 feat: empty log
0e26bf7 feat: add config
dae40cb init
Output of `git log -p | grep -c 'ghp_'`: **2**
```
### After
```
732e352 (HEAD -> master) docs: add usage notes
d5b2a49 feat: empty log
05a8d6d feat: add config
76b1ffc init
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**
```
### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` - rewrite locally
2. Rotation (revocation/rotation of the compromised secret) - the MANDATORY second step. Rewriting history removes the secret from git, but if it was already pushed to a public remote, an attacker may have copied it. Only revoking the token or rotating the key turns cleanup into full remediation.

### Two real-world gotchas
1. filter-repo refused to run because the repo was not a "fresh clone" - it detected multiple reflog entries and aborted with "expected at most one entry in the reflog for HEAD". I had to use `--force` to proceed, which is acceptable in a sandbox but risky on a real shared repo.
2. Commit hashes changed completely after rewrite - all four commits (`init`, `feat: add config`, `feat: empty log`, `docs: add usage notes`) received new SHA-1 hashes because `filter-repo` rewrote the entire history. This means any open PRs, tags, or team members' local branches would diverge and require `git fetch --force` or re-clone.

