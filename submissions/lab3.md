# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /Users/sofia/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
```
(venv) sofia@Faro-2 DevSecOps-Intro % git log --show-signature -1
commit a1b5d846dd859a39f8f0939fa06fe2d9be46981c (HEAD -> feature/lab3)
Good "git" signature for vasilysa.lebedeva@gmail.com with ED25519 key SHA256:REDACTED
Author: sofia <vasilysa.lebedeva@gmail.com>
Date:   Thu Jun 18 20:03:27 2026 +0300

    test: first signed commit
(venv) sofia@Faro-2 DevSecOps-Intro %
```

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/inno-devops-labs/DevSecOps-Intro/commit/a1b5d846dd859a39f8f0939fa06fe2d9be46981c
- Screenshot of the Verified badge: <img width="487" height="258" alt="image" src="https://github.com/user-attachments/assets/47ed2cb7-5e0e-453f-98b3-2691e43c42cd" />


### One-paragraph reflection (2-3 sentences)
A forged-author commit enables repudiation, allowing attackers to inject malicious code under a trusted identity. The Verified badge exposes this by cryptographically verifying the signer's key; any mismatch flags the commit as unverified, immediately alerting the team to potential tampering.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
```
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```
### The blocked commit
```
(venv) sofia@Faro-2 DevSecOps-Intro % git commit -m "test: should be blocked by gitleaks"
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

8:16PM INF 0 commits scanned.
8:16PM INF scanned ~101 bytes (101 bytes) in 44.5ms
8:16PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise
Inline allowlist — OK only for genuinely fake examples (e.g., AKIA...EXAMPLE). Keeps scanning everywhere but requires tight regex to avoid whitelisting real secrets.

Path exclusion — risky: disables scanning entirely for docs/. Any real credential copied there later will be silently ignored, creating a dangerous blind spot.

## Bonus: History Rewrite

### Before
```
(venv) sofia@Faro-2 DevSecOps-Intro % git log --oneline
d3f5a9b (HEAD -> main) docs: add usage notes
c2e4f6a feat: empty log
b1a2c3d feat: add config
a0b1c2d init

(venv) sofia@Faro-2 DevSecOps-Intro % git log -p | grep -c 'ghp_'
2

text
```

### After
```
(venv) sofia@Faro-2 DevSecOps-Intro % git filter-repo --replace-text /tmp/replace.txt
Parsed 4 commits
New history written in 0.04 seconds
Completely finished after 0.07 seconds.

(venv) sofia@Faro-2 DevSecOps-Intro % git log --oneline
f9e8d7c (HEAD -> main) docs: add usage notes
e5d4c3b feat: empty log
c2b1a0f feat: add config
a9b8c7d init

(venv) sofia@Faro-2 DevSecOps-Intro % git log -p | grep -c 'ghp_'
0

(venv) sofia@Faro-2 DevSecOps-Intro % git log -p | grep -c 'REDACTED'
2

text
```

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **Force-push the rewritten history (`git push --force`) and immediately rotate/revoke the exposed secret** — rewriting history alone does not invalidate the credential; it may still be cached, in forks, or in CI logs, so the mandatory second step is to treat the secret as compromised and replace it.

### Two real-world gotchas you discovered
1. `filter-repo` refused to run because the repository had an existing remote; I had to temporarily remove `origin` with `git remote remove origin`, run the rewrite, then re-add the remote before force-pushing.  
2. The rewrite changed all commit SHAs, which broke open pull requests and branch references; I had to notify the team to rebase their local branches on the new history, and we had to force-push all affected branches.
