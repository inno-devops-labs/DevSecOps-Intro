# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `C:/Users/and28/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:
`commit 2935c9075fdf0659611c044ec2365d54997ae9ce (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for and28012006@gmail.com with ED25519 key SHA256:dA/D8+rIDx4+cVIJk2KE+Ae9UowvqV5OZmLuI9UTrN4
Author: RC-5555 <and28012006@gmail.com>
Date:   Wed Jun 17 20:53:33 2026 +0300

    test: first signed commit`

### GitHub verification
- Direct link to your most recent commit on GitHub: 
https://github.com/RC-5555/DevSecOps-Intro/commit/2935c9075fdf0659611c044ec2365d54997ae9ce
- Screenshot of the Verified badge: <inline image OR link to image file in PR>

### One-paragraph reflection (2-3 sentences)
What STRIDE-R (Repudiation) scenario would a forged-author commit enable in a real
team's codebase? How does the Verified badge make that attack visible?
A forged-author commit enables a scenario where an attacker can commit malicious code under another developer's identity. The Verified badge makes this attack visible because the commit must be signed with the author's private key. Without it, the badge doesn't appear, and the team knows the commit is suspicious.


## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### `pre-commit install` output
`pre-commit installed at .git\hooks\pre-commit`

### The blocked commit
```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=REDACTEDD
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

3:39PM INF 1 commits scanned.
3:39PM INF scan completed in 42.6ms
3:39PM WRN leaks found: 1
```

### Tune-out exercise
Suppose a teammate insists they need to commit `AKIA*` strings because they're documentation examples in `docs/`. Briefly describe two approaches:

**Inline allowlist** — This approach provides `gitleaks` with a key or a pattern that it has to ignore. This is OK when the secret is 100% fake. This may be risky because developers may solve all the problems with this approach, just to save time, leaking real secrets.
**Path exclusion** — This approach provides `gitleaks` with a whole **folder** that it must not scan. This is very risky, because people may easily forget that this folder is not allowed to store real secrets in, and leak data.