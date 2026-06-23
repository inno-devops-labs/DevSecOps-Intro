# Lab 3 — Secure Git: Signed Commits, Secret Scanning, and History Hygiene

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/Users/philip/.ssh/id_ed25519_lab3.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:
```
commit 95d7d57ed0eb3e42d28d420544d9a417aa083bc5 (HEAD -> feature/lab3)
Good "git" signature for idiarephilip@gmail.com with ED25519 key SHA256:G5eGvZ7xEqq/fXPQhJV78wd7a0bXYFisdRSFXSBrrTk
Author: Philip Idiare <idiarephilip@gmail.com>
Date:   Thu Jun 18 03:24:01 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to signed commit on GitHub: https://github.com/Philip-78/DevSecOps-Intro/commit/95d7d57ed0eb3e42d28d420544d9a417aa083bc5
- Verified badge: confirmed green "Verified" badge visible on GitHub commits page for `feature/lab3`

### STRIDE-R reflection
A forged-author commit enables a Repudiation attack where a malicious insider or compromised contributor pushes harmful code — a backdoor, a deleted access control, a leaked secret — under a colleague's name. Without signing, Git's author field is just a string anyone can set with `git config user.email`; the attacker can plausibly deny the commit and blame the colleague. The green Verified badge breaks this attack by cryptographically binding every commit to a specific SSH key: if the signature is missing or from the wrong key, GitHub flags it as Unverified, making the forgery immediately visible to any reviewer or branch protection rule that requires signed commits.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (full content)
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.27.2
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### `pre-commit install` output
```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of the `git commit` that gitleaks blocked:
```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

3:57AM INF 0 commits scanned.
3:57AM INF scanned ~48 bytes (48 bytes) in 30.2ms
3:57AM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise

**1. Inline allowlist — `[allowlist]` block in `.gitleaks.toml`. When is this OK?**
An inline allowlist is appropriate when a specific string is provably not a real secret — for example, a canonical documentation example value like `ghp_16C7e42F292c6912E7710c838347Ae178B4a` that appears in a test fixture or a README explaining what a PAT looks like. The allowlist targets that exact string or regex so only that specific pattern is suppressed while all other matches still fire. This is acceptable because the scope is narrow and deliberate: a reviewer can see exactly what was exempted and why, making the decision auditable.

**2. Path exclusion — `paths: [docs/]` in `.gitleaks.toml`. When is this risky?**
Path exclusion is risky because it silences gitleaks for an entire directory rather than a specific value, meaning a real secret accidentally committed to `docs/` would never be caught. An attacker or careless developer could exploit this blind spot by placing a real credential in a file under the excluded path. It is only acceptable when the excluded path is genuinely static-content-only (auto-generated HTML, pure prose) and is enforced by a separate access control that prevents code or config files from landing there — a condition that is difficult to guarantee long-term as a repository evolves.
