# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → <ssh>
- `git config --global user.signingkey` → </home/ratteperk/.ssh/id_ed25519.pub>
- `git config --global commit.gpgsign` → <true>

### Local verification
Output of `git log --show-signature -1`:
```
commit cdd587014371199c10c11df559a8590b4f4faae2 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for spered2109@gmail.com with ED25519 key SHA256:HEqmCG37HkRkR3Q28V4BYUiP2VlfTD4qLvAsChPLckI
Author: ratteperk <spered2109@gmail.com>
Date:   Fri Jun 19 02:55:10 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: <https://github.com/ratteperk/DevSecOps-Intro/commit/cdd587014371199c10c11df559a8590b4f4faae2>
- Screenshot of the Verified badge: <img width="1562" height="86" alt="image" src="https://github.com/user-attachments/assets/752734ca-65f0-492d-8de6-aee1bef9dba1" />

### One-paragraph reflection (2-3 sentences)
Without signed commits, an attacker can fake user.name and email to push malicious code and later deny doing it (Repudiation). The GitHub "Verified" badge prevents this by cryptographically proving the commit came from the developer's actual SSH key. If a commit lacks the badge, the team instantly knows it's spoofed.


## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: end-of-file-fixer
      - id: trailing-whitespace

```

### `pre-commit install` output
```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of the `git commit` that gitleaks blocked (the failing hook output):
```
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/ratteperk/.cache/pre-commit/patch1781878314-2223631.
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

5:11PM INF 1 commits scanned.
5:11PM INF scan completed in 16.4ms
5:11PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
fix end of files.........................................................Passed
trim trailing whitespace.................................................Passed
[INFO] Restored changes from /home/ratteperk/.cache/pre-commit/patch1781878314-2223631.
```

### Tune-out exercise
Suppose a teammate insists they need to commit `AKIA*` strings because they're documentation examples in `docs/`. Briefly describe two approaches:
1. **Inline allowlist** — `[allowlist]` block in `.gitleaks.toml`. When is this OK?

```
Add a [allowlist] block in .gitleaks.toml with regexes or paths that match the documentation examples (e.g., AKIAIOSFODNN7EXAMPLE). This is OK when the "secrets" are canonical test values published by AWS/GitHub themselves and will never be rotated. It's risky if the allowlist grows too broad — a real leaked key matching the same pattern could slip through.
```

2. **Path exclusion** — `paths: [docs/]` in `.gitleaks.toml`. When is this risky?

```
Add paths: [docs/] in .gitleaks.toml so gitleaks skips the entire docs folder. This is simpler and doesn't require regex tuning, but it's risky because any real secret accidentally dropped into docs/ (e.g., a screenshot with credentials, a config snippet) will bypass scanning entirely. It trades precision for convenience.
```

(2-3 sentences each. No correct answer; both have tradeoffs.)
