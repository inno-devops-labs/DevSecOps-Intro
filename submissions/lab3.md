# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /Users/rii/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
```
Output of `git log --show-signature -1`:
commit f710a7d7b33810226a2cd603b1abff7d6c7825c6 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for namespaces=git with ED25519 key SHA256:W9mgJHshjfQoW5M5bVgtVjKS7dcrHesF7kJ9vssSV58
Author: RII6 <albert.khechoyan16@gmail.com>
Date:   Sat Jun 13 18:12:12 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/inno-devops-labs/DevSecOps-Intro/commit/f710a7d7b33810226a2cd603b1abff7d6c7825c6
- Screenshot of the Verified badge: ![image](/submissions/verified.png)

### One-paragraph reflection (2-3 sentences)
What STRIDE-R (Repudiation) scenario would a forged-author commit enable in a real
team's codebase? How does the Verified badge make that attack visible?



## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.2
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
Output of the `git commit` that gitleaks blocked (the failing hook output):
```
rii:~/Code/DSO lab3/DevSecOps-Intro % git commit -m "test: should be blocked by gitleaks"
[WARNING] top-level `default_stages` uses deprecated stage names (commit) which will be removed in a future version.  run: `pre-commit migrate-config` to automatically fix this.
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

Finding:     ...es=git with ED25519 key SHA256:REDACTED
Author: RII6 <alber...
Secret:      REDACTED
RuleID:      generic-api-key
Entropy:     4.646968
File:        submissions/lab3.md
Line:        14
Fingerprint: submissions/lab3.md:generic-api-key:14

9:30PM INF 1 commits scanned.
9:30PM INF scan completed in 7.84ms
9:30PM WRN leaks found: 2

detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise
Suppose a teammate insists they need to commit `AKIA*` strings because they're documentation examples in `docs/`. Briefly describe two approaches:
1. **Inline allowlist** — `[allowlist]` block in `.gitleaks.toml`. When is this OK?
This approach is OK when the specific,standardized dummy values (e.g., AKIAIOSFODNN7EXAMPLE) for documentation or testing are used. It is highly secure because it only permits those exact safe strings to pass. If a developer accidentally commits a real, unique AWS key, the scanner will still successfully catch and block it.


2. **Path exclusion** — `paths: [docs/]` in `.gitleaks.toml`. When is this risky?
Excluding an entire directory is highly risky because it creates a massive blind spot for the security scanner. If a developer accidentally saves a .env file, an error log, or actual configuration containing real production secrets into the docs/ folder, the scanner will silently ignore it, leading to a critical leak.


## Bonus: History Rewrite

### Before
```
3000deb (HEAD -> main) docs: add usage notes
ecb830e feat: empty log
ee634b2 feat: add config
b1ac2cd init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```
451e894 (HEAD -> main) docs: add usage notes
74dc0f8 feat: empty log
4d2a994 feat: add config
beccefa init
```
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally.
2. **Secret Rotation (Revocation)** — This is the mandatory second step. Cleaning the history only removes the secret from the repository. However, since the secret was already pushed to a remote server, it is compromised. You must go to the service provider (e.g., GitHub, AWS), revoke the old compromised key, and generate a new one.

### Error without --forced
The tool has a built-in safety mechanism and refuses to destructively overwrite history if the repository is not a "fresh clone" (e.g., if there are reflog entries from recent work). I had to explicitly add the `--force` flag to bypass this protection and proceed with the rewrite.