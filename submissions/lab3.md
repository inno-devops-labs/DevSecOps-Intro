# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /Users/ranishaertdinov/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
```
commit 9d44f18eee3c291d0758fc0ec8caaae44f23094b (HEAD -> feature/lab3)
Good "git" signature for khaertdinovranis@gmail.com with ED25519 key SHA256:<fingerprint>
Author: Ranis Haertdinov <khaertdinovranis@gmail.com>
Date:   Thu Jun 18 21:20:32 2026 +0300

    feat(lab3): SSH signing + gitleaks pre-commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/RanisKhaertdinov/DevSecOps-Intro/commit/9d44f18eee3c291d0758fc0ec8caaae44f23094b
- Screenshot of the Verified badge: commit shows green "Verified" badge on GitHub

### One-paragraph reflection
A forged-author commit lets an attacker push malicious code under a trusted developer's name. This is a classic STRIDE-R (Repudiation) threat — the real author can deny the change, and blame falls on the impersonated person. The Verified badge blocks this: a commit signed with the wrong key (or unsigned) shows "Unverified", making the forgery immediately visible in code review.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (full content)
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

### `pre-commit install` output
```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
```
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /Users/ranishaertdinov/.cache/pre-commit/patch1781806698-4064.
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
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

9:18PM INF 0 commits scanned.
9:18PM INF scanned ~48 bytes (48 bytes) in 30.4ms
9:18PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
[INFO] Restored changes from /Users/ranishaertdinov/.cache/pre-commit/patch1781806698-4064.
```

### Tune-out exercise

**1. Inline allowlist** (`[allowlist]` in `.gitleaks.toml`)
This exempts a specific regex pattern from triggering gitleaks. It is safe when the pattern matches only well-known fake values (e.g., canonical AWS example keys) that will never appear in real configs. The scope is narrow, so the risk of silencing a real secret is low.

**2. Path exclusion** (`paths: [docs/]` in `.gitleaks.toml`)
This silences gitleaks for an entire directory. It is risky because `docs/` is a naming convention, not a security boundary. A real credential accidentally placed in `docs/setup.md` will be ignored. Prefer inline allowlists over blanket path exclusions.

---

## Bonus: History Rewrite

### Before
```
04b1bd6 (HEAD -> main) docs: add usage notes
48118a8 feat: empty log
b8d4fc0 feat: add config
6094722 init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```
f001711 (HEAD -> main) docs: add usage notes
ab35880 feat: empty log
0a1e7c0 feat: add config
2baf17b init
```
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite history locally
2. **Rotate (revoke and reissue) the leaked secret** — this is the mandatory second step. History rewrite only removes the token from future clones. Anyone who already cloned the repo may still have it. Until the token is revoked at the issuing service, it remains exploitable.

### Two real-world gotchas

1. **filter-repo refuses to run if the repo is not a fresh clone.** It checks the reflog: if HEAD has more than one entry, it assumes the repo has local history and aborts with "Refusing to destructively overwrite repo history". The fix is to use `--force`, or to work on a fresh `git clone --mirror` copy specifically for rewriting.

2. **All commit SHAs change after the rewrite.** Every commit that touched the affected content gets a new SHA. Open pull requests, CI references, and branch protection rules pointing to old SHAs break. The whole team must discard local branches and re-clone from the rewritten copy.
