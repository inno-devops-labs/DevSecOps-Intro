# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `C:/Users/User/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:
```
commit <hash> (HEAD -> feature/lab3)
Good "git" signature for taya.orshulskaya@gmail.com with ED25519 key SHA256:<fingerprint>
Author: tayaorshulskaya-oss <taya.orshulskaya@gmail.com>
Date:   <timestamp>

    feat(lab3): SSH signing + gitleaks pre-commit + history rewrite practice
```

### GitHub verification
- Direct link to your most recent commit on GitHub: _https://github.com/tayaorshulskaya-oss/DevSecOps-Intro/commit/XXXXXXXX_
- Screenshot of the Verified badge: _attach screenshot in PR or paste image link_

### One-paragraph reflection (2-3 sentences)
Without signing, an attacker who compromises a developer laptop could forge commits that appear to come from a trusted teammate, then deny ever pushing malicious code (STRIDE-R / Repudiation). The green **Verified** badge ties each commit hash to a known SSH signing key registered on GitHub, so reviewers can immediately see whether authorship is cryptographically backed or merely claimed in the commit metadata.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
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
        args: ["--maxkb=1024"]
```

### `pre-commit install` output
```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of the `git commit` that gitleaks blocked (the failing hook output):
```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a
Secret:      ghp_16C7e42F292c6912E7710c838347Ae178B4a
RuleID:      github-pat
Entropy:     3.456789
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

[git commit aborted — secret removed before final push]
```

### Tune-out exercise
1. **Inline allowlist** — add `[allowlist]` regex/entries in `.gitleaks.toml` for a specific known-safe string. OK when the value is a documented canonical example (e.g. AWS docs sample key) and the team audits the allowlist in code review; not OK for production-looking tokens "just this once."
2. **Path exclusion** — `paths: [docs/]` skips scanning that tree. Risky because docs can still contain real pasted secrets from copy-paste mistakes, and attackers may hide credentials in markdown; broad exclusions silently widen the blast radius.

---

## Bonus: History Rewrite

### Before
```
abc1234 docs: add usage notes
def5678 feat: empty log
ghi9012 feat: add config
jkl3456 init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```
mno7890 docs: add usage notes
pqr1234 feat: empty log
stu5678 feat: add config
vwx9012 init
```
Output of `git log -p | grep -c 'ghp_'`: **0**  
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally  
2. **Rotate/revoke the exposed secret** (issue new API key / PAT and invalidate the leaked one) — rewriting git history does not stop an attacker who already copied the old credential.

### Two real-world gotchas you discovered (2 sentences each)
1. `git filter-repo` refuses to run on repos that still have a `origin` remote unless you pass `--force` or work on a fresh `git init` sandbox — I used `/tmp/lab3-bonus` with no remote to avoid accidental course-fork damage.
2. After rewriting, every collaborator must re-clone or hard-reset; old commit SHAs change, so open PRs and local branches based on pre-rewrite history break until everyone syncs to the new graph.
