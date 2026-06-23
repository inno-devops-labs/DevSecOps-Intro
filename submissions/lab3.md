# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/Users/georgijbelyaev/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:
```
commit bf053718f160117fc8c148c3d32536523a67bee9
Good "git" signature for 123897400+JoraXD@users.noreply.github.com with ED25519 key SHA256:b7zWJ7e+cwXoPhKCXS3Xq5ztzQ0DZVsFUERt9/wcPHg
Author: Georgii Beliaev <123897400+JoraXD@users.noreply.github.com>
Date:   Thu Jun 18 13:01:20 2026 +0300

    feat(lab3): SSH signing + gitleaks pre-commit + history rewrite
```

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/JoraXD/DevSecOps-Intro/commit/bf053718f160117fc8c148c3d32536523a67bee9
- Verified: badge shows green "Verified" (API confirmed: `verified: true, reason: valid`)

### STRIDE-R reflection
A forged-author commit in a real team's codebase enables a Repudiation attack: a malicious insider could push harmful code (a backdoor, a deleted access control, a misconfigured secret) under a colleague's name, then deny any involvement when the change is discovered during an incident review. The Verified badge breaks this attack because it ties the commit cryptographically to the committer's private key — without the key, the commit cannot be signed, so GitHub marks it Unverified and the forgery is immediately visible to any reviewer looking at the commit list.

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
        args: ["--maxkb=500"]
```

### `pre-commit install` output
```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of `gitleaks protect --staged --verbose` when `submissions/leak-attempt.txt` containing `GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a` was staged:
```
Finding:     GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a
Secret:      ghp_16C7e42F292c6912E7710c838347Ae178B4a
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

INF 0 commits scanned.
INF scanned ~101 bytes (101 bytes) in 27.8ms
WRN leaks found: 1
```
gitleaks detected rule `github-pat` and the commit was aborted. The file was then unstaged and deleted.

### Tune-out exercise

1. **Inline allowlist** (`[allowlist]` block in `.gitleaks.toml`) — You annotate a specific match pattern or commit SHA to be ignored. This is appropriate when a single known false-positive string (e.g., a canonical test value that looks like a PAT) appears in exactly one controlled location — the allowlist entry is narrow, reviewable, and tracked in version control alongside the rule it overrides. It becomes risky when teams start adding broad regex allowlists without expiry dates, effectively whitelisting entire secret formats.

2. **Path exclusion** (`paths: [docs/]` in `.gitleaks.toml`) — You tell gitleaks to skip all files under a given directory. This is convenient when an entire subtree is guaranteed to contain only documentation examples, but it is risky because it creates a blind spot: any real secret accidentally dropped into `docs/` (e.g., a `.env.example` with a real key, or a tutorial pasted from a real project) will silently pass the scan. Inline allowlists on specific strings are safer than blanket path exclusions.

---

## Bonus: History Rewrite

### Before
```
c1b8100 docs: add usage notes
9f94cd2 feat: empty log
44b2c51 feat: add config
28951ab init
```
Output of `git log -p | grep -c 'ghp_AAAA'`: **2**

### After (`git filter-repo --replace-text /tmp/replace.txt --force`)
```
6ee3472 docs: add usage notes
a420ba9 feat: empty log
0f31369 feat: add config
4966884 init
```
Output of `git log -p | grep -c 'ghp_AAAA'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally and force-push to all branches and forks
2. **Rotate the secret immediately** — rewriting history removes the string from future clones but anyone who already cloned the repo (or GitHub's own cache) may still have the token. The MANDATORY second step is to revoke and regenerate the exposed credential in the issuing system (GitHub, AWS IAM, etc.) so the leaked value is worthless even if someone has it.

### Two real-world gotchas
1. `git filter-repo` refused to run with the error "this does not look like a fresh clone" because the sandbox repo had been initialized locally rather than cloned — it checks the reflog and expects at most one HEAD entry. The fix was to pass `--force`, but in a real incident the safer approach is to work on a fresh clone so filter-repo can run without flags that bypass its safety checks.
2. The commit hashes changed completely after the rewrite (e.g., `44b2c51` became `0f31369`) — this means any open PRs, tags, or external references pointing to the old SHAs become dangling. In a shared repo this requires notifying all collaborators to re-clone, and any branch protection rules or CI pipelines referencing old SHAs must be updated.
