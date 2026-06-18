# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/prudens/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
```
commit 773bdad1e322438f3065c2da482f2005606cc860
Good "git" signature for makarus.roru@gmail.com with ED25519 key SHA256:223peJY/…
Author: prudenz1 <makarus.roru@gmail.com>
Date:   Thu Jun 18 22:53:23 2026 +0300

    feat(lab3): SSH signing + gitleaks pre-commit + history rewrite practice
```
(Full `git log --show-signature -1` output verified locally; SHA256 fingerprint truncated here to avoid gitleaks false positive on commit.)

### GitHub verification
- Direct link to signed commit: https://github.com/prudenz1/DevSecOps-Intro/commit/773bdad1e322438f3065c2da482f2005606cc860
- Latest commit on PR (also Verified): https://github.com/prudenz1/DevSecOps-Intro/commit/315a7b7
- Verified badge: **confirmed** — GitHub API returns `verified: true, reason: valid` after uploading the SSH key as a **Signing Key**.

### One-paragraph reflection (2-3 sentences)
In a real team, a forged-author commit (STRIDE-R / Repudiation) lets an attacker push malicious code while framing a colleague — during an incident review, the victim cannot prove they did not author the change, and auditors lose a reliable attribution chain. The green **Verified** badge on GitHub ties each commit to a known SSH signing key registered to a specific account, so an unsigned or wrongly signed commit stands out immediately in the PR timeline and blocks the "it wasn't me" repudiation scenario.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.0
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
Output of the `git commit` that gitleaks blocked (the failing hook output):
```
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

10:52PM INF 0 commits scanned.
10:52PM INF scanned ~101 bytes (101 bytes) in 31.9ms
10:52PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise
1. **Inline allowlist** — add the exact `AKIA*` example string to a `[allowlist]` block in `.gitleaks.toml`. This is OK when the value is a well-known, non-functional placeholder (e.g., AWS documentation examples) and the allowlist entry is as narrow as possible — one literal string, not a regex that could swallow real keys.
2. **Path exclusion** — exclude `docs/` from scanning via `paths` in `.gitleaks.toml`. This is risky because docs directories often accumulate copy-pasted `.env` snippets, CI logs, and screenshots with real tokens; a broad path exclusion creates a blind spot that grows over time as teammates treat `docs/` as a safe place to dump secrets.

---

## Bonus: History Rewrite

### Before
```
f6f431d docs: add usage notes
65b0619 feat: empty log
27ed1b9 feat: add config
28c0281 init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```
4bd63af docs: add usage notes
958a3d5 feat: empty log
641edf3 feat: add config
fe37bf9 init
```
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **Rotate/revoke the exposed secret** — rewriting history removes the leak from git, but anyone who already fetched the old commits (or scraped GitHub before the force-push) may still have the credential; the secret must be invalidated at the provider and all dependent systems updated.

### Two real-world gotchas you discovered (2 sentences each)
1. After `git filter-repo`, every commit hash changed (e.g., `f6f431d` → `4bd63af`), so any open clone or CI cache pinned to the old SHAs breaks until teammates re-clone or reset — history rewrite is not a silent fix.
2. Running `pre-commit run --all-files` on the course repo failed on `detect-private-key` for an existing Ansible file in `labs/lab6/`, even though gitleaks passed — first-run full-repo scans surface legacy issues unrelated to your change, which is why teams often scope hooks to staged files only.
