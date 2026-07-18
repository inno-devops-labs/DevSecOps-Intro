# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `C:/Users/mv103/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:
```
commit c0b77b2a1674194c601d327eb75f162ddfd63d92 (HEAD -> feature/lab3)
Good "git" signature for <n.serov@innopolis.university> with ED25519 key SHA256:a...
Author: SNeka <n.serov@innopolis.university>
Date:   Thu Jun 18 22:39:57 2026 +0300
    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: <https://github.com/SSSNeka/DevSecOps-Intro/commit/c0b77b2a1674194c601d327eb75f162ddfd63d92>
- Screenshot of the Verified badge:![alt text](image.png)

### One-paragraph reflection (STRIDE-R)
Without commit signing, anyone can set `user.name`/`user.email` to a colleague's identity and push commits that appear authored by them — a textbook Repudiation (STRIDE-R) attack. A malicious actor could plant a backdoor or remove a security control and have it attributed to a trusted maintainer, who could then plausibly deny it was their work (or be wrongly blamed), leaving no reliable audit trail. SSH commit signing closes this gap: the Verified badge proves the commit was signed by a key bound to that GitHub account, so a forged-author commit shows up as Unverified and stands out immediately in review and in the commit history.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (full content)
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.0
    hooks:
      - id: gitleaks-system
        pass_filenames: false

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
        exclude: '^labs/lab6/vulnerable-iac/'
      - id: check-added-large-files
        args: ["--maxkb=1024"]
```

> Note: the `gitleaks-system` hook (vs `gitleaks`/golang or `gitleaks-docker`) uses the
> locally installed gitleaks v8.30.0 binary — no Go toolchain or Docker required.
> `pass_filenames: false` is required because the upstream `gitleaks-system` hook omits
> it, which otherwise makes pre-commit pass filenames to `gitleaks git` (it accepts at
> most one positional arg) and the hook errors out.

### `pre-commit install` output
```
pre-commit installed at .git\hooks\pre-commit
```

### The blocked commit
Output of the `git commit` that gitleaks blocked:
```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks-system
- exit code: 1
    gitleaks
Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2
INF 0 commits scanned.
INF scanned ~101 bytes (101 bytes) in 228ms
WRN leaks found: 1
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise
1. **Inline allowlist** — a `[allowlist]` block in `.gitleaks.toml` (e.g., a `regexes` or `stopwords` entry, or a specific `fingerprint`) tells gitleaks to ignore a precise, known value. This is OK when the match is genuinely a non-secret you can pin exactly — a canonical documentation example like `AKIAIOSFODNN7EXAMPLE`, or a specific fingerprint you've reviewed. It's surgical: you whitelist *that* string, not whole files, so a real secret elsewhere still gets caught.
2. **Path exclusion** — `paths: [docs/]` (or `[[allowlist]] paths`) skips scanning entire directories. This is risky because it's a blunt instrument: once `docs/` is excluded, *any* secret that later lands there — a real key pasted into a tutorial, a leaked token in an example — passes silently. Directory-level exclusions tend to rot, since people forget the carve-out exists and start trusting a path the scanner no longer watches.
