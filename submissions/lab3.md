\# Lab 3 — Submission



\## Task 1: SSH Commit Signing



\### Local configuration

\- `git config --global gpg.format` → ssh

\- `git config --global user.signingkey` → /c/Users/golor/.ssh/id\_ed25519.pub

\- `git config --global commit.gpgsign` → true



\### Local verification

Output of `git log --show-signature -1`:

commit 4526760249b0c61fd70cbb8c140d1f7afb9792a3 (HEAD -> feature/lab3)



Good "git" signature for ruslan.glvv@gmail.com with ED25519 key SHA256:FqT0MdfUde5Ga+7PVLiVjZkytqoC6DF5+cROAR7hhRg



Author: ruslan ruslan.glvv@gmail.com



Date:   Fri Jun 19 11:05:54 2026 +0300



test: first signed commit



\### GitHub verification

\- Direct link to your most recent commit on GitHub: https://github.com/ruslanglvv/DevSecOps-Intro/commit/4526760249b0c61fd70cbb8c140d1f7afb9792a3

\- Screenshot of the Verified badge: <вставь сюда свой скриншот>



\### One-paragraph reflection (2-3 sentences)

A forged-author commit lets an attacker plant malicious code (e.g. a backdoor) while making the commit history show a different, innocent developer as the author — since Git's author/committer fields are just plain text and can be set to anything with git config user.name/email. This is a textbook Repudiation scenario: if the backdoor is later discovered, the real attacker can deny involvement, and suspicion falls on whoever's name was forged. The Verified badge closes this gap by binding each commit to a cryptographic signature from a specific person's private SSH key, which is registered to their GitHub account — so an attacker can spoof the author field, but not the signature, making any forged-author commit immediately visible as Unverified.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
        exclude: ^labs/lab6/vulnerable-iac/
      - id: check-added-large-files
```

### `pre-commit install` output
pre-commit installed at .git\hooks\pre-commit

### The blocked commit
Output of the `git commit` that gitleaks blocked (the failing hook output):
Detect hardcoded secrets.................................................Failed

hook id: gitleaks
exit code: 1

Finding:     GH_PAT=REDACTED

Secret:      REDACTED

RuleID:      github-pat

Entropy:     4.143943

File:        submissions/leak-attempt.txt

Line:        2

Fingerprint: submissions/leak-attempt.txt:github-pat:2

11:26AM WRN leaks found: 1


### Tune-out exercise

1. **Inline allowlist** — An allowlist entry in `.gitleaks.toml` matches a specific
   *value* (e.g. exactly `AKIAIOSFODNN7EXAMPLE`). This is safe when the excluded
   string is a canonical, well-known placeholder that can never be a real secret —
   if a teammate later pastes an actual AWS key into the same file, it won't match
   the allowlisted string and will still get caught. The exception is narrow and
   doesn't weaken coverage anywhere else.

2. **Path exclusion** — Excluding `docs/` via `paths:` stops gitleaks from scanning
   that directory at all, regardless of what's in it. This is risky because it's an
   exclusion by *location*, not by *value*: if someone later pastes a real credential
   into `docs/` (e.g. copying a working config "as an example" instead of writing a
   fake one), gitleaks will silently miss it. I saw this firsthand with
   `detect-private-key` and `labs/lab6/vulnerable-iac/` — excluding that whole path
   was reasonable only because the entire directory is intentionally vulnerable
   training material, not real production code. Path exclusions should be scoped as
   narrowly as possible and revisited periodically, since they create a permanent
   blind spot rather than a one-time exception.
