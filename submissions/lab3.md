# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `~/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:
```
commit 667d59cb9d1455466d29a35dde8481ec3e873a18 (HEAD -> feature/lab3)
Good "git" signature for egor.neyalov@mail.ru with ED25519 key SHA256:VjXsGms5VaarmJ6Mk3UML8JHF/TCOUcF90EFeq9HRyE
Author: Meliman1000-7 <egor.neyalov@mail.ru>
Date:   Fri Jun 12 19:42:50 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to commit: https://github.com/Meliman1000-7/DevSecOps-Intro/commit/667d59cb9d1455466d29a35dde8481ec3e873a18
- Verified badge: ✅ Green **Verified** badge confirmed on GitHub (see screenshot in PR)

### One-paragraph reflection
A forged-author commit — where an attacker sets `git config user.email` to a trusted colleague's address — would allow them to introduce malicious code (a backdoor, a dependency swap, a secrets exfiltration snippet) while attribution points to an innocent team member. In a real codebase this could pass code review because reviewers trust the name they see, and audit logs would blame the wrong person. The green **Verified** badge breaks this attack: because the badge requires the committer to hold the private key registered under that email as a GitHub Signing Key, a forged author address without the matching key produces an **Unverified** commit that stands out immediately in the commit history.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (full content)
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
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
Output of `git commit -m "test: should be blocked by gitleaks"`:
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

8:18PM INF 1 commits scanned.
8:18PM INF scan completed in 7.57ms
8:18PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

Gitleaks fired on the `github-pat` rule, flagged the finding in `submissions/leak-attempt.txt:2`, and aborted the commit with exit code 1. The file was unstaged and deleted after the test — it never entered the repository.

### Tune-out exercise

**1. Inline allowlist — `[allowlist]` block in `.gitleaks.toml`**

This approach adds an exception directly to the gitleaks configuration by specifying a finding fingerprint or a regex pattern to ignore. It is appropriate when the string is a well-known documentation example (e.g. `AKIAIOSFODNN7EXAMPLE` from official AWS docs) whose value is fixed and will never be a real secret. The risk is that developers may abuse the allowlist by adding real secrets under the pretext of "this is just a test value", effectively disabling detection for a live credential.

**2. Path exclusion — `paths: [docs/]` in `.gitleaks.toml`**

This approach excludes an entire directory from scanning. It is convenient when `docs/` contains many key-shaped strings in different formats and maintaining a per-finding allowlist is impractical. The danger is that if a developer accidentally places a real secret in `docs/` (for example, copying a working config as a usage example), gitleaks will silently skip it — meaning the control fails precisely where it is least expected to be bypassed.

---

## Bonus: History Rewrite

### Before
```
2b564af (HEAD -> main) docs: add usage notes
657ee91 feat: empty log
9cd940d feat: add config
b786272 init
```
Output of `git log -p | grep -c 'ghp_AAAA'`: **2**
Output of `git log -p | grep -c 'REDACTED'`: **0**

### After
```
86cc1b3 (HEAD -> main) docs: add usage notes
3398aca feat: empty log
5e6a9b2 feat: add config
ceea4f8 init
```
Output of `git log -p | grep -c 'ghp_AAAA'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite history locally and force-push to all remotes
2. **Secret rotation** — the mandatory second step in a real incident. Rewriting history removes the secret from the repository, but does not revoke it: if the key or token was ever visible, it may have been copied, cached by a CI/CD system, or saved in logs. Until the old secret is invalidated and replaced with a new one, the cleanup is incomplete and the exposure window remains open.

### Two real-world gotchas

1. **`filter-repo` refused to run without `--force`** — the tool checks that the repository is a fresh clone (at most one reflog entry for HEAD) and raises the error `Refusing to destructively overwrite repo history`. In the sandbox this was resolved with the `--force` flag; in a real incident the correct approach is to work on a fresh `git clone` to avoid accidentally losing local changes during the rewrite.

2. **All commit hashes changed after the rewrite** — even the `feat: empty log` commit, which contained no secret, received a new SHA (`657ee91` → `3398aca`). In a real project this means all open PRs, commit links in issues, and references in external systems (Jira, Slack) immediately become invalid, and every team member must run `git fetch --force` and rebase their branches — otherwise their next push could silently restore the old history containing the leaked secret.
