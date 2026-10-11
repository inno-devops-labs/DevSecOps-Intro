# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/home/gh0st/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:

```text
commit a807e63ae07dbbd0bc6d21a04fb729c39ca065b5
Good "git" signature for artem.mlrrlm.mks@gmail.com
Author: Wilikson173 <artem.mlrrlm.mks@gmail.com>
Date: Fri Jun 19 16:39:28 2026 +0300

    feat(lab3): add pre-commit gitleaks configuration
```

### GitHub verification
- Direct link to my most recent commit on GitHub: `https://github.com/Wilikson173/DevSecOps-Intro/commit/a807e63ae07dbbd0bc6d21a04fb729c39ca065b5`
- Screenshot of the Verified badge: attached in the PR

### One-paragraph reflection
A forged-author commit enables repudiation: someone can introduce a change and later deny having authored or approved it. In a team codebase, that can hide malicious edits, weaken audit trails, and make incident response harder because the commit history no longer clearly shows who actually signed the change. The Verified badge makes that attack visible by showing whether GitHub can cryptographically trust the commit’s signer, not just the text in the author field.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.26.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### `pre-commit install` output
```text
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of the `git commit` that gitleaks blocked:

```text
Detect hardcoded secrets.Failed
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

4:36PM INF 1 commits scanned.
4:36PM INF scanned ~101 bytes (101 bytes) in 22.3ms
4:36PM WRN leaks found: 1

detect private key.Passed
check for added large files.Passed
```

### Tune-out exercise
**1. Inline allowlist** — A `[allowlist]` block in `.gitleaks.toml` is reasonable only when the false positive is tightly scoped, well understood, and reviewed by the team. It is safer for a tiny, explicit exception than for broad patterns, because it keeps the policy close to the detector and documents why the exception exists.

**2. Path exclusion** — `paths: [docs/]` is risky because it can create a blind spot for an entire directory. If someone later places real secrets in that path, the detector will ignore them too, so path exclusions should be used sparingly and only when the directory is truly non-sensitive and controlled.

## Bonus: History Rewrite

### Before
```text
fdc5aba (HEAD -> master) docs: add usage notes
0364a47 feat: empty log
d38fc8e feat: add config
da40e23 init
```

Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```text
4242c03 (HEAD -> master) docs: add usage notes
bd81766 feat: empty log
2778440 feat: add config
4a09a7b init
```

Output of `git log -p | grep -c 'ghp_'`: **0**  
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite history locally.
2. **Rotate/revoke the leaked secret everywhere it could have been used** — replace the credential, invalidate the old one, and confirm it can no longer authenticate.

### Two real-world gotchas I hit
1. `pre-commit run --all-files` failed on an already existing private key in `labs/lab6/vulnerable-iac/ansible/configure.yml`. That showed me the hook checks the whole repository, not only the file I had just changed.
2. Installing `git-filter-repo` with `pip` hit Kali’s externally-managed-environment restriction, so I had to use the already available `git filter-repo` command instead. In the bonus repo, I also needed to run the rewrite with `--force` to complete the history cleanup.

## PR checklist
- [x] Task 1 — SSH signing configured + Verified badge on commit
- [x] Task 2 — .pre-commit-config.yaml + gitleaks demonstrably blocking
- [x] Bonus — filter-repo rewrite practice documented
