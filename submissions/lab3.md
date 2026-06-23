# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/home/shadex/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:
```bash
commit ea0bfeb5dd4da6c7c775898c55050477d33f89a0 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for namespaces=git with ED25519 key SHA256:REDACTED
Author: Timur Iakovlev <t.iakovlev@innopolis.university>
Date:   Thu Jun 18 10:45:12 2026 +0300

    test: first signed commit
```


### GitHub verification
- Direct link to your most recent commit on GitHub: `https://github.com/AskoRBINKAs/DevSecOps-Intro/commit/ea0bfeb5dd4da6c7c775898c55050477d33f89a0`
- Screenshot of the Verified badge: `https://github.com/AskoRBINKAs/DevSecOps-Intro/pull/3#issuecomment-4739579803`

### One-paragraph reflection (2-3 sentences)
A forged-author commit would let an attacker push malicious or risky code while making it look like a trusted teammate wrote it, creating a repudiation problem because the real teammate could deny making the change and the team would have weak proof of who actually did it. In a real codebase, this could be used to sneak in a backdoor, disable tests, or change security logic while shifting blame to someone else. The GitHub Verified badge makes the attack visible because only commits signed with a trusted key show as verified, so an unsigned or incorrectly signed forged-author commit stands out as not cryptographically tied to the claimed author.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### `pre-commit install` output
```text
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of the git commit that gitleaks blocked (the failing hook output):
```bash
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/shadex/.cache/pre-commit/patch1781769679-155635.
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

11:01AM INF 0 commits scanned.
11:01AM INF scanned ~101 bytes (101 bytes) in 46.4ms
11:01AM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
[INFO] Restored changes from /home/shadex/.cache/pre-commit/patch1781769679-155635.
```

### Tune-out exercise
1. **Inline allowlist** - a targeted `[allowlist]` rule in `.gitleaks.toml` is OK when the example string is intentionally fake, stable, and narrowly scoped to a specific rule or exact value. This keeps scanning active for the rest of the repository and avoids hiding real secrets in nearby files.
2. **Path exclusion** - excluding `docs/` with `paths: [docs/]` is risky because it creates a blind spot where a real credential could be committed without being scanned. I would only use it for a tightly controlled generated-docs path, and even then I would prefer exact allowlisted examples over excluding the whole directory.

## Bonus: History Rewrite

### Before
```text
bf711f4 docs: add usage notes
25d7116 feat: empty log
616f7e3 feat: add config
a8d4c80 init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```text
044aa3b docs: add usage notes
900cf40 feat: empty log
38c68e2 feat: add config
c8384fb init
```
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` - rewrite locally.
2. Rotate and revoke the exposed secret everywhere it was valid, then force-push the rewritten history and coordinate with teammates to reclone or reset. Rewriting removes the secret from Git history, but it does not make a leaked credential safe again.

### Two real-world gotchas you discovered
1. `git filter-repo` was installed as a Python module, but `git filter-repo` was not available as a Git subcommand in this environment. I had to run the same tool as `python -m git_filter_repo --replace-text /tmp/replace.txt`.
2. `filter-repo` refused to rewrite the sandbox history because the repo did not look like a fresh clone: it reported more than one `HEAD` reflog entry. Since this was a throwaway `/tmp/lab3-bonus` repo with no remote, I reran it with `--force`.
