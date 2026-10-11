# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /Users/achegaev/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
```
commit 71f4eb16602d1a25e45184c886a74cb2de5b4db0 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for achegaev06@gmail.com with ED25519 key <fingerprint redacted>
Author: Aleksey Chegaev <achegaev06@gmail.com>
Date:   Thu Jun 18 22:30:50 2026 +0300
```

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/wyroxx/DevSecOps-Intro/commit/71f4eb16602d1a25e45184c886a74cb2de5b4db0
- Screenshot of the Verified badge: <image src="/screenshots/verified.png">

### One-paragraph reflection (2-3 sentences)
A forged-author commit could let an attacker push a malicious change while making it look like a trusted teammate approved or wrote it. That creates a Repudiation problem because the real author can deny responsibility and the blamed developer has weak evidence that the commit was forged. The Verified badge makes this attack visible because GitHub can show whether the commit was cryptographically signed by a key attached to the claimed identity.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks-system
        pass_filenames: false

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
        exclude: ^labs/lab6/vulnerable-iac/
      - id: check-added-large-files
```

### `pre-commit install` output
```text
pre-commit installed at .git/hooks/pre-commit
```

### Sanity check
Output of `pre-commit run --all-files`:
```text
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### The blocked commit
Output of the `git commit` that gitleaks blocked:
```text
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /Users/achegaev/DevSecOps-Intro/.cache/pre-commit/patch1781813028-3946.
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks-system
- exit code: 1

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

11:03PM INF 0 commits scanned.
11:03PM INF scanned ~101 bytes (101 bytes) in 15ms
11:03PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
[INFO] Restored changes from /Users/achegaev/DevSecOps-Intro/.cache/pre-commit/patch1781813028-3946.
```

### Tune-out exercise
1. Inline allowlist: a narrow `[allowlist]` rule in `.gitleaks.toml` is OK when the example value is intentionally fake, stable, and documented, such as one exact placeholder token used in a tutorial. I would keep the rule as specific as possible so it does not also allow real secrets that merely look similar.

2. Path exclusion: excluding `docs/` is convenient when documentation contains many known-safe examples, but it is risky because real credentials can be accidentally pasted into the same folder and the scanner will never see them. I would only use a path exclusion for generated or heavily reviewed documentation, and I would prefer inline allowlists for small numbers of examples.

## Bonus: History Rewrite

### Before
```text
71ac075 docs: add usage notes
4569c7a feat: empty log
cb258b7 feat: add config
b6f23f7 init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```text
ca0202b docs: add usage notes
a64328f feat: empty log
22c49d9 feat: add config
b6f23f7 init
```
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. Rotate or revoke the leaked secret. Rewriting history cleans the repository, but the credential must still be treated as compromised because it may already have been copied, logged, or indexed.

### Two real-world gotchas you discovered
1. My global Git config signs every commit, so the sandbox repo initially failed to create commits because the SSH signing key required a passphrase in a non-interactive shell. I fixed this only inside the throwaway bonus repo with `git config commit.gpgsign false`, leaving the course repo signing setup intact.

2. `git filter-repo` refused to rewrite even the local sandbox history because the repository did not look like a fresh clone and HEAD had more than one reflog entry. Since this was an isolated throwaway repo, I reran the command with `--force`; I would not do that casually in a real project repo.
