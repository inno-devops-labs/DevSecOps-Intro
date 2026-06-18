# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/home/pavel/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:
```
commit 92499f1601e4733d054faacca7834ae1e4370dee
Good "git" signature for alexander@heronwater.com with ED25519 key SHA256:vwqxlQeyMQRmpij9axlAMAhQZB9aoV+I7goi6xeApDs
Author: Temniy Princ <alexander@heronwater.com>
Date:   Thu Jun 18 17:04:36 2026 +0300

    feat(lab3): SSH signing + gitleaks pre-commit + history rewrite practice
```

### GitHub verification
- Direct link to your most recent commit on GitHub: <to be added after push>
- Screenshot of the Verified badge: <to be added after push>

### One-paragraph reflection
A forged-author commit allows an attacker (or a malicious insider) to plant backdoors, sabotage releases, or comply fraud while attributing the change to a trusted colleague — perfect Repudiation under STRIDE-R: the actual actor can deny the action, and the framed developer cannot prove their innocence. Without signing, `git log --author` is trivially spoofable via `git commit --author "trusted@example.com"`. The Verified badge breaks this attack by binding the commit to the SSH private key only the real author possesses: a commit showing "Unverified" next to a trusted name is an immediate red flag that triggers investigation rather than silent acceptance.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (full content)
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.27.2
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
Output of the `git commit` that gitleaks blocked:
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

5:02PM INF 0 commits scanned.
5:02PM INF scanned ~101 bytes (101 bytes) in 23.8ms
5:02PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise

**1. Inline allowlist** — `[allowlist]` block in `.gitleaks.toml`

Example:
```toml
[allowlist]
  regexes = ['''ghp_16C7e42F292c6912E7710c838347Ae178B4a''']  # exact known example value
```
(In practice, write the regex as a fixed-string match so it doesn't accidentally catch real tokens.)

This approach is OK when the pattern is highly specific (a single known example value, not a broad regex), the exemption is peer-reviewed and intentional, and the file lives in the repo itself so it's version-controlled and auditable. If you use a broad regex like `ghp_[A-Za-z0-9]+` you effectively disable the rule for the entire codebase — that's when it becomes dangerous.

**2. Path exclusion** — `paths: [docs/]` in `.gitleaks.toml`

Example:
```toml
[allowlist]
  paths = ['''docs/''']
```

This is risky because it creates a blind spot: once `docs/` is excluded, anyone who wants to sneak a real secret past gitleaks just names the file `docs/my-config.md`. Path exclusions are also fragile — a file move from `src/` into `docs/` silently removes it from scanning. Use only for tightly scoped paths (e.g., `docs/examples/fake-credentials.md`) and add a comment explaining the rationale.

---

## Bonus: History Rewrite

### Before
```
16ddad0 docs: add usage notes
7761171 feat: empty log
6796a92 feat: add config
f3bd98b init
```
Output of `git log -p | grep -c 'ghp_AAAA'`: **2**

### After
```
e5eacd4 docs: add usage notes
b0aee0d feat: empty log
1a0d567 feat: add config
18f8d28 init
```
Output of `git log -p | grep -c 'ghp_AAAA'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **Rotate the secret immediately** — what's the MANDATORY second step in a real incident. Even after a successful `--force` push that overwrites all branches, the token was already exposed: GitHub's API, CDN caches, local clones on every contributor's machine, and any CI log that ever printed it may still hold the live value. Rewriting history removes the evidence but does not invalidate the credential. Rotation (revoking the old token and issuing a new one) is the only action that actually closes the attack window.

### Two real-world gotchas

1. **filter-repo refused to run because the repo was not a fresh clone.** The tool checks reflog depth and aborts with "this does not look like a fresh clone" if there is more than one entry for HEAD. In the sandbox this was hit immediately because commits had been added after `git init`. The fix is `--force`, but in a real incident you should work on a dedicated fresh clone (so your working copy stays clean) and only force-push once the rewrite is verified.

2. **All commit SHAs change after the rewrite, breaking every in-flight PR and CI run.** After `filter-repo` runs, every commit hash is different — the history is literally a new DAG. In a team repo this means every open pull request shows as "nothing to merge" or conflicts, every local clone is now diverged, and CI pipelines referencing old SHAs point to orphaned objects. The standard playbook is: announce the rewrite, ask everyone to re-clone or hard-reset their local branches, and re-open any PRs that were in progress.
