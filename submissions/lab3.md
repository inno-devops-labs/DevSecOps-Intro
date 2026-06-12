# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/Users/jester/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:
```
commit 7e6ea2d008ba7da97d51e7fd8c459e0c4b161d64 (HEAD -> feature/lab3)
Good "git" signature for jester.auer@gmail.com with ED25519 key SHA256:Xc1WRiu4/4y4/EGzmwdvxRaKpDRlagrvuvdnhlg0cEc
Author: jestersw <jester.auer@gmail.com>
Date:   Fri Jun 12 18:37:12 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to commit: https://github.com/jestersw/DevSecOps-Intro/commit/7e6ea2d008ba7da97d51e7fd8c459e0c4b161d64
- The commit "test: first signed commit" shows a green **Verified** badge on the `feature/lab3` commits page.

### One-paragraph reflection
A forged-author commit lets an attacker push code under someone else's name — for example, an attacker who gains write access could commit a backdoor and set the author field to a senior engineer's name and email, making it look like that engineer introduced the vulnerability (Repudiation: the real engineer could later deny it, but so could the actual attacker, and the audit trail can't distinguish them). The green Verified badge makes this attack visible because it cryptographically ties the commit to a specific SSH/GPG key that only the real author possesses — an attacker without that private key can set any author name/email they want, but the commit will show as "Unverified," immediately flagging it as suspicious during code review or an incident investigation.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
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
      - id: check-added-large-files
        args: ["--maxkb=1000"]
```

### `pre-commit install` output
```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

6:43PM INF 0 commits scanned.
6:43PM INF scanned ~101 bytes (101 bytes) in 13.3ms
6:43PM WRN leaks found: 1
```

### Tune-out exercise

1. **Inline allowlist** — Adding a `[[rules.allowlist]]` regex or a global `[allowlist]` block in `.gitleaks.toml` to ignore a specific string pattern (e.g. `AKIAIOSFODNN7EXAMPLE`). This is OK when the "secret" is a well-known, canonical placeholder value that appears in official documentation and can never be a real working credential — the risk of a false negative is essentially zero because the value itself is public and non-functional.

2. **Path exclusion** — Adding `paths: ["docs/"]` (or a `.gitleaksignore` path rule) so gitleaks skips an entire directory. This is risky because it creates a blind spot: anyone (including future contributors who don't know the convention) could accidentally — or maliciously — commit a real secret inside `docs/` and gitleaks would never flag it. A path-level exclusion is much coarser than an inline allowlist, since it doesn't care what the actual content is, only where it lives.

## Bonus: History Rewrite

### Before
```
00b91c0 (HEAD -> main) docs: add usage notes
e0856d5 feat: empty log
0e4200c feat: add config
0d24f9e init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```
19c2855 (HEAD -> main) docs: add usage notes
5086071 feat: empty log
efa4256 feat: add config
3edf777 init
```
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **Rotate the leaked credential** — rewriting history does NOT undo the fact that the secret was already pushed and is potentially cached/cloned/indexed elsewhere (GitHub caches, forks, CI logs, third-party mirrors). The MANDATORY second step is to immediately revoke/rotate the actual credential (API key, token, password) at its source, since the rewrite only cleans your repo's history going forward — it cannot retroactively un-leak a secret that was ever pushed to a remote.

### Two real-world gotchas

1. `git filter-repo` refused to run on the first attempt with: *"Aborting: Refusing to destructively overwrite repo history since this does not look like a fresh clone... expected at most one entry in the reflog for HEAD."* Even on a brand-new local sandbox repo I had just created, making 4 commits in a row was enough to populate the reflog beyond one entry, triggering the safety check. I had to re-run with `--force` to proceed — a reminder that the tool is deliberately paranoid about accidental history destruction, even when there's no remote involved yet.

2. After the rewrite, **all commit hashes downstream of the first changed commit were different** (`0e4200c` → `efa4256`, `e0856d5` → `5086071`, `00b91c0` → `19c2855`) — only the empty `init` commit's content was unaffected, but even its hash changed because it's part of the rewritten chain. In a real scenario with a shared remote, this means every collaborator's local clone now has "diverged" history and would need to hard-reset to the new history after a force-push — a disruptive operation that has to be coordinated with the team, not done silently.