
# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `no output`
- `git config --global user.signingkey` → `no output`
- `git config --global commit.gpgsign` → `no output`

### Local verification
Output of `git log --show-signature -1`:

```
commit be4fa4bba05c3d549d449bfebd20d6c8ac15c96d (HEAD -> feature/lab3)
Good "git" signature for dif[redacted]@gmail.com with ED25519 key SHA256:3O[REDACTED]
Author: diffouo44 <dif[redacted]@gmail.com>
Date:   Fri Jun 19 17:56:42 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: [https://github.com/IamdLite/DevSecOps-Intro/commit/cc0de71853e2ac0a9a0ac53e27db6f4290fd5e4f]
- Screenshot of the Verified badge: ["https://github.com/user-attachments/assets/0d7957ad-7320-4874-9253-3ddb39697703]

### One-paragraph reflection (2-3 sentences)
A forged-author commit enables a **repudiation** scenario where a malicious actor injects vulnerable code under a trusted developer's name, allowing the attacker to later deny responsibility while the team wastes time blaming the wrong person. The **Verified badge** (via GPG or SSH signing) makes this attack visible by cryptographically linking the commit to a specific key, so any unsigned or wrongly-signed commit immediately flags that the author claim is untrustworthy—forcing the attacker to either forge the signature (infeasible without the key) or reveal the tampering.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
Paste the full content of your `.pre-commit-config.yaml` here:

```
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0  # Use the latest stable version
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=1000']  # Blocks files larger than 1000 KB

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1  # Check for the latest v8.x release tag (v8.30.1 is recent as of 2026)[citation:2]
    hooks:
      - id: gitleaks
```

### `pre-commit install` output

```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of the `git commit` that gitleaks blocked (paste the failing hook output):

```
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/i/.cache/pre-commit/patch1781882490-22933.
detect private key.......................................................Passed
check for added large files..............................................Passed
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

6:21PM INF 0 commits scanned.
6:21PM INF scanned ~101 bytes (101 bytes) in 75.6ms
6:21PM WRN leaks found: 1

[INFO] Restored changes from /home/i/.cache/pre-commit/patch1781882490-22933.
```

### Tune-out exercise
1. **Inline allowlist** (.gitleaks.toml [allowlist] block) — This approach adds a specific regex or fingerprint to an allowlist section that explicitly permits those exact AKIA* example strings. This is OK when the strings are truly fake (e.g., AKIAIOSFODNN7EXAMPLE) and appear in a controlled, non-production context, because it preserves detection coverage everywhere else in the codebase. However, it becomes risky if the allowlist is too broad (e.g., allowing AKIA as a substring) or if teammates start adding every flagged string to the allowlist out of convenience, gradually blinding the tool to real leaks..
2. **Path exclusion**(paths: ["docs/"] in .gitleaks.toml) — This approach tells Gitleaks to completely skip scanning the docs/ directory. This is risky because documentation files are often copied, pasted, or used as templates by developers—a real credential accidentally pasted into a docs/ example would go undetected, potentially causing a leak. It also creates a false sense of security; the team might assume docs/ is "safe," but future contributors could unknowingly introduce real secrets there, and the exclusion would silently hide them from detection..

---

## Bonus: History Rewrite with `git filter-repo`

### Before
Output of `git log --oneline` before rewrite:

```
392a74c (HEAD -> master) docs: add usage notes
51cf6b0 feat: empty log
c1f4253 feat: add config
1239e20 init
```

Output of `git log -p | grep -c 'ghp_'`: 2

### After
Output of `git log --oneline` after rewrite:

```
7fba89e (HEAD -> master) docs: add usage notes
f4b0341 feat: empty log
1f3eb5e feat: add config
ec9cff8 init
```

Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally.
2. **MANDATORY second step:** Force-push the rewritten history to the remote (git push --force-with-lease) — this ensures the compromised commits are removed from the shared repository, preventing new clones from fetching the leaked secret. The critical nuance from Lecture 3 Slide 12: History rewrite is the cleanup step (removing the secret from Git), but rotation is the actual remediation step—because the secret has already been exposed (especially if it ever hit a public remote).

### Two real-world gotchas you discovered (2 sentences each)
1. filter-repo refused to failed the first time for this reason: "Aborting: refusing to destructively overwrite repo history since this does not look like a fresh clone." — so I had to use a `--force` flag. Also, Git filter-repo deliberately blocks execution on repositories with configured remotes as a safety mechanism to prevent accidental irreversible history rewrites; I had to temporarily remove the remote (git remote remove origin) to proceed, and then re-add it afterward for the force-push.
2. The --replace-text file format is extremely strict — Each line must be pattern==>replacement (with no extra spaces or comments inline), and the replacement text must be exactly the desired new string; if the format is off or the replacement string is empty for the wrong entries, filter-repo either errors out or silently rewrites commits in unexpected ways, requiring careful validation before running the command.


---