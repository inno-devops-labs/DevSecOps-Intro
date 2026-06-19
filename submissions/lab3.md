# Lab 3 — Submission

> Note: signing config and all three tasks were executed and verified **locally**. The one
> part that needs your GitHub account — uploading the SSH key as a **Signing Key** and the
> green **Verified** badge — is marked TODO below.

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → **ssh**
- `git config --global user.signingkey` → **C:/Users/user/.ssh/id_ed25519.pub**
- `git config --global commit.gpgsign` → **true**
- `git config --global tag.gpgsign` → **true**
- `git config --global gpg.ssh.allowedSignersFile` → **C:/Users/user/.config/git/allowed_signers**

`allowed_signers` content:
```
a.mikhelson@innopolis.university namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDqY9C8KStvJHzC8fj2eG+0sn+gqpnhQw2JS4jBJv32M a.mikhelson@innopolis.university
```

### Local verification
Output of `git log --show-signature -1` (on a signed test commit):
```
commit 5a2443c26a964c2e24f08227a0bf6b0db72cc759
Good "git" signature for a.mikhelson@innopolis.university with ED25519 key SHA256:qAmJ3kpUCV9WcYg5PdEFfFrrlzE0FCCV6eNjYjGoKwQ
Author: Anastasiia Mikhelson <a.mikhelson@innopolis.university>
Date:   Fri Jun 19 21:55:20 2026 +0500

    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: **<TODO — paste after pushing to your fork>**
- Screenshot of the Verified badge: **<TODO — see instructions below>**

### One-paragraph reflection (STRIDE-R / Repudiation)
Without commit signing, anyone can run `git commit --author="Trusted Dev <dev@team.com>"` and
forge authorship — a **Repudiation** attack. A malicious or compromised contributor could slip a
backdoor into the codebase and have it appear, in `git blame` and the history, to have been
written by a trusted maintainer; that maintainer could equally **deny** ("repudiate") a commit
that really was theirs, since author metadata is just plaintext. SSH commit signing binds each
commit to a cryptographic key the author controls, and GitHub's **Verified** badge makes the
distinction visible at a glance: a forged-author commit shows up **without** the badge (or as
"Unverified"), so reviewers can spot and reject it before it reaches `main`.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```yaml
# Lab 3 — pre-commit configuration
# Blocks secrets and risky files before they ever reach a commit.
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=1024']
```

### `pre-commit install` output
```
pre-commit installed at .git\hooks\pre-commit
```

`pre-commit run --all-files` on clean files:
```
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### The blocked commit
Output of the `git commit` that gitleaks blocked (planted fake GitHub PAT):
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
File:        leak-attempt.txt
Line:        2
Fingerprint: leak-attempt.txt:github-pat:2

INF 0 commits scanned.
INF scanned ~490 bytes (490 bytes) in 98.1ms
WRN leaks found: 1
```
The commit aborted with exit code 1; the secret never entered history.

### Tune-out exercise
1. **Inline allowlist** (`[allowlist]` block with `regexes`/`stopwords` in `.gitleaks.toml`).
   OK when the false positive is a **specific, known, non-sensitive value** — e.g. a single
   documented example token or a fixed test fixture. It's surgical: you allow *that exact
   pattern*, so real secrets elsewhere still trip the scanner. The risk is allowlists drift —
   an over-broad regex can silently whitelist a whole class of real keys.
2. **Path exclusion** (`paths: ['docs/']` in `.gitleaks.toml`). This stops gitleaks scanning a
   whole directory, which is **risky**: it's coarse. If `docs/` later gains a real credential
   (a config snippet someone pastes with a live key), it sails through unscanned. Use it only
   for directories that are guaranteed never to hold real secrets (e.g. generated fixtures),
   and prefer the narrower inline allowlist whenever you can name the exact value.

---

## Bonus: History Rewrite (`git filter-repo`)

### Before
```
e505d49 docs: add usage notes
8814beb feat: empty log
da3c0fb feat: add config
117b59e init
```
Output of `git log -p | grep -c 'ghp_AAAA'`: **2**

### After
```
9be2982 docs: add usage notes
10fb0c2 feat: empty log
e71fa8a feat: add config
378f04c init
```
Output of `git log -p | grep -c 'ghp_AAAA'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

(Note: every commit hash changed — rewriting content rewrites every downstream commit object.)

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally, then **force-push**
   the cleaned history (`git push --force`) and have collaborators re-clone.
2. **ROTATE THE SECRET.** Rewriting history only removes the string from *your* repo. The leaked
   credential must be assumed **already compromised** — cloned forks, CI caches, GitHub's
   dangling-commit views, and anyone who fetched it still have it. The mandatory second step is
   to **revoke/rotate the key** at the provider so the exposed value is worthless. Rewrite =
   cleanup; rotation = remediation.

### Two real-world gotchas discovered
1. **`git filter-repo` refuses to run on a non-fresh clone** ("this does not look like a fresh
   clone") to stop you accidentally destroying a repo with un-pushed work or remotes. In the
   sandbox I had to pass `--force`; in a real incident the safe path is a fresh `git clone`,
   rewrite there, then force-push.
2. **All commit SHAs change after the rewrite** (e.g. `e505d49` → `9be2982`). Any open PRs, tags,
   pinned commit references, submodule pointers, or "deploy this SHA" pipelines that referenced
   the old hashes break — which is exactly why this is a disruptive last resort, not routine.
