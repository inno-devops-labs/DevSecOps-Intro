# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` -> ssh
- `git config --global user.signingkey` -> C:\Users\kamh1\.ssh\id_ed25519.pub
- `git config --global commit.gpgsign` -> true

### Local verification
Output of `git log --show-signature -1`:

    Good "git" signature for kam.h116@mail.ru with ED25519 key SHA256:ugfsT50oXshPRR780RTl+hPWtsoXSebjxm/ZkGRqIYo
    Author: Basinkse21 <kam.h116@mail.ru>
    test: first signed commit

### GitHub verification
- Direct link to the commit: https://github.com/Basinkse21/DevSecOps-Intro/commit/e6b68f1
- Screenshot of the Verified badge: attached in the PR.

### Reflection (STRIDE-R)
Without commit signing, anyone can set `user.name` and `user.email` to a colleague's identity and push commits that appear to be authored by them — a Repudiation (STRIDE-R) problem, since the real author can deny their work and a malicious one can frame someone else (e.g. slipping a backdoor in under a senior engineer's name). The Verified badge makes this visible because it only appears when the commit carries a cryptographic signature tied to a key the claimed author registered with GitHub; an impersonated commit simply shows no Verified badge, so reviewers can spot it.

## Task 2: Pre-commit + gitleaks

### .pre-commit-config.yaml
    repos:
      - repo: https://github.com/gitleaks/gitleaks
        rev: v8.21.2
        hooks:
          - id: gitleaks
      - repo: https://github.com/pre-commit/pre-commit-hooks
        rev: v5.0.0
        hooks:
          - id: detect-private-key
          - id: check-added-large-files

### pre-commit install output
    pre-commit installed at .git\hooks\pre-commit

### The blocked commit
The commit `test: should be blocked by gitleaks` was aborted by the gitleaks hook:

    Detect hardcoded secrets.................................................Failed
    - hook id: gitleaks
    - exit code: 1
    Finding:     GH_PAT=REDACTED
    Secret:      REDACTED
    RuleID:      github-pat
    File:        submissions/leak-attempt.txt
    Line:        1
    leaks found: 1

(Note: a first `pre-commit run --all-files` also flagged a planted private key in
`labs/lab6/vulnerable-iac/ansible/configure.yml` via the `detect-private-key` hook —
course plumbing for a later lab, which confirms that hook works too.)

### Tune-out exercise
1. **Inline allowlist** (`[allowlist]` block in `.gitleaks.toml`): This is acceptable when the flagged string is genuinely a non-secret — e.g. a well-known documentation example or a test fixture — and you allowlist that *specific* value (or a tight regex). It keeps the scan strict everywhere else while silencing one known false positive. It is OK precisely because it is narrow and reviewable.
2. **Path exclusion** (`paths: [docs/]` in `.gitleaks.toml`): This is risky because it turns off scanning for an *entire directory*. A real secret committed under `docs/` later would sail through undetected. Excluding a path trades safety for convenience over a broad area, so it should be a last resort and kept as small as possible.

## Bonus: History Rewrite

### Before
    21ac8e6 docs: add usage notes
    bf9b4ff feat: empty log
    1f5f5cf feat: add config
    8fb4464 init

`git log -p | Select-String "ghp_AAAA"` count: **2**

### After
    d5d6038 docs: add usage notes
    a4fcaf6 feat: empty log
    245b8e3 feat: add config
    e4b0bce init

`git log -p | Select-String "ghp_AAAA"` count: **0**
`git log -p | Select-String "REDACTED"` count: **2**

(Note: every commit hash changed after the rewrite — filter-repo recreated the
entire history, so the commits that contained the secret no longer exist.)

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite history locally and force-push to purge the secret from the remote.
2. **Rotate the secret.** Rewriting history only removes the secret from the repo's record — but by then it has already been exposed (cloned, cached, possibly read). The mandatory second step is to revoke the leaked credential and issue a new one. Cleanup hides the secret; rotation is what actually removes the risk.

### Two real-world gotchas
1. `git filter-repo` refused to run with "this does not look like a fresh clone" and aborted. It is destructive by design and won't touch a repo it isn't sure about; I had to re-run with `--force` (safe here because it's a throwaway sandbox, but a real incident should run on a fresh clone).
2. On Windows there is no `grep`, so the lab's `git log -p | grep -c` had to be replaced with `git log -p | Select-String ... | Measure-Object -Line`. The verification idea is the same, but the exact command from the lab (written for Linux) does not run as-is in PowerShell.