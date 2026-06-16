# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → ~/.ssh/id_ed25519_signing.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
```
commit e2dd7f6abae801f2d03f6ae67d5e966bdfc5295e (HEAD -> feature/lab3)
Good "git" signature for d.malygin@innopolis.university with ED25519 key SHA256:05ds2+R6MJynlpO5lEdWnotFdQEIhMUZdmjvJI5eSRU
Author: Danil Malygin <d.malygin@innopolis.university>
Date:   Tue Jun 16 23:55:22 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/chebudelphin/DevSecOps-Intro/commit/e2dd7f6abae801f2d03f6ae67d5e966bdfc5295e
- Screenshot of the Verified badge: ![Verified Badge](verified.png)

### One-paragraph reflection (2-3 sentences)
A forged-author commit allows an attacker to inject malicious code into a codebase while masquerading as a trusted developer, completely bypassing accountability (STRIDE-R: Repudiation). When analyzing an incident queue, distinguishing legitimate developer actions from an attacker's payload is critical. The Verified badge cryptographically guarantees the author's identity; if an attacker simply spoofs an email in their git config, the resulting commit will lack the Verified badge, instantly flagging the anomaly during an investigation.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```yaml
repos:
  - repo: [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
    rev: v8.21.2
    hooks:
      - id: gitleaks
  - repo: [https://github.com/pre-commit/pre-commit-hooks](https://github.com/pre-commit/pre-commit-hooks)
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
Output of the `git commit` that gitleaks blocked (the failing hook output):
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

12:16AM INF 1 commits scanned.
12:16AM INF scan completed in 3.24ms
12:16AM WRN leaks found: 1

```

### Tune-out exercise
Suppose a teammate insists they need to commit `AKIA*` strings because they're documentation examples in `docs/`. Briefly describe two approaches:
1. **Inline allowlist** — This approach is acceptable when dealing with explicitly known, safe placeholder values (like a standard `AKIAIOSFODNN7EXAMPLE` used in public AWS documentation). It provides surgical precision by ignoring only the specific fake string, ensuring that actual secrets are still caught even if they appear in the same file.
2. **Path exclusion** — Excluding entire directories like `docs/` is highly risky because it creates a total blind spot for the scanner. If a developer accidentally leaves a real, active production token inside a tutorial or markdown guide within that folder, the scanner will completely ignore it, leading to a silent leak.

## Bonus: History Rewrite

### Before
```
d3ce215 (HEAD -> master) docs: add usage notes
3c8b00d feat: empty log
d410638 feat: add config
6533e01 init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```
01e4e6d (HEAD -> master) docs: add usage notes
f9f0f3d feat: empty log
97fc7d8 feat: add config
e5a4e5a init
```
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **Rotate the secret (revoke and regenerate)** — Rewriting history is only cleanup; rotation is the actual remediation because any secret pushed to a remote server must be considered irreversibly compromised.

### Two real-world gotchas you discovered (2 sentences each)
1. The tool has a built-in safety mechanism and refuses to overwrite history if it detects local reflogs (it expects a fresh clone). I had to explicitly use the `--force` flag to make it run.
2. Rewriting history completely changes the commit SHA hashes. In a real shared repository, force-pushing this new history would break the local branches of all other developers on the team, requiring them to perform hard resets.
