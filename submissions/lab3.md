# Lab 3 - Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` -> `ssh`
- `git config --global user.signingkey` -> `/Users/rom.m.ivanov/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` -> `true`

### Local verification
Output of `git log --show-signature -1`:
```
[paste output here - it should include a good SSH signature for your configured email]
```

### GitHub verification
- Direct link to your most recent commit on GitHub: [paste commit URL here]
- Screenshot of the Verified badge: [attach in PR or link here]

### One-paragraph reflection (2-3 sentences)
In a real team, an unsigned or forged-author commit could let someone deny responsibility for a change or impersonate another developer when introducing malicious code. A visible Verified badge does not prove the code is safe, but it makes authorship tampering much easier to detect and strengthens the audit trail for reviews and incident response.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
```yaml
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

11:17PM INF 0 commits scanned.
11:17PM INF scanned ~101 bytes (101 bytes) in 22.4ms
11:17PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise
1. **Inline allowlist** - An inline allowlist in `.gitleaks.toml` is acceptable when a specific example value is known, intentional, and tightly scoped, such as a canonical documentation token that is not real and cannot be abused. The advantage is precision: the rule still protects the rest of the repository without suppressing unrelated findings.
2. **Path exclusion** - Excluding a whole path such as `docs/` is riskier because it creates a blind spot where real secrets can later be committed unnoticed. It may be tempting for noisy documentation folders, but it trades convenience for a broader loss of coverage and should be used very carefully.

## Bonus: History Rewrite

### Before
```
ba9c76e (HEAD -> main) docs: add usage notes
0afb204 feat: empty log
0cde15a feat: add config
8a8d948 init
```
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
```
5d18498 (HEAD -> main) docs: add usage notes
4d0f9ed feat: empty log
0373b55 feat: add config
eb63517 init
```
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` - rewrite locally
2. Rotate or revoke the exposed secret and then force-push the rewritten history to the remote. Rewriting history removes the value from Git, but remediation still requires treating the leaked credential as compromised.

### Two real-world gotchas you discovered (2 sentences each)
1. `git filter-repo` changes commit IDs, so every rewritten commit becomes a different object and any collaborators must resync carefully afterward. In a real shared repository, this makes communication and force-push coordination part of the incident response, not an optional cleanup detail.
2. Removing the secret from current files is not enough if it still exists in older commits. The exercise shows why prevention with hooks matters: once a secret enters history, cleanup is slower, riskier, and easier to get wrong.
