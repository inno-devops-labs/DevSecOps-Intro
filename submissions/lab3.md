# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration

- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/Users/msumakov366gmail.com/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification

```text
Good "git" signature for msumakov366@gmail.com (key fingerprint omitted)
```

### GitHub verification

- Verified commit: https://github.com/0xsmk/DevSecOps-Intro/commit/a938eeccf0e8efbf0afda7d48e54e6f5bb36d200

### Reflection

A forged-author commit could make malicious code appear to have been approved or written by a trusted teammate, allowing the attacker to deny responsibility while shifting blame. The Verified badge cryptographically connects the commit to a registered signing key, making an unsigned or incorrectly signed impersonation visible during review.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`

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
        exclude: ^labs/lab6/vulnerable-iac/ansible/configure\.yml$
      - id: check-added-large-files
```

### Installation

```text
pre-commit installed at .git/hooks/pre-commit
```

### Blocked commit

```text
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

8:03PM INF 0 commits scanned.
8:03PM INF scanned ~83 bytes (83 bytes) in 28.7ms
8:03PM WRN leaks found: 1
```

### Tune-out exercise

An inline allowlist in `.gitleaks.toml` is appropriate for a narrowly identified and verified fake example whose exact value or rule can be excluded. The exception should remain specific and documented so that similar real credentials are still detected.

A path exclusion such as `docs/` can be convenient when an entire generated documentation tree contains many false positives. It is risky because a real credential placed anywhere under that path will also avoid scanning, creating a broad blind spot.

## Bonus: History Rewrite

### Before

```text
249d264 docs: add usage notes
67bede0 feat: empty log
d08a259 feat: add config
fe25519 init
```

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

```text
db27279 docs: add usage notes
5527da2 feat: empty log
cdbf9c6 feat: add config
4d69f10 init
```

Output of `git log -p | grep -c 'ghp_'`: **0**

Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life

1. Run `git filter-repo --replace-text replacements.txt` and force-push the rewritten history.
2. Immediately revoke or rotate the exposed credential because rewriting history does not invalidate copies already fetched, cached, or logged elsewhere.

### Two real-world gotchas

1. `git filter-repo` refused to rewrite the locally created repository because it was not considered a fresh clone. Since this was a disposable sandbox, I had to explicitly use `--force`.
2. Every rewritten commit received a new hash, including commits whose visible files were not directly edited. Existing links and references to the old commit IDs therefore became obsolete.
