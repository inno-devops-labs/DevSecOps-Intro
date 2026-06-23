# Lab 3 - Submission

## Task 1: SSH Commit Signing

### Local configuration

- `git config --global gpg.format` -> `ssh`
- `git config --global user.signingkey` -> `/home/bimbiriim/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` -> `true`
- `git config --global gpg.ssh.allowedSignersFile` -> `/home/bimbiriim/.config/git/allowed_signers`

### Local verification

The Lab 3 commit was created with SSH signing enabled. Local verification command:

```bash
git log --show-signature -1
```

```text
commit fe867dd86f46f57dbda991a8c88d8989d0d55c4e
Good "git" signature for is.gainullin@innopolis.university with ED25519 key SHA256:/4A7JBbJxjw9fFpAfe//7GEGCMUQu+sR1Mm2m2hTG90
Author:     bimbiriim <is.gainullin@innopolis.university>
AuthorDate: Fri Jun 19 12:58:25 2026 +0300
Commit:     bimbiriim <is.gainullin@innopolis.university>
CommitDate: Fri Jun 19 12:58:25 2026 +0300

    feat(lab3): configure secure git hooks and submission
```

### GitHub verification

- Branch prepared for PR: `feature/lab3`
- Direct signed commit link after push: `https://github.com/Walkerino/DevSecOps-Intro/commit/fe867dd86f46f57dbda991a8c88d8989d0d55c4e`
- GitHub "Verified" badge prerequisite: the public key from `/home/bimbiriim/.ssh/id_ed25519.pub` must be added in GitHub as an SSH **Signing Key**, not only as an authentication key.

### Reflection

A forged-author commit can let an attacker hide malicious code behind a trusted teammate's identity, creating a Repudiation problem when the team later tries to determine who approved or introduced the change. The GitHub Verified badge makes this attack visible because it ties the commit content to a private key controlled by the real author; an unsigned or unverified commit becomes suspicious during review.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`

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
        exclude: ^labs/lab6/vulnerable-iac/ansible/configure\.yml$
      - id: check-added-large-files
```

### `pre-commit install` output

```text
pre-commit installed at .git/hooks/pre-commit
```

### Sanity check

```text
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

`detect-private-key` initially found the intentionally vulnerable training fixture in `labs/lab6/vulnerable-iac/ansible/configure.yml`, so I excluded only that shipped lab fixture from the hook. The exclusion is narrow and does not disable private-key detection for new submission files.

### The blocked commit

Command:

```bash
git commit -m "test: should be blocked by gitleaks"
```

Output:

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

INF 0 commits scanned.
INF scanned ~101 bytes (101 bytes) in 56.1ms
WRN leaks found: 1
```

After the blocked commit, I ran:

```bash
git restore --staged submissions/leak-attempt.txt
rm submissions/leak-attempt.txt /tmp/leak-test.txt
```

### Tune-out exercise

An inline allowlist in `.gitleaks.toml` is acceptable when the example value is intentionally fake, narrowly scoped, and reviewed like code. It is safer when it matches an exact test string or rule/path combination rather than a broad pattern.

A path exclusion such as `paths: [docs/]` is risky because real secrets often leak through documentation, examples, screenshots, and runbooks. I would only use it for generated or vendored documentation that is scanned elsewhere, and I would prefer a narrow rule-specific allowlist over excluding an entire directory.

## Bonus: History Rewrite

### Before

```text
af94d67 docs: add usage notes
173fd90 feat: empty log
dbcf38d feat: add config
66fa465 init
```

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

```text
25ba390 docs: add usage notes
1c754ac feat: empty log
971487a feat: add config
7930433 init
```

Output of `git log -p | grep -c 'ghp_'`: **0**

Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life

1. `git filter-repo --replace-text replacements.txt` - rewrite locally.
2. Rotate and revoke the leaked credential everywhere it may have been accepted. Rewriting history removes future exposure, but it does not make a leaked secret safe again.

### Two real-world gotchas

1. `git filter-repo` refused to run in the sandbox after several local commits because the repository did not look like a fresh clone: `expected at most one entry in the reflog for HEAD`. For this throwaway lab repo I used `--force`; in a real repo I would work from a fresh mirror/clone and coordinate the force-push.

2. Rewriting changed every commit hash, even commits that did not directly add the secret. That means collaborators must rebase or reclone after the force-push, and any open PRs or branch protections need coordinated handling.

## Submission Checklist

- [x] Task 1 - SSH signing configured locally
- [x] Task 2 - `.pre-commit-config.yaml` + gitleaks blocked a fake secret
- [x] Bonus - filter-repo rewrite practice documented
