# Lab 3 — Secure Git

## Task 1 — SSH Commit Signing

### Git configuration

The following Git configuration was used:

```text
gpg.format=ssh
user.signingkey=~/.ssh/id_ed25519.pub
commit.gpgsign=true
```

The SSH public key was registered in GitHub as a **Signing Key**.

### Local signature verification

The commit was verified locally using:

```text
git log --show-signature -1
```

Output:

```text
commit 6dcce2d049fe27cbfad38bbb067df63f0b1087ad (HEAD -> feature/lab3)
Good "git" signature for kirillmao27@icloud.com with ED25519 key SHA256:<key fingerprint>Author: mao72 <kirillmao27@icloud.com>
Date:   Mon Sep 21 10:22:59 2026 +0300

    test: first signed commit
```

### GitHub verification

The commit was signed using the SSH signing key registered in GitHub.

GitHub commit link: **to be added after pushing the branch**

### Why signing is important

The author name and email in a Git commit can be forged because they are part of the commit metadata. SSH commit signing provides cryptographic proof that the commit was signed by the holder of the corresponding private key. GitHub can verify the signature using the registered public signing key and display a **Verified** badge, making the origin of the commit easier to authenticate.

---

## Task 2 — Pre-commit and Gitleaks

### `.pre-commit-config.yaml`

The repository uses Gitleaks together with additional security-oriented pre-commit hooks:

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
      - id: check-added-large-files
```

The hooks were installed using:

```text
pre-commit install
```

The configured checks include:

* `gitleaks` — detects hardcoded secrets;
* `detect-private-key` — detects accidentally committed private keys;
* `check-added-large-files` — prevents accidentally committing large files.

### Gitleaks secret detection test

A fake GitHub Personal Access Token was added to:

```text
submissions/leak-attempt.txt
```

The attempted commit was:

```text
git commit -m "test: should be blocked"
```

The pre-commit hook blocked the commit. Gitleaks reported:

```text
Detect hardcoded secrets.................................................Failed

Finding:     ﻿GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

10:29AM INF 0 commits scanned.
10:29AM INF scanned ~51 bytes (51 bytes) in 51.9ms
10:29AM WRN leaks found: 1
```

The important part is the detected rule:

```text
RuleID: github-pat
```

This demonstrates that Gitleaks correctly identifies a GitHub Personal Access Token and prevents the commit from being created.

### Proof that the commit was blocked

After the failed commit attempt:

```text
git log --oneline -1
```

returned:

```text
6dcce2d (HEAD -> feature/lab3) test: first signed commit
```

The `"test: should be blocked"` commit was therefore not added to the repository history.

### `.gitleaks.toml` allowlist vs path exclusion

A Gitleaks `[allowlist]` is appropriate when a particular detected value is intentionally safe and should not be treated as a secret, for example a documented fake credential used in tests. However, an allowlist can become unsafe if real credentials are accidentally added and match the allowed pattern or value.

A path exclusion is different because it ignores an entire file or directory. It can be useful for intentionally vulnerable examples, generated files, or documentation containing known test data, but it becomes unsafe if the excluded path is also used for real application code or real credentials because secrets inside that path will no longer be detected.

