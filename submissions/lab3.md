# Task 1 — Signed Commits

## 1. Git configuration

The following Git configuration was used:

```text
gpg.format = ssh
user.signingkey = ~/.ssh/id_ed25519.pub
commit.gpgsign = true
```

These settings configure Git to use SSH keys for commit signing and automatically sign commits.

## 2. Signature verification

The signature was verified locally using:

```bash
git log --show-signature -1
```

Output:

```text
commit ad1896aa8b6d12c389a118ccd47ea0965b8bb8e6 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for xxlavan@gmail.com with ED25519 key SHA256:<KEY_FINGERPRINT>
Author: sedimentt <xxlavan@gmail.com>
Date:   Thu Sep 17 16:28:00 2026 +0300

    test: first signed commit
```

The `Good "git" signature` message confirms that the commit signature was successfully verified.

## 3. GitHub verification

The signed commit was pushed to GitHub:

**Commit:** `ad1896aa8b6d12c389a118ccd47ea0965b8bb8e6`

**GitHub:** https://github.com/sedimentt/DevSecOps-Intro/commit/ad1896aa8b6d12c389a118ccd47ea0965b8bb8e6

The commit is displayed on GitHub with the **Verified** badge.

## 4. Forged author line and repudiation

Without commit signing, someone could create a commit with a forged author name and email address, making it appear as if the commit was created by another developer. The **Verified** badge provides evidence that the commit was signed with the corresponding signing key, making it possible to verify possession of the key and reducing the ability to repudiate the signed commit.


# Task 2 — Secret Scanning with pre-commit

## 1. `.pre-commit-config.yaml`

The repository uses Gitleaks together with standard pre-commit hooks:

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

The hooks were installed with:

```bash
pre-commit install
```

The configuration was then tested with:

```bash
pre-commit run --all-files
```

Gitleaks passed the existing files. The `detect-private-key` hook detected a private key already present in `labs/lab6/vulnerable-iac/ansible/configure.yml`, while `check-added-large-files` passed.

## 2. Blocked secret commit

A fake GitHub Personal Access Token was placed into a test file:

```bash
printf 'GH_PAT=<REDACTED>\n' > submissions/leak-attempt.txt
git add submissions/leak-attempt.txt
git commit -m "test: should be blocked"
```

The pre-commit hook blocked the commit. Gitleaks identified the secret using the `github-pat` rule:

```text
Detect hardcoded secrets.................................................
Failed
- hook id: gitleaks
- exit code: 1

○     │╲     │ ○     ○ ░     ░    gitleaks

Finding:
    GH_PAT=
    ***REDACTED***

Secret:
    ***REDACTED***

RuleID:
    github-pat

Entropy:
    4.143943

File:
    submissions/leak-attempt.txt

Line:
    1

Fingerprint:
    submissions/leak-attempt.txt:github-pat:1

INF  1 commits scanned.
INF  scan completed in 4.35ms
WRN  leaks found: 1
```

The commit was therefore not created. The previous commit remains the latest commit:

```bash
git log --oneline -1
```

```text
ad1896a test: first signed commit
```

This demonstrates that the pre-commit hook prevented the secret from entering Git history.

## 3. Allowlist entry vs. path exclusion

### `[allowlist]` entry in `.gitleaks.toml`

An `[allowlist]` entry allows specific known-safe strings or patterns to be ignored by Gitleaks while keeping scanning enabled for the rest of the repository. This becomes unsafe if the allowed value is later replaced with a real credential, or if the allowlist pattern is too broad and accidentally hides an actual secret.

### Path exclusion for `docs/`

A path exclusion disables or bypasses secret detection for files under `docs/`, which can be convenient when documentation contains many intentionally fake credential examples. It becomes unsafe when real credentials can be placed in `docs/`, because the scanner will no longer inspect that entire path.


# Bonus — Purge a Secret from Git History

## 1. Git history before and after

A throwaway repository was created in `/tmp/lab3-bonus`. A fake GitHub token was intentionally committed twice: once to `config.txt` and once to `README.md`.

### Before rewriting history

```bash
git log --oneline
```

```text
46fa22a docs: usage notes
912719b feat: empty log
f1cb514 feat: add config
4a5cba1 init
```

The secret was present in Git history:

```bash
git log -p | grep -c 'ghp_AAAA'
```

```text
2
```

The replacement was configured:

```bash
echo '<FAKE_TOKEN>==>[REDACTED]' \
  > /tmp/replace.txt
```

### After rewriting history

The first attempt to run `git filter-repo` was refused. After rerunning it with `--force`, the history was rewritten:

```bash
git filter-repo --replace-text /tmp/replace.txt --force
```

The command processed all four commits and created a new history.

After rewriting:

```bash
git log -p | grep -c 'ghp_AAAA'
```

```text
0
```

The replacement marker appeared twice:

```bash
git log -p | grep -c 'REDACTED'
```

```text
2
```

Therefore, both occurrences of the secret were removed from the visible Git history and replaced with `[REDACTED]`.

## 2. `git filter-repo` refusal

The first attempt:

```bash
git filter-repo --replace-text /tmp/replace.txt
```

returned:

```text
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

The repository was a throwaway sandbox, so the command was rerun with `--force`:

```bash
git filter-repo --replace-text /tmp/replace.txt --force
```

The rewrite completed successfully:

```text
Parsed 4 commits
New history written in 0.01 seconds; now repacking/cleaning...
Repacking your repo and cleaning out old unneeded objects
HEAD is now at f3b31c1 docs: usage notes
```

The lab specifically uses this sandbox scenario to demonstrate the `--force` behavior.

## 3. The step that ends the incident

Rewriting Git history is only the first step. The step that actually ends the incident is **credential rotation or revocation**.

History rewriting removes the secret from the repository's current history, but it does not make a previously exposed credential invalid. Anyone who obtained the credential before the rewrite could still use it, so the credential must be revoked or replaced.

## 4. Two unexpected terminal results

### 1. `git filter-repo` refused to run

The first unexpected result was the safety check:

```text
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
```

I expected `git filter-repo` to immediately rewrite the history, but it detected that the repository did not look like a fresh clone and required `--force`.

### 2. Commit hashes changed after the rewrite

Before rewriting, the latest commit was:

```text
46fa22a docs: usage notes
```

After rewriting, the latest commit became:

```text
f3b31c1 docs: usage notes
```

This happened because rewriting the contents of commits creates a new history, which results in new commit hashes.



## Note

Some values in the command outputs were replaced with placeholders such as `<REDACTED>` and `<KEY_FINGERPRINT>`. This was necessary because Gitleaks scans the report itself and detects secret-like strings from the examples and command outputs. The replacements do not change the meaning of the demonstrated results.
