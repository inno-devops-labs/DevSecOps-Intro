# Lab 3 Submission — Secure Git

## Task 1

### SSH commit signing

Git was configured to use SSH signing with the new key and the requested account:

```text
$ git config --global --get gpg.format
ssh

$ git config --global --get user.signingkey
/Users/pavel/.ssh/github_shnupel_signing.pub

$ git config --global --get commit.gpgsign
true
```

The signed commit verification output was:

```text
commit 41767f42104f679faa72634884935bc127d1130b
Good "git" signature for ufamail.com2@gmail.com with ED25519 key SHA256:<redacted fingerprint>
Author: shnupel <ufamail.com2@gmail.com>

    feat(lab3): signed commits and gitleaks pre-commit hook
```

Without a signature, another person can use my name and email in Git and create a commit that looks like it was written by me. SSH signing gives GitHub cryptographic evidence that the commit was created with my signing key, so GitHub can show the **Verified** badge. This helps to investigate repudiation, although it does not prove that the code itself is safe.

Commit link: https://github.com/Shnupel/DevSecOps-Intro/commit/41767f42104f679faa72634884935bc127d1130b

## Task 2

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

The exclusion is only for the intentional fake private-key fixture in Lab 6. The other files are still checked by `detect-private-key`.

The full scan passed:

```text
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Blocked secret commit

The fake GitHub token was added to `submissions/leak-attempt.txt`. The commit was rejected with exit status `1`:

```text
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
File:        submissions/leak-attempt.txt
Line:        1

--- commit exit status ---
1
--- last commit ---
f667747 Merge pull request #2 from Shnupel/lab2
```

The last commit did not change, which proves that the commit containing the secret was blocked. The test file was then removed.

An `[allowlist]` entry in `.gitleaks.toml` is appropriate for a specific value that is confirmed to be fake. It becomes unsafe when the value becomes real or when the matching rule is too broad and hides real credentials.

A path exclusion for `docs/` disables scanning for the whole directory. It is unsafe when documentation can contain copied configuration or real credentials, because gitleaks will not detect them. A narrow allowlist is safer than excluding a whole directory.

## Bonus

### History before rewriting

The sandbox repository history before rewriting was:

```text
e67e2d3 docs: usage notes
3e5b01d feat: empty log
4759713 feat: add config
10f7b7e init
```

The fake token appeared two times:

```text
$ git log -p | grep -c 'ghp_AAAA'
2
```

### `git filter-repo`

The first command was refused:

```text
$ git filter-repo --replace-text /tmp/replace.txt
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

Because this was a throwaway repository, I followed the instruction and ran:

```text
git filter-repo --force --replace-text /tmp/replace.txt
```

The history after rewriting was:

```text
85ab8d0 docs: usage notes
5170acb feat: empty log
b830031 feat: add config
7a9ef59 init
```

The final counts were:

```text
$ git log -p | grep -c 'ghp_AAAA'
0

$ git log -p | grep -c 'REDACTED'
2
```

Rewriting history is not enough to end the incident. The leaked credential must also be revoked or rotated, because it may already exist in clones, forks, backups, or other copies.

Two surprises were that `git filter-repo` refused the first run even in a newly initialized sandbox, because it checks reflog entries, and that gitleaks redacted the detected secret in its output instead of printing the full value.
