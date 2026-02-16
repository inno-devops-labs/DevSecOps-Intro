# Lab 3 Submission — Secure Git

## Student

- Name: Danil Fishchenko
- Branch: `feature/lab3`

## Task 1 — SSH Commit Signature Verification

### 1.1 Why commit signing matters

Commit signing adds cryptographic proof that:
- the commit was authored by the expected developer identity;
- commit contents were not altered after signing;
- CI/CD and code-review workflows can trust provenance of changes.

For DevSecOps, this reduces supply-chain risks such as forged commits, impersonation, and unauthorized changes entering protected branches.

### 1.2 SSH signing setup

Repository signing configuration:

```bash
git config --get gpg.format
git config --get user.signingkey
git config --get commit.gpgsign
git config --get user.email
```

Output:

```text
ssh
/Users/pepega/.ssh/id_ed25519_github.pub
true
150794989+pepegx@users.noreply.github.com
```

Evidence that recent commits contain SSH signature data:

```bash
git log --oneline -1
for c in $(git log --format=%H -1); do
  echo "commit:$c"
  git cat-file -p "$c" | sed -n '1,12p' | rg '^gpgsig|^author|^committer'
done
```

Output excerpt:

```text
6a72b87 chore: sign with github identity key

commit:6a72b87cc9f8fb45e92701dabc6968f7088f9163
author Danil Fishchenko <150794989+pepegx@users.noreply.github.com> ...
committer Danil Fishchenko <150794989+pepegx@users.noreply.github.com> ...
gpgsig -----BEGIN SSH SIGNATURE-----
```

GitHub verification result for commit `6a72b87`:

```text
verified: true
reason: valid
```

### 1.3 Why commit signing is critical in DevSecOps workflows

Signed commits provide tamper-evident traceability from developer workstation to repository and deployment pipeline. This strengthens auditability, supports non-repudiation, and helps enforce policy controls (for example, “require signed commits” on protected branches).

## Task 2 — Pre-commit Secret Scanning

### 2.1 Hook setup

Created local hook:

```bash
cat > .git/hooks/pre-commit   # with Dockerized TruffleHog + Gitleaks logic
chmod +x .git/hooks/pre-commit
```

Note: the hook was adjusted for macOS Bash 3 compatibility by replacing `mapfile` with a `while read` loop for staged file collection.

### 2.2 Secret detection tests

#### Blocked commit (expected failure)

Staged file with test AWS-like secret pattern and attempted commit. Hook blocked commit:

```text
[pre-commit] Scanning labs/lab3_secret_test.txt with Gitleaks...
Gitleaks found secrets in labs/lab3_secret_test.txt:
RuleID:      aws-access-token
...
[pre-commit] ✖ Secrets found in non-excluded file: labs/lab3_secret_test.txt
...
✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
exit_code=1
```

#### Successful commit after remediation

Removed secret pattern from file, staged again, and committed successfully:

```text
[pre-commit] ✓ No secrets detected in non-excluded files; proceeding with commit.
[feature/lab3 5b1bb7b] test: remove test secret after hook block
1 file changed, 2 insertions(+), 1 deletion(-)
```

### 2.3 How this prevents incidents

Automated pre-commit secret scanning shifts detection left by stopping credential leaks before they enter Git history or remote repositories. This reduces incident response overhead, credential rotation costs, and exposure windows for attackers.
