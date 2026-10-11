# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration

- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/Users/esqavator/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification

Output of `git log --show-signature -1`:

```text
commit 2130532840faeb3a2911b027b0d7f55453ca318b
Good "git" signature for s.shakirov@innopolis.university with ED25519 key SHA256:+INv6sPP5W9M9LsogcgkH5GTe2l9jbvCbg1vU1NTIKo
Author: Esqavator <s.shakirov@innopolis.university>
Date:   Fri Jun 19 13:20:35 2026 +0300

    test: first signed commit
```

### GitHub verification

- Direct link to the signed commit on GitHub: https://github.com/Esqavator/DevSecOps-Intro/commit/2130532840faeb3a2911b027b0d7f55453ca318b
- Verified badge evidence: the commit above shows a green `Verified` badge on GitHub.

### STRIDE-R reflection

A forged-author commit would allow an attacker to make malicious code look like it was written by a trusted teammate. This creates a Repudiation problem because the real author could deny the commit and the team would have weak evidence about who actually approved or introduced the change. SSH signing and the GitHub Verified badge make this attack visible because unsigned or incorrectly signed commits will not show the same verified identity signal.

---

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
        args: ['--maxkb=500']
```

### pre-commit install output

```text
pre-commit installed at .git/hooks/pre-commit
```

### Sanity check

I ran `pre-commit run --all-files`. The first run failed because `detect-private-key` found an existing training fixture in `labs/lab6/vulnerable-iac/ansible/configure.yml`. I added a narrow exclude only for that known lab fixture, and the next run passed all hooks:

```text
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### The blocked commit

Output of the git commit that gitleaks blocked:

```text
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     GH_PAT=[1;3;mREDACTED[0m
Secret:      [1;3;mREDACTED[0m
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

[90m1:51PM[0m [32mINF[0m [1m0 commits scanned.[0m
[90m1:51PM[0m [32mINF[0m [1mscanned ~101 bytes (101 bytes) in 21.5ms[0m
[90m1:51PM[0m [33mWRN[0m [1mleaks found: 1[0m

detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise

#### 1. Inline allowlist

An inline allowlist in `.gitleaks.toml` is acceptable when the example secret is intentionally fake, narrowly scoped, and stable. This is safer when only a specific known test value should be ignored, because the scanner can still detect real secrets in the same directory or file.

#### 2. Path exclusion

A path exclusion such as excluding `docs/` is risky because real secrets often appear in documentation, examples, screenshots, and onboarding guides. It may be useful for a tightly controlled generated documentation folder, but it should be avoided for broad source-controlled documentation unless there is another compensating scanning process.

---

## Bonus: History Rewrite

### `git log --oneline` before rewrite

~~~text
aa97f61 docs: add usage notes
ecc9ea7 feat: empty log
7e0d1ff feat: add config
292841d init
~~~

### `git log --oneline` after rewrite

~~~text
c256208 docs: add usage notes
5cd6b7d feat: empty log
83f82c3 feat: add config
2f16acc init
~~~

### Before

Output of `git log -p | grep -c 'ghp_AAAA'`: **2**

### After

Output of `git log -p | grep -c 'ghp_AAAA'`: **0**

Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life

1. `git filter-repo --replace-text replacements.txt` — rewrite the repository history locally.
2. **Rotate the exposed secret immediately** — rewriting history removes the secret from the repository, but it does not make the leaked credential safe again. In a real incident, the key/token/password must be revoked and replaced.

### Two real-world gotchas discovered

1. My first local signature verification was not clean because my `allowed_signers` file contained invalid lines and my Git identity was set to `obsessed <abc>`. I fixed it by recreating `~/.config/git/allowed_signers`, setting my real Git identity, and amending the first commit with `git commit --amend --reset-author --no-edit`.

2. `pre-commit run --all-files` initially failed on an existing training file from a later lab: `labs/lab6/vulnerable-iac/ansible/configure.yml`. I did not modify that lab file; instead, I added a narrow `exclude` only for that known fixture so `detect-private-key` still protects the rest of the repository.

3. `git filter-repo` refused to run at first because the sandbox repository did not look like a fresh clone and had more than one reflog entry for `HEAD`. Since this was a throwaway repo in `/tmp/lab3-bonus`, I reran the rewrite with `--force`, after which the secret count changed from 2 to 0 and the `[REDACTED]` marker count became 2.
