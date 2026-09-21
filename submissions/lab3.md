# Lab 3 — Secure Git: Signed Commits, Secret Scanning, and History Hygiene

## Task 1

### Signing configuration

```console
$ git config --get gpg.format
ssh
$ git config --get user.signingkey
~/.ssh/inno-devops-signing.pub
$ git config --get commit.gpgsign
true
```

The signing key's public half is also registered in
`~/.ssh/allowed_signers` for the `git` namespace, under the same email used
by the commits.

### Signed-commit proof

```console
$ git log --show-signature -1 --format=fuller
commit 1df48472e5711ca6561d9ff8f2a82c7a57e3511c
Good "git" signature for a.shiian@innopolis.university with ED25519 key SHA256:[public fingerprint redacted]
Author:     whynotgm <a.shiian@innopolis.university>
AuthorDate: Mon Sep 21 11:10:15 2026 +0300
Commit:     whynotgm <a.shiian@innopolis.university>
CommitDate: Mon Sep 21 11:10:15 2026 +0300

    test: first signed commit
```

GitHub commit: [1df4847 — test: first signed commit](https://github.com/whynotgm/DevSecOps-Intro/commit/1df48472e5711ca6561d9ff8f2a82c7a57e3511c)

Without signing, someone able to push to this repository could set the author name and email to
mine and make a malicious change appear to be my work, leaving me able to repudiate the commit
later. GitHub's Verified badge binds the commit contents to a signing key registered to my
account, so reviewers have evidence that the holder of that key approved that exact commit.

## Task 2

### Pre-commit configuration

`.pre-commit-config.yaml`:

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
        # This course fixture intentionally demonstrates an embedded private key.
        exclude: ^labs/lab6/vulnerable-iac/ansible/configure\.yml$
      - id: check-added-large-files
```

The exclusion is limited to the deliberately vulnerable Lab 6 fixture; the private-key check
still protects every other path.

### Hook installation and full-repository check

```console
$ pre-commit install
pre-commit installed at .git/hooks/pre-commit

$ pre-commit run --all-files
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Blocked secret

I staged the lab's fake GitHub token and attempted the commit. The hook returned exit code 1:

```console
$ git commit -m "test: should be blocked"
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

11:11AM INF 0 commits scanned.
11:11AM INF scanned ~48 bytes (48 bytes) in 16.5ms
11:11AM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed

$ git log --oneline -1
1df4847 test: first signed commit
```

The log still points to the preceding signed commit, proving that the secret-containing commit
was not created. I then unstaged and deleted `submissions/leak-attempt.txt`.

### Tuning false positives

An `[allowlist]` entry in `.gitleaks.toml` can exempt only a tightly defined fake `AKIA...`
value or regex while gitleaks continues scanning the surrounding file and the rest of the
repository. It stops being safe when the expression is broad enough to match plausible real
credentials, or when examples are copied and modified into values that the exception still
accepts.

A path exclusion for `docs/` suppresses every finding in that directory, which is simpler but
has a much larger blind spot. It stops being safe as soon as documentation can contain copied
configuration, logs, generated output, or any other file into which a genuine credential could
be pasted, so a narrow value allow-list is preferable here.

## Bonus

### History before the rewrite

```console
$ git log --oneline
35e5014 docs: usage notes
777d423 feat: empty log
9a60bfa feat: add config
aa59a68 init

$ git log -p | grep -c 'ghp_AAAA'
2
```

### Refusal and safe override

The first attempt stopped without changing history:

```console
$ git filter-repo --replace-text /tmp/replace.txt
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

This was an isolated throwaway repository created specifically for the exercise, and I verified
the target before following the message's documented escape hatch:
`git filter-repo --force --replace-text /tmp/replace.txt`. Using `--force` on the real course
repository would not have been appropriate.

### History after the rewrite and counts

```console
$ git log --oneline
fe7feea docs: usage notes
73b1ecd feat: empty log
1ed2c4d feat: add config
24f3857 init

$ git log -p | grep -c 'ghp_AAAA'
0
$ git log -p | grep -c 'REDACTED'
2
```

Rewriting history is only containment. The step that ends the incident is **rotating (or
revoking) the credential** and updating every legitimate consumer: the old value may already be
in a clone, fork, CI log, cache, or an attacker's possession, none of which the local rewrite
can invalidate. A real repository would then need its remote restored if filter-repo removed it,
the rewritten refs force-pushed in coordination with collaborators, and affected clones cleaned
or replaced.

Two terminal results surprised me. First, a repository created moments earlier was rejected as
not fresh because its HEAD reflog already contained one entry per local commit. Second,
filter-repo changed every commit ID, including the empty root commit, and the rewritten commits
no longer displayed their original signatures; changing an ancestor changes every descendant,
and the signatures cannot remain valid over changed commit objects.
