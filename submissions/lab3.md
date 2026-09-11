# Lab 3 — Submission

## Task 1

### Git signing configuration

#### Setting - Value

* `gpg.format` - `ssh`

* `user.signingkey` - `~/.ssh/id_ed25519.pub`

* `commit.gpgsign` - `true`

* `tag.gpgsign` - `true`

Key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJlFDDEGAKwwxlik66rHRo5+LQGhlrq8fd7XgwScr5pf i.muhin@innopolis@university`

Fingerprint: `SHA256:vWuQ1tf1aBKjQIK/FNvOMudQ7PKACM2eeV3FQ5iXZF4`

### git log --show-signature -1

```
Good "git" signature for i.muhin@innopolis.university with ED25519 key SHA256:vWuQ1tf1aBKjQIK/FNvOMudQ7PKACM2eeV3FQ5iXZF4

Author: Ilya Muhin <i.muhin@innopolis.university>

Date:   Fri Sep 11 17:22:53 2026 +0300

test: signed commit
```

### GitHub Verified badge link

https://github.com/Mukhin-I/DevSecOps-Intro/commit/3379c6c8d94e7c693ce33bf93473456ac2e0a3f3

### Repudiation and what the badge changes

Without signed commits, anyone with permission to push to a fork can create commits using any name and email address. For example, `git commit --author="Ilya Muhin <i.muhin@innopolis.university>"` allows an attacker to make a commit appear as if it was authored by me. This also means that I could later deny responsibility for a commit that I actually created. This is the repudiation problem from Lab 2: there is no reliable proof of who performed an action.

The Verified badge provides additional assurance because GitHub verifies that the commit was signed using a key associated with the claimed GitHub account. If someone simply changes the author information without possessing the corresponding private key, GitHub displays the commit as Unverified or without a verification badge, making the discrepancy visible during review. Signing does not completely prevent forgery, but it changes the attack from modifying an author field to obtaining the author's private key.

---

## Task 2

### `.pre-commit-config.yaml`

```yaml
repos:

  - repo: local

    hooks:

      - id: gitleaks

        name: gitleaks

        description: Detect hardcoded secrets using gitleaks

        entry: gitleaks git --pre-commit --redact --staged

        language: system

        pass_filenames: false

  - repo: https://github.com/pre-commit/pre-commit-hooks

    rev: v5.0.0

    hooks:

      - id: detect-private-key

      - id: check-added-large-files

        args: ["--maxkb=500"]
```

Note: gitleaks 8.30.1 is installed through brew. The `local` repository with `language: system` invokes the system-installed binary directly, which avoids the Go build process that times out in this environment. Its hook behaviour and detection rules are the same as those provided by the upstream `github.com/gitleaks/gitleaks` repository at `v8.30.1`.

### Blocked commit output

Trying to stage and commit `GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a` produced:

```
Finding:     GH_PAT=REDACTED

Secret:      REDACTED

RuleID:      github-pat

Entropy:     4.143943

File:        leak-attempt.txt

Line:        1

Fingerprint: leak-attempt.txt:github-pat:1

leaks found: 1
```

Exit code 1 — the commit was rejected. `git log --oneline -1` still points to the previous commit rather than the blocked one.

### Allowlist options for `AKIA...` documentation examples

**Option 1 — Path exclusion for `docs/`**

A path exclusion makes gitleaks ignore all files located under a specified directory:

```toml
[allowlist]

  paths = ['''docs/''']
```

This becomes dangerous if an actual credential is accidentally placed somewhere inside `docs/`, for example while creating documentation containing live configuration values. It is also risky if the documentation is publicly served and the credential becomes searchable. Nested paths such as `docs/config/secrets.yaml` would likewise be skipped without any warning.

**Option 2 — `[allowlist]` entry in `.gitleaks.toml`**

An allowlist entry can use a regular expression to exclude matching values from detection throughout the entire repository. For example:

```toml
[allowlist]

  regexes = ['''AKIAIOSFODNN7EXAMPLE''']
```

This approach becomes risky if a real credential happens to match the same prefix or partial pattern, or if a developer accidentally copies the example into a production configuration and it is then ignored by gitleaks. Because the rule applies repository-wide, the same credential format could also be missed in files where it should be detected.


For both approaches, the safer long-term solution is to use placeholder values that clearly cannot be mistaken for real credentials, such as `AKIAXXXXXXXXXXXXXXXX`, and allowlist the exact placeholder string rather than a broader pattern.

---

## Bonus

### git log before rewrite

```
be996e5 docs: usage notes

02d5803 feat: empty log

6c73627 feat: add config

e91b46d init
```

`git log -p | grep -c 'ghp_AAAA'` → **2**

### filter-repo refusal message

```
Aborting: Refusing to destructively overwrite repo history since

this does not look like a fresh clone.

  (expected at most one entry in the reflog for HEAD)

Please operate on a fresh clone instead.  If you want to proceed

anyway, use --force.
```

The sandbox repository was created with `git init` and already contained four local commits, meaning its reflog had multiple entries. By default, `git filter-repo` considers a repository with a non-trivial reflog to be unsuitable for destructive rewriting and stops to prevent accidental history loss. Since this was a throwaway repository, the appropriate solution was to use `--force`, which is explicitly provided for such cases.

### git log after rewrite

```
c54ad5c docs: usage notes

e20d9ff feat: empty log

32273a0 feat: add config

066d02 init
```

All commit hashes changed because `filter-repo` reconstructs the entire history. Although the commit messages remain unchanged, the affected blobs and consequently the tree SHA values changed where the secret was replaced.

`git log -p | grep -c 'ghp_AAAA'` → **0**

`git log -p | grep -c 'REDACTED'` → **2**

### Rewriting history is not enough

Rewriting the repository only cleans the local and remote history from that point forward. The actual incident response must also include **rotating the credential** — revoking the exposed key and generating a replacement. Anyone who cloned or forked the repository, or otherwise cached it before the rewrite, may still possess the original history containing the plaintext secret. GitHub may retain cached repository data, CI runners can have shallow clones, and search engines may have indexed the previous diff. Therefore, the credential remains usable until it is revoked, regardless of whether the current Git history appears clean.

### Two things that surprised me

First, all four commit hashes changed, including the `init` commit that did not contain the secret. I initially expected `filter-repo` to modify only commits affecting the files where the replacement occurred. However, every descendant commit also receives a new hash because each commit SHA incorporates the SHA of its parent. Once an earlier commit changes, all following commits must therefore be recalculated.

Second, `filter-repo` removed the `origin` remote after the rewrite without prompting. This is a safety mechanism that removes remote-tracking references so the rewritten history cannot accidentally be pushed to an unintended repository. In an actual cleanup process, the remote would have to be added again explicitly before performing the force-push.