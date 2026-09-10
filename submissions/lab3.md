# Lab 3 — Submission

## Task 1

### Git signing configuration

| Setting | Value |
|---------|-------|
| `gpg.format` | `ssh` |
| `user.signingkey` | `~/.ssh/id_ed25519.pub` |
| `commit.gpgsign` | `true` |
| `tag.gpgsign` | `true` |

Key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBLCwbZWTdfMvhhOoZFVTaiPo7dJT8Go7U3PFZ7ASFH3 d.faizullina@innopolis.university`  
Fingerprint: `SHA256:xQnomxWUG8v2TlMj7QqNTUNOMRPlTHseLCISYvKCHhE`

### git log --show-signature -1

```
Good "git" signature for d.faizullina@innopolis.university with ED25519 key SHA256:xQnomxWUG8v2TlMj7QqNTUNOMRPlTHseLCISYvKCHhE
Author: Diliia Faizullina <d.faizullina@innopolis.university>
Date:   Thu Sep 10 22:55:41 2026 +0300

test: first signed commit
```

### GitHub Verified badge link

*(link to commit on GitHub to be added after push)*

### Repudiation and what the badge changes

Without signed commits, anyone who has push access to a fork can author commits with any name and email they like — `git commit --author="Diliia Faizullina <d.faizullina@innopolis.university>"` is a single flag. In practice this means an attacker who compromises the repo can plant commits that look like they came from me, or I could deny authorship of something I actually wrote. Lab 2 called this repudiation: the inability to prove who did what.

The Verified badge changes this because GitHub checks that the commit was signed with a key that is registered to the stated GitHub account. A forged author line produces an Unverified badge (or none at all), which is an immediate flag during code review. It does not make forgery impossible, but it raises the bar from "edit a text field" to "steal a private key".

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

Note: gitleaks 8.30.1 is installed via brew. The `local` + `language: system` hook calls the system binary directly, avoiding the Go build step that times out in this environment. The hook behaviour and rule set are identical to using the upstream `github.com/gitleaks/gitleaks` repo at `v8.30.1`.

### Blocked commit output

Attempting to stage and commit `GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a`:

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

Exit code 1 — commit blocked. `git log --oneline -1` still shows the previous commit, not the blocked one.

### Allowlist options for `AKIA...` documentation examples

**Option 1 — `[allowlist]` entry in `.gitleaks.toml`**

An allowlist entry uses a regex to exempt specific patterns everywhere in the repo, regardless of which file they appear in. For example:

```toml
[allowlist]
  regexes = ['''AKIAIOSFODNN7EXAMPLE''']
```

This stops being safe the moment a real key happens to share a prefix or partial match with the pattern, or when a developer copies the "example" string pattern into production config by accident and it silently passes. It's also repo-wide — if the same key format appears legitimately in a secrets file, the allowlist would suppress that detection too.

**Option 2 — Path exclusion for `docs/`**

A path exclusion tells gitleaks to skip files under a given path entirely:

```toml
[allowlist]
  paths = ['''docs/''']
```

This stops being safe as soon as someone puts a real credential into a file under `docs/` (easy to do by mistake when writing a tutorial with live examples), or when the docs directory is served publicly and a search engine indexes the key. Path exclusions are also a footgun for nested paths — `docs/config/secrets.yaml` would be silently ignored.

In both cases, the right long-term answer is to use placeholder values that look nothing like real credentials (e.g., `AKIAXXXXXXXXXXXXXXXX`) and add them to the gitleaks `allowlist` by exact string, not by pattern.

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

The sandbox repo was initialised with `git init` and four local commits, so the reflog already had multiple entries. `git filter-repo` treats any repo with a non-trivial reflog as "not a fresh clone" and refuses by default to avoid accidentally destroying real history. The fix is `--force`, which is explicitly documented for throwaway repos.

### git log after rewrite

```
c54ad5c docs: usage notes
e20d9ff feat: empty log
32273a0 feat: add config
066d02f init
```

All commit hashes changed because filter-repo rewrites the entire history. The commit messages are the same, but the blobs (and therefore the tree SHA) changed wherever the secret was replaced.

`git log -p | grep -c 'ghp_AAAA'` → **0**  
`git log -p | grep -c 'REDACTED'` → **2**

### Rewriting history is not enough

The rewrite only fixes the local and remote copies of the repository going forward. The step that actually ends the incident is **rotating the credential** — revoking the exposed key and issuing a new one. Anyone who cloned, forked, or cached the repository before the rewrite still has the original history with the plaintext secret. GitHub caches repository data, CI runners may have shallow clones, and Google may have indexed the diff. The secret is still valid and exploitable until it is revoked, regardless of how clean the git history looks.

### Two things that surprised me

First, all four commit hashes changed even for the "init" commit that contained no secret at all. I expected filter-repo to only rewrite commits that touched the files with the replacement, but it rewrites every descendant commit too because each commit's SHA includes its parent's SHA — once one commit changes, all subsequent ones must change as well.

Second, filter-repo silently removed the `origin` remote after running. The tool drops all remote-tracking references as a safety measure so you can't accidentally push the rewritten history to the wrong place. In a real cleanup you'd need to re-add the remote explicitly before doing the force-push.
