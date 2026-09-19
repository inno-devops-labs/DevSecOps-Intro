# Lab 3 — Secure Git

## Task 1

Git config values used for signing:

```
gpg.format = ssh
user.signingkey = ~/.ssh/id_ed25519.pub
commit.gpgsign = true
```

`git log --show-signature -1` output:

```
commit 86f6cb1e81a87a09a442bc01f25c96c2c728c04e
Good "git" signature for sashap070606@gmail.com with ED25519 key SHA256:utJtQllr1SnuooDnWQ5v07wCTRH4rpabSQJtx98vzZE
Author: Alexander Simonov <sashap070606@gmail.com>
Date:   Sat Sep 19 22:32:39 2026 +0300

    test: first signed commit
```

Commit on GitHub with the Verified badge:
https://github.com/AlexbittIT/DevSecOps-Intro/commit/86f6cb1e81a87a09a442bc01f25c96c2c728c04e

**Repudiation:** without signing, anyone with push access (or anyone who forges the `user.name`/`user.email` fields, which are plain, unauthenticated text) can produce a commit that looks like it came from me — I could later claim "I never wrote that" and there would be no way to disprove it, and the reverse: an attacker could pin blame on me for a commit I did not write. The SSH signature is a cryptographic proof tied to a private key only I hold, registered as a Signing Key on my GitHub account. The Verified badge tells anyone reviewing history that the author field and the signature agree, which removes the ability to disown or forge authorship — closing exactly the repudiation gap flagged in the Lab 2 threat model.

## Task 2

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
      - id: check-added-large-files
```

gitleaks output from the blocked commit:

```
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

INF 0 commits scanned.
INF scanned ~48 bytes (48 bytes) in 93.6ms
WRN leaks found: 1
```

Proof the commit did not go through — `git log --oneline -1` still shows the previous commit:

```
86f6cb1 test: first signed commit
```

**`[allowlist]` in `.gitleaks.toml` vs. path exclusion for `docs/`:**

An `[allowlist]` entry (e.g. allowlisting the literal string `AKIAIOSFODNN7EXAMPLE`) only whitelists that exact known-fake value or a narrow regex/fingerprint, so gitleaks keeps scanning everything else in the file and repo — it stops being safe the moment someone copy-pastes a *real* key that happens to match the allowlisted pattern loosely, or the allowlist regex is written too broadly and starts matching real secrets too.

A path exclusion for `docs/` (e.g. `[[rules.allowlist]] paths = ["docs/"]` or a global exclude) turns off scanning for the *entire* directory, not just one string — it stops being safe as soon as anyone puts real credentials, `.env` files, or config with live tokens anywhere under `docs/`, because gitleaks will never look there again. Path excludes are much easier to accidentally widen (a new subfolder, a moved file) and much more dangerous long-term than a narrow, explicit string allowlist.

## Bonus

`git log --oneline` before:

```
70435aa docs: usage notes
1a09006 feat: empty log
0893ed5 feat: add config
f5e717f init
```

`git log --oneline` after `git filter-repo --replace-text`:

```
b5ed436 docs: usage notes
d5cb1d4 feat: empty log
72e895c feat: add config
ec246f4 init
```

(all hashes changed, since every commit's tree/content was rewritten)

Grep counts:

```
git log -p | grep -c 'ghp_AAAA'   # 0
git log -p | grep -c 'REDACTED'   # 2
```

Refusal message on the first run:

```
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

filter-repo checks the reflog, not the presence of a remote — since I had already made several commits directly in this throwaway repo (not a fresh `git clone`), the reflog had more than one entry and it refused to run destructively. Since this was a disposable sandbox repo made specifically for this exercise, I re-ran with `--force` to confirm the rewrite intentionally.

**Rewriting history is only step one.** The step that actually ends the incident is **rotating the credential** — revoking the leaked `ghp_...` token and issuing a new one. Rewriting history only removes the secret from *this* copy of the repo; the original commits (and the real secret) may already be cached in forks, CI logs, local clones other people pulled, or GitHub's own caches/PR diffs, so the old token has to be treated as compromised regardless of how thoroughly history is cleaned.

Two things that surprised me:

1. `git filter-repo` deletes the `origin` remote as a side effect of the rewrite (as a safety measure, so you don't accidentally push rewritten history to the wrong place) — I didn't expect the remote itself to disappear, not just the commit hashes changing.
2. All four commit hashes changed, including the very first `init` commit which never touched the secret at all — because every commit's hash depends on its parent's hash, changing one commit cascades and rewrites every commit after it in the chain.
