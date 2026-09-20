# Lab 3 — Secure Git: Signed Commits, Secret Scanning, History Hygiene

Environment: git 2.50.1, gitleaks 8.30.1, pre-commit 4.6.2, git-filter-repo. Signing identity: `i.mukhamadullin@innopolis.university`.

## Task 1

### Signing config
```
$ git config --global --get gpg.format
ssh
$ git config --global --get user.signingkey
/Users/ildar/.ssh/id_ed25519.pub
$ git config --global --get commit.gpgsign
true
```
`gpg.ssh.allowedSignersFile` points at `~/.config/git/allowed_signers`, whose single line is
`i.mukhamadullin@innopolis.university namespaces="git" ssh-ed25519 AAAA...` — this is what lets Git verify my own signatures offline.

### `git log --show-signature -1`
```
commit 0654a9e18763269cef019a1b1171bf44d2d52de7
Good "git" signature for i.mukhamadullin@innopolis.university with ED25519 key SHA256:CKGNm3NpcIyQm896LVSYMsCyYPAhsWFKPTPDJ8Y8LEs
Author: Ildar Mukhamadullin <i.mukhamadullin@innopolis.university>
Date:   Sun Sep 20 19:09:49 2026 +0300

    test: first signed commit
```

### Verified badge on GitHub
<FILL IN — link to a commit on github.com/darik1201/DevSecOps-Intro showing the green "Verified" badge, after registering the signing key (Settings → SSH and GPG keys → New SSH key → Key type: **Signing Key**).>

### Repudiation (what the badge changes)
Git takes the author line from local config, so anyone can run `git commit --author="Ildar Mukhamadullin <i.mukhamadullin@innopolis.university>"` and produce commits in this fork that *look* like mine — planting a backdoor or a leaked secret that I could later deny writing, and that a reviewer would attribute to me. The SSH signature binds each commit to my private key: the **Verified** badge means GitHub checked the signature against the signing key registered on my account, so a forged author line without my key shows **Unverified**. That removes the repudiation risk Lab 2 flagged — I can no longer plausibly deny a signed commit, and no one can convincingly forge one in my name.

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
        exclude: ^labs/lab6/vulnerable-iac/
      - id: check-added-large-files
        args: ["--maxkb=1024"]
```
(`detect-private-key` is scoped away from `labs/lab6/vulnerable-iac/`, which ships a *deliberately* planted key as course fixture data — see the tune-out discussion below.)

`pre-commit run --all-files`:
```
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Blocked commit
Attempting to commit `submissions/leak-attempt.txt` containing `GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a`:
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
WRN leaks found: 1
```
Proof it was blocked — HEAD did not move:
```
$ git log --oneline -1
0654a9e test: first signed commit
```
(the same commit as before the attempt; the "should be blocked" commit was never created).

### Tuning out `AKIA...` documentation examples: allowlist vs path exclusion
- **`[allowlist]` entry in `.gitleaks.toml`** (e.g. a `regexes` or `stopwords` entry matching the specific example string, or `regexTarget = "line"`). This is surgical: it silences *exactly* the known example value anywhere it appears, while every other secret in every file still gets scanned. It stops being safe when the allowlist pattern is written too broadly — e.g. allowlisting the whole `AKIA[0-9A-Z]{16}` shape rather than the one documented literal, which would then wave through a *real* leaked AWS key that happens to match.
- **A path exclusion for `docs/`** (`paths` in `.gitleaks.toml`, or `exclude:` on the hook). This turns off scanning for an entire directory, which is simpler but blunt: it stops being safe the moment anyone commits a real secret under `docs/` (a config snippet, a `.env` pasted into a tutorial, an internal runbook) — the scanner never looks there again, so the leak sails through. The narrower the excluded path and the more purely-documentation its contents, the longer it stays safe.

## Bonus

### `git log --oneline` before and after
Before (secret present):
```
8cde38b docs: usage notes
484f5aa feat: empty log
40e7f5a feat: add config
2075f38 init
```
After (rewritten — every hash changed):
```
917d4cc docs: usage notes
c8db33f feat: empty log
4a9800e feat: add config
57b478b init
```

### The three grep counts
```
git log -p | grep -c 'ghp_AAAA'   # before: 2
git log -p | grep -c 'ghp_AAAA'   # after:  0
git log -p | grep -c 'REDACTED'   # after:  2
```

### The refusal message and what I did
```
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```
filter-repo counts **reflog entries**, not remotes — the four commits I just made left multiple `HEAD` reflog entries, so it refused to protect me from an accidental irreversible rewrite. As the message and the lab both note, `--force` is the documented answer for a throwaway sandbox, so I re-ran `git filter-repo --replace-text /tmp/replace.txt --force`, which rewrote all four commits.

### The step that ends the incident
**Rotating the credential** — revoke the leaked `ghp_...` token at the provider and issue a new one. The rewrite only removes the string from *this* repo's history; the real secret has almost certainly already been cloned, forked, cached by GitHub, or scraped by a bot the moment it was pushed, so it must be assumed compromised regardless of what the history now says. Rewriting without rotating leaves a live credential in the wild while giving a false sense of safety. (A real cleanup also force-pushes the rewritten history and re-adds the `origin` remote that `--force` dropped.)

### Two things that surprised me
1. **Every commit hash changed, not just the two that touched the secret** — even `init` and `feat: empty log`, which never contained `ghp_AAAA`. Rewriting content re-writes each commit object, and because a commit hash includes its parent, the change cascades forward through the whole chain.
2. **filter-repo refused on a repo I had *just* created** and never cloned. I expected the "fresh clone" guard to be about remotes, but it triggered purely on the number of `HEAD` reflog entries — the four ordinary commits I made were enough to trip it.
