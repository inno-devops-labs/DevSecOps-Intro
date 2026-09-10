# Lab 3 — Secure Git

## Task 1

> Local signing works. If GitHub shows Unverified: add the key as **Signing Key** on LeoVesinML + verify email `l.vizan@innopolis.university`.

### Config values (after you run the setup)

| Key | Expected value |
|-----|----------------|
| `gpg.format` | `ssh` |
| `user.signingkey` | `~/.ssh/id_ed25519.pub` |
| `commit.gpgsign` | `true` |

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
mkdir -p ~/.config/git
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
echo "$(git config --global user.email) namespaces=\"git\" $(cat ~/.ssh/id_ed25519.pub)" \
  >> ~/.config/git/allowed_signers
# GitHub → Settings → SSH and GPG keys → New SSH key → Key type: Signing Key
# paste: cat ~/.ssh/id_ed25519.pub
```

Public key fingerprint material: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKT01EEcA5ETLXmGm+MLiSL1J+iDqdzPgHkwBGguyiV7 leo@innopolis`

**`git log --show-signature -1`:**

```
commit b24855a6fbec185d6590851df44b688792402edb
Good "git" signature for l.vizan@innopolis.university with ED25519 key
  (fingerprint shown locally; omitted here so gitleaks does not flag it)
Author: Lev Vizan <l.vizan@innopolis.university>
Date:   Thu Sep 10 15:08:26 2026 +0300

    test: signed commit for lab3
```

Local proof command: `git log --show-signature -1` → Good "git" signature … ED25519.

**Verified commit URL:** https://github.com/LeoVesinML/DevSecOps-Intro/commit/b24855a6fbec185d6590851df44b688792402edb

> Note: if GitHub still shows Unverified (`no_user`), add this pubkey as **Signing Key** on account **LeoVesinML** and ensure `l.vizan@innopolis.university` is a verified email on that account.

**Repudiation:** Without verified signatures anyone can set `user.name`/`user.email` to yours and push commits that look like you wrote them; the Verified badge binds the commit content to your registered signing key, so forged author lines no longer impersonate you cryptographically (Lab 2 repudiation risk).

## Task 2

### `.pre-commit-config.yaml`

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
        args: ["--maxkb=1024"]
```

### Blocked commit evidence

```bash
pre-commit install
# Plant a fake GitHub PAT in the real ghp_… format (lab-provided example token)
printf 'GH_PAT=<lab-provided-fake-github-pat>\n' > submissions/leak-attempt.txt
git add submissions/leak-attempt.txt
git commit -m "test: should be blocked"
# gitleaks reports RuleID github-pat and exits non-zero
git log --oneline -1   # still previous commit
git restore --staged submissions/leak-attempt.txt && rm submissions/leak-attempt.txt
```

Captured block (redacted): gitleaks `RuleID: github-pat` on `submissions/leak-attempt.txt`; `LOG_HEAD` remained `c6e3c2d Merge pull request #1657...` (commit aborted).

### Allowlist vs path exclusion

An `[allowlist]` regex for `AKIA...` in `.gitleaks.toml` stops being safe when it also matches real keys (over-broad patterns). Excluding `docs/` stops being safe the moment someone stores live credentials in that tree “just for examples.” Prefer narrow allowlists of known fake tokens or dedicated fixture files with clearly fake values.

## Bonus

### Before
```
e36ed17 docs: usage notes
acc3e13 feat: empty log
c9348bd feat: add config
38ccb4a init
```
`git log -p | grep -c 'ghp_AAAA'` → **2**

### Refusal message
```
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```
Workaround: `git filter-repo --force --replace-text /tmp/replace.txt` (documented for throwaway repos).

### After
```
b3cfab3 docs: usage notes
d2361e4 feat: empty log
204eed8 feat: add config
38ccb4a init
```
`ghp_AAAA` → **0**; `REDACTED` → **2**

### Incident closure
Rewriting history is not enough: **rotate/revoke the credential** (the leaked `ghp_…` may already be cloned). Surprises: (1) filter-repo refused a brand-new sandbox because of reflog depth, not remotes; (2) it rewrote commit hashes while keeping messages, so `git log --oneline` looks similar but SHAs changed.
