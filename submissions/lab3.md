# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/home/lisoon/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`
- `git config --global tag.gpgsign` → `true`
- `git config --global gpg.ssh.allowedSignersFile` → `/home/lisoon/.config/git/allowed_signers`

### Local verification
Output of `git log --show-signature -1`:

```text
commit fd3fccb02afc733b2705ebe9050539e2f3049d67
Good "git" signature for roman.voronin.2006@mail.ru with ED25519 key [fingerprint redacted]
Author: Lisoon22 <roman.voronin.2006@mail.ru>
Date:   Fri Jun 19 19:29:33 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to the signed commit: https://github.com/Lisoon22/DevSecOps-Intro/commit/fd3fccb02afc733b2705ebe9050539e2f3049d67
- Verified badge evidence: [Open the signed commit and view its GitHub verification status](https://github.com/Lisoon22/DevSecOps-Intro/commit/fd3fccb02afc733b2705ebe9050539e2f3049d67)

The public key used for this commit is configured separately in GitHub as an SSH **Signing Key**, not only as an authentication key.

### STRIDE-R reflection
A forged-author commit would let an attacker introduce malicious code or weaken a security control while making the change appear to come from a trusted developer. This creates a repudiation problem because the named author could deny creating the change and the team would lack cryptographic proof of origin. A green GitHub **Verified** badge shows that the commit signature matches a signing key registered to the account, making unsigned or incorrectly signed impersonation attempts visible during review.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks-system
        alias: gitleaks
        name: Detect hardcoded secrets with Gitleaks
        pass_filenames: false

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
        exclude: ^labs/lab6/vulnerable-iac/ansible/configure\.yml$

      - id: check-added-large-files
        args: ["--maxkb=1024"]
```

### `pre-commit install` output

```text
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
The following output was captured from the deliberately failed commit containing a fake GitHub PAT. The test file was immediately unstaged and deleted, and the token is redacted below.

```text
Detect hardcoded secrets with Gitleaks...................................Failed
- hook id: gitleaks-system
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

[90m7:29PM[0m [32mINF[0m [1m0 commits scanned.[0m
[90m7:29PM[0m [32mINF[0m [1mscanned ~96 bytes (96 bytes) in 18.1ms[0m
[90m7:29PM[0m [33mWRN[0m [1mleaks found: 1[0m

detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise
1. **Inline allowlist:** A narrow allowlist in `.gitleaks.toml` is acceptable when a known false positive is stable and can be scoped to a specific rule, fingerprint, exact regex, or file. It should be reviewed like code because an overly broad expression can suppress real credentials that resemble the documentation example.

2. **Path exclusion:** Excluding `docs/` can be convenient when the directory contains many intentionally fake credential examples, but it is risky because real secrets can still be pasted into documentation. A whole-directory exclusion creates a blind spot, so a precise rule or fingerprint allowlist is normally safer than ignoring every file under the path.

## Bonus: History Rewrite

### Before

```text
ab4ae97 docs: add usage notes
30321a7 feat: empty log
6c6abc8 feat: add config
f037896 init
```

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

```text
8bf4c6a docs: add usage notes
d21d9dd feat: empty log
0e6ab92 feat: add config
f037896 init
```

Output of `git log -p | grep -c 'ghp_'`: **0**

Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in a real incident
1. `git filter-repo --replace-text replacements.txt` rewrites the affected local history.
2. **Immediately revoke and rotate the exposed credential, update every dependent system, and then coordinate the force-push of rewritten history.** History cleanup does not invalidate a credential that an attacker may already have copied.

The sandbox also force-pushed the rewritten branch to its local bare remote:

```text
To /tmp/lab3-bonus-remote.git
 + ab4ae97...8bf4c6a main -> main (forced update)
branch 'main' set up to track 'origin/main'.
```

### Two real-world gotchas discovered
1. The sandbox was a normal initialized working repository rather than a fresh clone, so git filter-repo's safety check required the explicit --force flag. This was acceptable only because /tmp/lab3-bonus was deliberately disposable.
2. git filter-repo removed the origin remote: yes. The workflow checked for that safety behavior, re-added the local bare remote when necessary, and then force-pushed the rewritten main branch.

## Final verification checklist
- [x] SSH commit signing is configured globally.
- [x] Local Git verification reports a good SSH signature.
- [x] The signed commit has a direct GitHub verification link.
- [x] `.pre-commit-config.yaml` contains gitleaks v8.x and two additional hooks.
- [x] The controlled fake-secret commit was blocked and cleaned up.
- [x] Both gitleaks tune-out approaches are discussed.
- [x] The bonus sandbox demonstrates the required `2 → 0` history rewrite.
- [x] Credential rotation is identified as mandatory incident remediation.
