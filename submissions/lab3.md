# Lab 3 — Submission

---

## Task 1: SSH Commit Signing

### Local configuration

- `git config --global gpg.format` - `ssh`
- `git config --global user.signingkey` - `/root/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` - `true`

### Local verification

Output of `git log --show-signature -1`:

```
git log --show-signature -1
commit 03147f83392ca0e73b69fba746b3140e8142726f (HEAD -> feature/lab3)
Good "git" signature for dsatyaev@innopolis.university with ED25519 key SHA256:REDACTED FOR COMMIT
/root/.config/git/allowed_signers:1: invalid key^M
/root/.config/git/allowed_signers:1: invalid key
Author: dsatyaev@innopolis.university <dsatyaev@innopolis.university>
Date:   Sun Jun 14 08:26:09 2026 -0400

    test: first signed commit
```

### GitHub verification

- Direct link to your most recent commit on GitHub: https://github.com/Nopef/DevSecOps-Intro/commit/1bfbc80167834056e9c15edade8cc5ee2f50be34
- Screenshot of the Verified badge: https://disk.yandex.ru/i/5N8cK5czK5JdXw

(I spent a few tries to figure out why there is no verified, so the commit is slightly different from the template in lab3.md)

### One-paragraph reflection (STRIDE-R)

If an attacker can commit code under someone else's name without signing, they could push malicious changes and later deny responsibility — classic repudiation in a team's audit trail. The green **Verified** badge on GitHub makes unsigned or forged-author commits obvious during code review, so reviewers can reject changes that cannot be tied to a trusted key.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (full content)

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
        args: ['--maxkb=500']
```

### `pre-commit install` pre-commit installed at .git/hooks/pre-commit

```
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Failed
- hook id: detect-private-key
- exit code: 1

Private key found: labs/lab6/vulnerable-iac/ansible/configure.yml

check for added large files..............................................Passed                                                                           
                                                                             — should say: pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit

Output of the `git commit` that gitleaks blocked:

```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

8:56AM INF 0 commits scanned.
8:56AM INF scanned ~101 bytes (101 bytes) in 49ms
8:56AM WRN leaks found: 1

detect private key.......................................................Passed                                                                           
check for added large files..............................................Passed                                                                           
```

### Tune-out exercise

**1. Inline allowlist (`[allowlist]` in `.gitleaks.toml`)**  
OK when the matched string is a documented fake example with a fixed, known value (e.g. canonical AWS demo keys) and the team accepts residual risk on that exact pattern. Risky when used to whitelist real-looking tokens "just this once" — allowlists tend to grow and hide real leaks.

**2. Path exclusion (`paths: [docs/]` in `.gitleaks.toml`)**  
Useful for generated docs or third-party samples you cannot edit. Risky because secrets often land in `docs/` by mistake (copy-paste from `.env` into README); excluding whole paths blinds the scanner to accidental commits in those folders.

---

## Bonus: History Rewrite

### Before

```
2d54268 init — git log --oneline before rewrite
```

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

```
e2cab7d (HEAD -> master) docs: add usage notes
e06f53d feat: empty log
83cf2ff feat: add config
2d54268 init — git log --oneline after rewrite
```

Output of `git log -p | grep -c 'ghp_'`: **0**  
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life

1. `git filter-repo --replace-text replacements.txt` — rewrite history locally  
2. **Rotate/revoke the exposed secret** — rewriting git history does not invalidate a leaked API key; anyone who copied it can still use it until you rotate at the provider.

### Two real-world gotchas

1. git filter-repo does not just edit files. It rewrites Git history. After the rewrite, all commit hashes changed, so this operation would require coordination in a real shared repository.
  
2. The bonus repo must stay outside the course fork. The sandbox contains a deliberately planted fake secret, so committing /tmp/lab3-bonus or its files into the course repository would defeat the purpose of the exercise.
