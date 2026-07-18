# Lab 3 — Submission
 
## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → ~/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
commit ae7a16e8b91c2b5055f130824e4eafd12eec9290
Good "git" signature for a.gainutdinova@innopolis.university with ED25519 key SHA256:qO/fDJ4nxjz+JNQ7jr9eAboeEB0bSL4olSebdLXMC3E
Author: alilek a.gainutdinova@innopolis.university
Date: Thu Jun 18 15:51:01 2026 +0300
test: first signed commit for Lab 3
### GitHub verification
- Direct link to signed commit: https://github.com/alileeeek/DevSecOps-Intro-1/commit/64b8d365af134c290e0b828d0a6590f702bf3e15
- Screenshot: 
<img width="509" height="117" alt="image" src="https://github.com/user-attachments/assets/e0b46d06-a508-48fa-ae62-09daebc34470" />


### STRIDE-R reflection
A forged-author commit enables a **Repudiation** attack where a malicious insider or attacker who compromises a developer's machine can push malicious code while pretending it came from a trusted team member. Without cryptographic signatures, the real author can later deny writing the code ("it wasn't me"), and the team has no way to prove otherwise. The "Verified" badge on GitHub makes this attack visible by cryptographically proving that only the holder of the private SSH key could have created that commit — any unsigned or badly-signed commit immediately raises suspicion and can be traced back to the actual key holder.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### `pre-commit install` output
```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of `git commit` after planting a fake AWS key:

```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     AWS_ACCESS_KEY_ID=REDACTED
Secret:      REDACTED
RuleID:      aws-access-token
Entropy:     3.684184
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:aws-access-token:1

8:41PM WRN leaks found: 1
```

### Tune-out exercise

**1. Inline allowlist** — `[allowlist]` block in `.gitleaks.toml`. When is this OK?

This approach is acceptable when you have legitimate example strings that must remain in the codebase (e.g., documentation showing API key formats, canonical test fixtures like `AKIAIOSFODNN7EXAMPLE`). The allowlist should be narrowly scoped to specific regex patterns or commit hashes, and reviewed by the security team to ensure it doesn't accidentally whitelist real secrets. It's the most precise method because it only exempts exact matches, not entire directories.

**2. Path exclusion** — `paths: [docs/]` in `.gitleaks.toml`. When is this risky?

Path exclusion is risky because it creates a blind spot where real secrets can hide. If a developer accidentally commits a real AWS key inside `docs/` (for example, in a tutorial or troubleshooting guide), gitleaks won't scan that directory at all and the leak will slip through to production. This approach should only be used for directories that are 100% documentation with no executable code or configuration examples, and should be combined with manual code review for those paths.

## Bonus: History Rewrite

### Before
```
5b5fe25 (HEAD -> master) docs: add usage notes
b47fb57 feat: empty log
ecdced9 feat: add config
fb8f598 init
```

Output of `git log -p | Select-String -Pattern "ghp_AAAA" | Measure-Object | Select-Object -ExpandProperty Count`: **2**

### After
```
573091c (HEAD -> master) docs: add usage notes
e017264 feat: empty log
cf29c64 feat: add config
9bf25cc init
```

Output of `git log -p | Select-String -Pattern "ghp_AAAA" | Measure-Object | Select-Object -ExpandProperty Count`: **0**
Output of `git log -p | Select-String -Pattern "REDACTED" | Measure-Object | Select-Object -ExpandProperty Count`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally to remove the secret from all commits in history.
2. **Rotate the compromised secret immediately** — this is the MANDATORY second step. Even after rewriting history, the secret may already be cached in CI logs, developer machines, backups, or attacker hands. Rewriting git history only cleans the repository; it does NOT invalidate the leaked credential. The old key must be revoked and a new one issued to actually remediate the incident.

### Two real-world gotchas
1. `git filter-repo` refuses to run if the repository has any configured remotes (it returns an error about "fresh-clone sanity check"). I had to use the `--force` flag to override this safety check — this is by design to prevent accidental rewrites of shared repositories.
2. After rewriting history, all commit hashes change, which means any existing PRs, branches, or references pointing to old commits become invalid. In a real incident, this requires force-pushing the rewritten branch and coordinating with all team members to re-clone or reset their local copies — a disruptive operation that should only be done as a last resort after the secret has been rotated.
