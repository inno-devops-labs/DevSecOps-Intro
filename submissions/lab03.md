# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → <ssh>
- `git config --global user.signingkey` → </Users/a79135/.ssh/id_ed25519.pub>
- `git config --global commit.gpgsign` → <true>

### Local verification
Output of `git log --show-signature -1`:commit 1dc66e3ae07fedd5c49dc6f039abb4c686c2ab5f (HEAD -> lab03)
Good "git" signature for a.nikolaeva@innopolis.university with ED25519 key SHA256:8GSxlvdecN00j5Mus9SElUSDbK6BYcUOIagqME2SBsA
Author: Arina Nikolaeva a.nikolaeva@innopolis.university
Date:   Fri Jun 12 12:15:37 2026 +0300

### GitHub verification
- Direct link to your most recent commit on GitHub: <https://github.com/Nik-ari-ai/DevSecOps-Intro/commit/1dc66e3ae07fedd5c49dc6f039abb4c686c2ab5f>
- Screenshot of the Verified badge: <submissions/lab03-verified.png>

### One-paragraph reflection (2-3 sentences)
What STRIDE-R (Repudiation) scenario would a forged-author commit enable in a real
team's codebase? How does the Verified badge make that attack visible?
Without signed commits, anyone with push access or someone who steals push access can author a commit under any name and email they want, since Git takes the author field on trust. A forged-author commit could quietly slip in a backdoor or a secret while looking like it came from a trusted maintainer, and on review the team would have no way to repudiate it: that is the STRIDE-R scenario. The Verified badge makes the attack visible because GitHub re-checks every commit against the actual signing keys uploaded by the named author -> a forged commit either shows up as unverified.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)
```yaml
default_stages: [pre-commit]

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
### `pre-commit install output` (paste the full content)
pre-commit installed at .git/hooks/pre-commit

### `The blocked commit` (paste the full content)
Detect hardcoded secrets.................................................Failed

hook id: gitleaks
exit code: 1
gitleaks

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2
12:39PM INF 0 commits scanned.
12:39PM INF scanned ~101 bytes (101 bytes) in 31.7ms
12:39PM WRN leaks found: 1
detect private key.......................................................Passed
check for added large files..............................................Passed

Tune-out exercise

Suppose a teammate insists they need to commit AKIA* strings because they're documentation examples in docs/. Briefly describe two approaches:
Inline allowlist — [allowlist] block in .gitleaks.toml. When is this OK?
When the exception is narrowly scoped to one or two known-safe strings and the entry is reviewed in the diff like any other change. Because the allowlist is matched on a specific value or regex, anything outside that exact pattern still gets flagged, so the blast radius of the exception stays tiny.
Path exclusion — paths: [docs/] in .gitleaks.toml. When is this risky? (2-3 sentences each. No correct answer; both have tradeoffs.)
It is risky because it turns off scanning for the entire folder, not for a single string. The day someone moves real configuration into docs, the scanner stops protecting them and a real secret can land in the repo unnoticed. Path exclusions are sometimes the right call for generated fixtures, but they should be the last resort, not the default fix.

## Bonus: History Rewrite

### Before
<76884be (HEAD -> master) docs: add usage notes
afc0dfe feat: empty log
84dc162 feat: add config
606df6e init>
Output of `git log -p | grep -c 'ghp_'`: **2**

### After
<1445bd9 (HEAD -> master) docs: add usage notes
733df56 feat: empty log
929ba4a feat: add config
606df6e init>
Output of `git log -p | grep -c 'ghp_'`: **0**
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **<Rotate the leaked secret at the provider (revoke + reissue), then force-push the rewritten history>** — what's the MANDATORY second step in a real incident?
   (Hint: Lecture 3 slide 12 has this — it's the difference between cleanup and remediation.)

### Two real-world gotchas you discovered (2 sentences each)
1. <something the lab actually surprised you with — e.g., "filter-repo refused to run because there were existing remotes; I had to remove origin">
`git filter-repo` refused to run with "this does not look like a fresh clone". It is a safety guard against destroying a working repo, and I had to add `--force` because it was a throwaway sandbox. In a real incident, the safer fix is to make a fresh clone first instead of using `--force`
2. <The signing setup from Task 1 is global, so the new sandbox repo under `/tmp` also tried to sign every commit. I had to disable signing per command with `git -c commit.gpgsign=false`, otherwise the commits would either fail or get signatures that nothing can verify.>
