# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/katharina/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
commit d721426db42cf658432e2a10672144fd0d6a9b55 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for katharina270907@gmail.com with ED25519 key SHA256:oZmM9+FlK1XZUT3Vm5UaQDbYJY1TL3nKKTPJqb6lrB0   # gitleaks:allow
Author: katharina-gross <katharina270907@gmail.com>
Date:   Fri Jun 19 14:15:22 2026 +0300

    test: first signed commit

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/inno-devops-labs/DevSecOps-Intro/commit/d721426db42cf658432e2a10672144fd0d6a9b55
- Screenshot of the Verified badge: file in PR

### One-paragraph reflection (2-3 sentences)
What STRIDE-R (Repudiation) scenario would a forged-author commit enable in a real
team's codebase? How does the Verified badge make that attack visible?

A forged-author commit could allow an attacker to introduce malicious code while pretending to be a trusted developer, making it difficult to identify the real author of the change. 
The GitHub Verified badge makes this attack visible because it shows whether the commit was cryptographically signed by the expected developer.

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml`

cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
EOF

### `pre-commit install` output
pre-commit installed at .git/hooks/pre-commit

### `pre-commit run --all-files` output
pre-commit run --all-files
[INFO] Initializing environment for https://github.com/gitleaks/gitleaks.
[INFO] Initializing environment for https://github.com/pre-commit/pre-commit-hooks.
[WARNING] repo `https://github.com/pre-commit/pre-commit-hooks` uses deprecated stage names (commit, push) which will be removed in a future version.  Hint: often `pre-commit autoupdate --repo https://github.com/pre-commit/pre-commit-hooks` will fix this.  if it does not -- consider reporting an issue to that repo.
[INFO] Installing environment for https://github.com/gitleaks/gitleaks.
[INFO] Once installed this environment will be reused.
[INFO] This may take a few minutes...
[INFO] Installing environment for https://github.com/pre-commit/pre-commit-hooks.
[INFO] Once installed this environment will be reused.
[INFO] This may take a few minutes...
Detect hardcoded secrets.................................................Passed
detect private key.......................................................Failed
- hook id: detect-private-key
- exit code: 1

Private key found: labs/lab6/vulnerable-iac/ansible/configure.yml

check for added large files..............................................Passed

### The blocked commit
cat > /tmp/leak-test.txt <<EOF
# This is a deliberate fake secret for Lab 3 testing
GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a   # gitleaks:allow
EOF
cp /tmp/leak-test.txt submissions/leak-attempt.txt
git add submissions/leak-attempt.txt
git commit -m "test: should be blocked by gitleaks"
[WARNING] Unstaged files detected.
[INFO] Stashing unstaged files to /home/katharina/.cache/pre-commit/patch1781877586-73326.
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

4:59PM INF 0 commits scanned.
4:59PM INF scanned ~101 bytes (101 bytes) in 72.7ms
4:59PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
[INFO] Restored changes from /home/katharina/.cache/pre-commit/patch1781877586-73326.

### Tune-out exercise

Suppose a teammate insists they need to commit `AKIA*` strings because they're
documentation examples in `docs/`. Briefly describe two approaches:

1. **Inline allowlist** — `[allowlist]` block in `.gitleaks.toml`. When is this OK?
   This is basically telling gitleaks "ignore this exact string, I know it's not
   a real secret" — like the example AWS key from the docs that will never
   actually work. It's fine as long as the pattern is narrow and tied to something
   specific (one exact value or one commit), not a broad match like `AKIA*`.
   If you allowlist too loosely, you risk hiding a real leaked key that just
   happens to look the same.

2. **Path exclusion** — `paths: [docs/]` in `.gitleaks.toml`. When is this risky?
   Here you're telling gitleaks to skip scanning a whole folder. That's risky
   because if someone accidentally pastes a real secret into `docs/` instead of
   a fake example, the hook just won't catch it — the whole folder is a blind
   spot. It can work if the team is disciplined about never putting real
   credentials there, but otherwise it's basically a hole in the protection
   instead of an actual fix.

## Bonus: History Rewrite

### Before

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

Output of `git log -p | grep -c 'ghp_'`: **0**  
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite locally
2. **Rotate the compromised secret immediately** — rewriting history removes the secret from the repo, but anyone who already cloned or cached it still has it; the token/key must be revoked and regenerated in whatever system issued it.

### Two real-world gotchas you discovered
1. `git filter-repo` refused to run without `--force` because the repo wasn't a fresh clone — even though it was a local `git init` sandbox with no remotes, filter-repo still flagged it as not looking like a fresh clone and required the `--force` flag to proceed.
2. `pip install git-filter-repo` failed the first time with "externally-managed-environment" because the system Python on Debian/Ubuntu blocks system-wide pip installs by default; I had to re-run with `--break-system-packages` to get it installed.
