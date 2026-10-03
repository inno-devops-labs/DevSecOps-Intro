# Lab 3 — Secure Git: Signed Commits, Secret Scanning, and History Hygiene

![difficulty](https://img.shields.io/badge/difficulty-beginner-success)
![topic](https://img.shields.io/badge/topic-Secure%20Git-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Git%20%2B%20gitleaks%20%2B%20filter--repo-informational)

> **Goal:** Sign every commit with your SSH key, block secrets before they leave your laptop, and rewrite history to purge one that got through.
> **Deliverable:** A PR from `feature/lab3` with `submissions/lab3.md` and `.pre-commit-config.yaml`. Submit the PR link via Moodle.
> **Builds on:** the fork and PR workflow from Lab 1, and the repudiation risk your Lab 2 model flagged. **Used by:** every later lab, since your commits stay signed.

## Setup

- Git 2.34 or newer (`git --version`): SSH signing does not exist before it, and older Git answers `gpg failed to sign the data`.
- An SSH key: `ls ~/.ssh/id_*.pub`, or `ssh-keygen -t ed25519`.
- `gitleaks` 8.x ([releases](https://github.com/gitleaks/gitleaks/releases), or `brew install gitleaks`).
- `pre-commit` and `git-filter-repo`, both Python tools:

<!-- verify:skip student fork branch and per-machine python setup -->
```bash
git switch main && git pull
git switch -c feature/lab3

pipx install pre-commit && pipx install git-filter-repo
```

On Debian and Ubuntu a plain `pip install` fails with `externally-managed-environment` (PEP 668). Use `pipx` as above, a virtualenv, or `pip install --break-system-packages`.

## Task 1 — SSH commit signing (6 pts)

### 3.1 Configure signing

<!-- verify:skip changes the reader's global git config -->
```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true

mkdir -p ~/.config/git
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
echo "$(git config --global user.email) namespaces=\"git\" $(cat ~/.ssh/id_ed25519.pub)" \
  >> ~/.config/git/allowed_signers
```

The last two lines are what lets `git log --show-signature` verify your own signatures offline. Without them Git signs happily, then cannot check the result.

### 3.2 Register the key with GitHub

Settings → SSH and GPG keys → New SSH key, **Key type: Signing Key**, paste `cat ~/.ssh/id_ed25519.pub`.

### 3.3 Prove it works

<!-- verify:skip signs commits in the student's own fork -->
```bash
echo "lab3" > submissions/lab3.md
git add submissions/lab3.md
git commit -m "test: first signed commit"
git log --show-signature -1
git push -u origin feature/lab3
```

Locally: `Good "git" signature for <your-email> with ED25519 key SHA256:...`. On GitHub: a green **Verified** badge.

**Submit** in `submissions/lab3.md`, section `## Task 1`:

- The values of `gpg.format`, `user.signingkey` and `commit.gpgsign`.
- The `git log --show-signature -1` output.
- A link to the commit on GitHub showing the Verified badge.
- Two or three sentences: what could someone do in your repository with a forged author line, and what does the badge change? Lab 2 called this repudiation.

## Task 2 — Pre-commit and gitleaks (4 pts)

Optional. Skipping it does not affect later labs.

### 3.4 Write the hook config

```yaml
# YOUR TASK: .pre-commit-config.yaml at the repo root
# Requirements:
#   - repo https://github.com/gitleaks/gitleaks at a real 8.x tag, hook id: gitleaks
#   - at least one hook from https://github.com/pre-commit/pre-commit-hooks,
#     detect-private-key and check-added-large-files are the useful ones here
# Hints:
#   - the syntax is at https://pre-commit.com/#2-add-a-pre-commit-configuration
#   - `rev:` must be a tag that exists; check the releases page
```

### 3.5 Install and test it

<!-- verify:skip needs the config the student writes in 3.4 -->
```bash
pre-commit install
pre-commit run --all-files
```

Now try to commit a secret. The string below is a fake token in the real format:

<!-- verify:skip plants a secret in the student's own working tree -->
```bash
printf 'GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n' > submissions/leak-attempt.txt
git add submissions/leak-attempt.txt
git commit -m "test: should be blocked"
```

The commit must fail, gitleaks naming the `github-pat` rule. Clean up with `git restore --staged submissions/leak-attempt.txt && rm submissions/leak-attempt.txt`.

**Submit**, section `## Task 2`:

- Your `.pre-commit-config.yaml`.
- The gitleaks output from the blocked commit, and proof it was blocked: `git log --oneline -1` still shows the previous commit.
- A teammate wants to commit `AKIA...` strings as documentation examples. In 2-3 sentences each: an `[allowlist]` entry in `.gitleaks.toml` versus a path exclusion for `docs/`. When does each stop being safe?

## Bonus — Purge a secret from history (2 pts)

### 3.6 Build a sandbox and plant a secret

<!-- verify:skip throwaway repo outside the fork -->
```bash
mkdir -p /tmp/lab3-bonus && cd /tmp/lab3-bonus && git init
git commit --allow-empty -m "init"
echo "API_KEY=ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ" > config.txt
git add config.txt && git commit -m "feat: add config"
echo "log file" > app.log && git add app.log && git commit -m "feat: empty log"
echo "API_KEY=ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ" >> README.md
git add README.md && git commit -m "docs: usage notes"
git log -p | grep -c 'ghp_AAAA'    # 2
```

### 3.7 Rewrite

<!-- verify:skip acts on the throwaway repo from 3.6 -->
```bash
echo 'ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJ==>[REDACTED]' > /tmp/replace.txt
# YOUR TASK: run git filter-repo --replace-text /tmp/replace.txt
# It will refuse the first time. Read the message before you work around it.
git log -p | grep -c 'ghp_AAAA'    # 0
git log -p | grep -c 'REDACTED'    # 2
```

**Submit**, section `## Bonus`:

- `git log --oneline` before and after, and the three grep counts.
- The message filter-repo printed when it refused, and what you did about it.
- Rewriting history is only step one. Name the step that ends the incident, and why the rewrite alone is not enough.
- Two things that surprised you: what did your terminal print that you did not expect?

## Acceptance criteria

- Task 1 (6): `gpg.format` is `ssh`; `git log --show-signature -1` shows a good signature; every commit on the PR is Verified on GitHub; the repudiation answer is specific to your repository.
- Task 2 (4): config has a gitleaks hook at a real 8.x tag plus one more hook; the blocked-commit output names the rule; both tune-out options answered with the condition that makes each unsafe.
- Bonus (2): counts go 2 to 0, with 2 for the marker; the refusal message quoted and explained; the second step named as **rotating the credential**; two specific surprises.
## Submit

<!-- verify:skip student fork files -->
```bash
git add <proof of work + lab3.md> (.pre-commit-config.yaml submissions/lab3.md, ...)
git commit -m "feat(lab3): signed commits + gitleaks pre-commit hook"
git push -u origin feature/lab3
```


## Common pitfalls

- `pip install pre-commit` fails with `externally-managed-environment` on Debian and Ubuntu. Use `pipx`, a virtualenv, or `--break-system-packages`.
- Commits show Unverified on GitHub: the key is registered as an Authentication Key only. The same key bytes go in twice, once per role.
- `git log --show-signature` cannot check the signature: `allowedSignersFile` is missing, or the file format is wrong. It is `<email> namespaces="git" <the whole public key line>`.
- gitleaks ignores your planted secret: documentation values such as `AKIAIOSFODNN7EXAMPLE` are allowlisted on purpose. The `ghp_` token in 3.5 does fire `github-pat`.
- `gitleaks protect` no longer exists. 8.x has `dir`, `git` and `stdin`; the pre-commit hook picks the right one for you.
- `git filter-repo` refuses with `does not look like a fresh clone` even in the sandbox you just created, because it counts reflog entries, not remotes. `--force` is the documented answer for a throwaway repo. It also drops your `origin` remote, so a real cleanup ends with re-adding the remote and force-pushing.

## Resources

- [Git SSH signing](https://git-scm.com/docs/git-config#Documentation/git-config.txt-gpgformat), [GitHub SSH commit verification](https://github.blog/changelog/2022-08-23-ssh-commit-verification-now-supported/)
- [pre-commit](https://pre-commit.com/) and [gitleaks](https://github.com/gitleaks/gitleaks)
- [git filter-repo](https://github.com/newren/git-filter-repo), and the [filter-branch warning](https://git-scm.com/docs/git-filter-branch) explaining why
- [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
