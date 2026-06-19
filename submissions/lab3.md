# Lab 3 - Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` -> `ssh`
- `git config --global user.signingkey` -> `~/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` -> `true`

### Local verification
Output of `git log --show-signature -1`:
commit 31d8292493e6a4a2f296ccb3fcc8bfc9c4c9f668 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for dudnyashka2006@gmail.com with ED25519 key SHA256:+FVa5orAeRvszaLrTd8BTnoGGkk2c0aMvcdOO1QkmPM
Author: Tatiana <dudnyashka2006@gmail.com>
Date:   Fri Jun 19 19:43:01 2026 +0300

    test: first signed commit

### GitHub verification
- Direct link to my most recent commit on github: https://github.com/witch2256/DevSecOps-Intro/commit/31d8292493e6a4a2f296ccb3fcc8bfc9c4c9f668
- Screenshot of the Verified badge:
  ![verified-badge.png](verified-badge.png)

### One-paragraph reflection
If an attacker can forde a commit author, they can inject malicious code and later deny having done so, causing confusion and undermining thust in the codebase. Signed commits protect the team from both external impersonation and internal disputes about who introduced a change.
