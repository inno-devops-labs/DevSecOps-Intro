# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → /home/yalmen/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
commit 1d676ad1a4034c9ac1aec08a732bf2a71fdafcdb (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for namespaces=git with ED25519 key SHA256:PKPugT/aED7zX7HhCKAVxtK5ftFgA5yq/fo0V+fLQZg
Author: yalmen <yalmen@kali.yalmen>
Date:   Thu Jun 18 09:14:42 2026 +0300

    test: first signed commit

### GitHub verification
- Direct link to your most recent commit on GitHub: https://github.com/lashmanovSergey/DevSecOps-Intro/commit/1d676ad1a4034c9ac1aec08a732bf2a71fdafcdb
- Screenshot of the Verified badge: <inline image OR link to image file in PR>

### One-paragraph reflection (2-3 sentences)
What STRIDE-R (Repudiation) scenario would a forged-author commit enable in a real
team's codebase? How does the Verified badge make that attack visible?
