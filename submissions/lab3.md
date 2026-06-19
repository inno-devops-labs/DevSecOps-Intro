# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → ssh
- `git config --global user.signingkey` → ~/.ssh/id_ed25519.pub
- `git config --global commit.gpgsign` → true

### Local verification
Output of `git log --show-signature -1`:
git log --show-signature -1
commit 4cc054284fe36ba7e98deb1fbb63b35049ae993d (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for perekrestova.i@yandex.ru with ED25519 key SHA256:VFcU3cHVxkbc36re8h/tXzO8EoqQ4kiuLU5ojbEFUkQ
Author: ashuno <perekrestova.i@yandex.ru>
Date:   Fri Jun 19 22:35:42 2026 +0300

    first signed commit

### GitHub verification
Direct link to the most recent commit on GitHub: `https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1153/changes/14fd1fa5d4449d002762ef99e630e4048d96f1f4`
Screenshot of the Verified badge: `https://github.com/inno-devops-labs/DevSecOps-Intro/pull/1153#issuecomment-4754425067`

### Reflection 
Without verification, a malicious commit becomes difficult to trace. With the Verified badge, every change is connected to a real person
