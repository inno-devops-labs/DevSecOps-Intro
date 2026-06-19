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
lab3 signing test 2
