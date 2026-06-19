# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → <ssh>
- `git config --global user.signingkey` → </home/ratteperk/.ssh/id_ed25519.pub>
- `git config --global commit.gpgsign` → <true>

### Local verification
Output of `git log --show-signature -1`:
```
commit cdd587014371199c10c11df559a8590b4f4faae2 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for spered2109@gmail.com with ED25519 key SHA256:HEqmCG37HkRkR3Q28V4BYUiP2VlfTD4qLvAsChPLckI
Author: ratteperk <spered2109@gmail.com>
Date:   Fri Jun 19 02:55:10 2026 +0300

    test: first signed commit
```

### GitHub verification
- Direct link to your most recent commit on GitHub: <https://github.com/ratteperk/DevSecOps-Intro/commit/cdd587014371199c10c11df559a8590b4f4faae2>
- Screenshot of the Verified badge: <img width="1562" height="86" alt="image" src="https://github.com/user-attachments/assets/752734ca-65f0-492d-8de6-aee1bef9dba1" />

### One-paragraph reflection (2-3 sentences)
What STRIDE-R (Repudiation) scenario would a forged-author commit enable in a real
team's codebase? How does the Verified badge make that attack visible?


