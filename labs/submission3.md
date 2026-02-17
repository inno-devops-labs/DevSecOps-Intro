# Lab 3

# Task 1
## 1. Benefits of signing commits for security

Using unsigned commit is unsafe because everyone could use commands ```git config user.name "YourName"``` and email to make changes from your account name or rewrite history of repository by using ```git push --force```. CI/CD pipeline also in danger of attacks from random user, which could be signed as an owner of project.  

Signed commits gives oppotunity to have verifired commits with badge (only you from your device could get this badge in your own repository). 

Signature contains also hash of content of the commit. So if someone will change even 1 byte of information - the whole commit will be invalid.

Also we could add the rule to allow only signed commits to CI/CD pipeline, what gives more reliable system and guarantee that unsecure code will not come to production.  

In open sourse projects hard to detect replacement if there is no signatures, but adding verification of commits resolve this pronlem, because all commits of owner is checked by verified badge



## 2. Evidence of successful config
```
➜  DevSecOps-Intro git:(feature/lab3) ✗ git config --global user.name
sayfetik
➜  DevSecOps-Intro git:(feature/lab3) ✗ git config --global user.email
sayfetik2005@gmail.com
➜  DevSecOps-Intro git:(feature/lab3) ✗ git config --global gpg.format
ssh
➜  DevSecOps-Intro git:(feature/lab3) ✗ git config --global user.signingkey
/Users/sayfetik/.ssh/id_ed25519
➜  DevSecOps-Intro git:(feature/lab3) ✗ git config --global commit.gpgSign
true
```

## 3. Why is commit signing critical in DevSecOps workflows?"

DevSecOps is a worklow, when we try integrate security in each step of development lifecycle.  
So, the commits is an inseparable part of development and to provide more reliable workflow is crutial to sign commits. First of all to prevent fake commits and change of commits from the third parties. 
Also it is good for CI/CD pipeline, becuase it also part of development and we want to make it secure. So, the adding the rule to allow only signed commits will give us guarantee that only our team could publish code to production. 

4. Screenshoot of badge
![pic](/assets/verified.png)

# Task 2
## Precommit hook setup
Firsty I created the file ```.git/hooks/pre-commit``` with hooks and add there content, provided in lab.  
Also I run command ```chmod +x .git/hooks/pre-commit``` to make a file executable. Also I open the Docker, because this script use a docker containers, which will not opened without docker.   

## Test results of blocked and passed commit

```
echo 'ghp_...' > bad.txt
git add bad.txt
git commit -S -m "test: must be blocked"
```
```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: bad.txt
[pre-commit] Non-lectures files: bad.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2025-09-27T08:31:02Z    info-0  trufflehog      running source  {"source_manager_worker_id": "3r8sN", "with_units": true}
2025-09-27T08:31:02Z    info-0  trufflehog      finished scanning       {"chunks": 1, "bytes": 41, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "951.930709ms", "trufflehog_version": "3.90.8", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":947}}
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning bad.txt with Gitleaks...
Gitleaks found secrets in bad.txt:
Finding:     ghp_...
Secret:      ghp_...
RuleID:      github-pat
Entropy:     4.246439
File:        bad.txt
Line:        1
Fingerprint: bad.txt:github-pat:1

8:31AM INF scanned ~41 bytes (41 bytes) in 29.4ms
8:31AM WRN leaks found: 1
---
✖ Secrets found in non-excluded file: bad.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: true
Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
```

And a commit without secrets  passed
```
marinalavrova@MacBook-Pro-Marina F25-DevSecOps-Intro % echo 'hello' > good.txt
git add good.txt                            
git commit -S -m "feat: clean commit passes"
```
```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: good.txt
[pre-commit] Non-lectures files: good.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2025-09-27T08:59:47Z    info-0  trufflehog      running source  {"source_manager_worker_id": "hTIZ3", "with_units": true}
2025-09-27T08:59:47Z    info-0  trufflehog      finished scanning       {"chunks": 1, "bytes": 6, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "1.57125ms", "trufflehog_version": "3.90.8", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning good.txt with Gitleaks...
[pre-commit] No secrets found in good.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
[features/lab3 c0e9c90] feat: clean commit passes
 1 file changed, 1 insertion(+)
marinalavrova@MacBook-Pro-Marina F25-DevSecOps-Intro % 
 ```


## Analysis of how automated secret scanning prevents security incidents

Automated precommit scanner reduce risk of leakage of secret keys of early stages of development before the appearing commits in the history of Git and push to repository. It is good because it help to prevent:
- Accidential leaks: accidential publication of keys to the open/inner repository.
- Supply chain risks: the secrets sometimes could be added in artifacts during CI/CD pipeline from old, even deleted locally commits. So if you even once commit your secret to github - your keys in risk.