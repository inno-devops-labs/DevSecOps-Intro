# Task 1
## Proof of already signing
I have been using SSH signing on GitHub long before the course's beginning, proofs:
- GitHub signing key in settings

![alt text](assets/image.png)
- Signed commits on the previous lab
  
![alt text](assets/image-1.png)

## Reasoning behind SSH commit signing
*(copied from the same task from the DevOps course)*

Commit signing is useful for verifying the source of the commits. If the commit was signed with the source owner's key, then the commit will be verified. If the commit is verified, then one can be sure that that commit came from the original (trusted) source.

# Task 2

Provided pre-commit hook doesn't seem to filter out a fake AWS secret:
```shell
[rightrat | ~/c/DevSecOps-Intro] cat labs/secrets.env                                                                                    
access_key_id=AKIAIOSFODNN7EXAMPLE
secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY⏎    
```
Pre-commit hook output:
```shell
[rightrat | ~/c/DevSecOps-Intro] git commit -S -m "docs: add fake aws key"                                                                                   
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: labs/secrets.env
[pre-commit] Non-lectures files: labs/secrets.env
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-05-10T15:24:39Z    info-0  trufflehog      running source  {"source_manager_worker_id": "hDCbt", "with_units": true}
2026-05-10T15:24:40Z    info-0  trufflehog      finished scanning       {"chunks": 1, "bytes": 93, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "943.644017ms", "trufflehog_version": "3.95.2", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":942}}
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning labs/secrets.env with Gitleaks...
[pre-commit] No secrets found in labs/secrets.env

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
[feature/lab3 28ecd8f] docs: add fake aws key
 1 file changed, 2 insertions(+)
 create mode 100644 labs/secrets.env
```

So I don't know how to replicate a positive detection case 🤷‍♂️

... but secret scanning is absolutely necessary, especially in multi-dev projects, since scraping secrets from GitHub **is** prominent.