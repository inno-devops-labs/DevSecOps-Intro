# Lab 3 Submission: Git Commit Signing

## Summary: Benefits of Signing Commits for Security
Signing commits provides cryptographic proof of the author's identity. It ensures non-repudiation, meaning the author cannot deny making the commit, and guarantees data integrity by confirming that the commit's contents have not been altered since it was signed. This prevents malicious actors from impersonating developers and injecting unauthorized code into the repository.

## Evidence of Successful SSH Key Setup and Configuration
I used already generated SSH key:
![Using the signing key](./screenshots/submission3/signing-key.png)

## Analysis: Why is commit signing critical in DevSecOps workflows?
In DevSecOps workflows, securing the software supply chain is paramount. The source code repository is the foundation of this chain. If an attacker gains access to a repository (e.g., via stolen credentials or a compromised CI/CD pipeline), they could silently inject vulnerabilities or backdoors. 

Commit signing is critical because it establishes a zero-trust approach to code authorship. Even if an attacker pushes code, the lack of a valid cryptographic signature will flag the commit as unverified. Automated DevSecOps pipelines can be configured to reject unsigned or improperly signed commits, effectively blocking unauthorized changes from reaching production. It ensures that every piece of code has a verified, auditable trail back to a trusted developer's private key.

## VerificationÍÍ
![GitHub Verified Badge](../screenshots/submission3/verified-badge.png)
