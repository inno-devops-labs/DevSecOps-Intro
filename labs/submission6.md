# Task 1
## Tool comparison
- tfsec findings: 53
- Checkov findings: 78
- Terrascan findings: 22

## Pulumi

6 findings: 
- 1 Critical
- 2 High
- 1 Medium
- 2 Informational

## Terraform vs Pulumi
Terraform found more than Pulumi, however not full Pulumi was used...

Pulumi is more targeted (narrow), but may be more deep

## Critical findings 
- (Maybe) Publicly accessible RDS database
- Security open to ``0.0.0.0/0``
- Unencrypted RDS
- Weak public access controls (S3)
- Generic password 

## Tool Strengths
- tfsec: quick at finding terraform misconfigurations, readable output (if filter out the ""s)
- Checkov: best in this excercise, overall seems the most "swiss knife" of all
- Terrascan: selective but effective for open ports and storage risks
- KICS for Pulumi: least useful in this excercise, more general coverage

# Task 2

## Ansible Security Issues
10 findings: 9 high 1 low, mainly - secret exposure

## Best Practice Violations
- Passwords in URLs - very bad
- Plaintext passwords and generic secrets - very very bad
- Unpinned package versions - app may not work

## KICS Ansible Queries
In this excercise KICS mainly scanned for secrets

## Remediation
- Passwords in URLs: move passwords from URLs to environment vars or use secret manager
- Plaintext passwords and secrets: replace hardcoded passwords with external injects or encrypt them
- Unpinned packages: pin the packages' versions lol




```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

```shell

```

