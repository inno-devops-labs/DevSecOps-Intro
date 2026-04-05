# Lab 9 вЂ” Monitoring & Compliance

## Task 1 вЂ” Falco runtime detection

### Evidence files
- Full Falco log: $FalcoLog
- Extracted alert lines: $FalcoSummary

### Baseline alerts observed
- Terminal shell in container
- Container drift / file write under /usr/local/bin

### Custom rule
- File: labs/lab9/falco/rules/custom-rules.yaml
- Purpose: detect writable file creation/modification under /usr/local/bin inside a container.
- Should fire: when a process inside a container opens or creates a file for writing in /usr/local/bin/.
- Should not fire: when activity happens on the host or when files are only read.

## Task 2 вЂ” Conftest policy analysis

### Evidence files
- Unhardened manifest results: $ConftestUnhardened
- Hardened manifest results: $ConftestHardened
- Compose manifest results: $ConftestCompose

### What to describe in the report
- Which deny checks failed on the unhardened manifest.
- Why each violation matters for security.
- Which hardening fields in the hardened manifest satisfy the policies.
- Whether the Compose manifest passes, warns, or fails and why.

## Notes
- Replace this stub with your final analysis before submitting.
- Add screenshot snippets or copied alert lines from the evidence files above.
