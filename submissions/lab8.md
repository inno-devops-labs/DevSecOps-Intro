# Lab 8 — Submission



## Task 1: Sign + Tamper Demo



### Registry + image push

- Registry container: `lab8-registry` running on `localhost:5000`

- Image pushed: `localhost:5000/juice-shop:v20.0.0`

- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`



### Signing

- Output of `cosign sign` (just the success line is fine):

- Pushing signature to: localhost:5000/juice-shop



### Verification (PASSED)

Output of `cosign verify` on original digest:

```json

Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --

```

The following checks were performed on each of these signatures:

&#x20; - The cosign claims were validated

&#x20; - Existence of the claims in the transparency log was verified offline

&#x20; - The signatures were verified against the specified public key

## Tamper Demo (FAILED — correctly)

### Output of cosign verify on tampered digest:

```

Error: no signatures found

error during command execution: no signatures found

```

### Sanity — original still verifies

```

Verification: localhost:5000/juice-shop@sha256:... The signatures were verified against the specified public key

```

## Why digest binding matters

The tampered re-tag pointed to a DIFFERENT digest; your signature was bound to the ORIGINAL digest. If Cosign had signed the tag instead of the digest, an attacker could simply re-tag a malicious image with the same tag (e.g., v20.0.0), and the signature would incorrectly validate against the malicious image. Digest binding ensures the signature is cryptographically tied to the exact byte content of the image.

# Task 2: SBOM + Provenance Attestations

## SBOM attestation

- \* Attached: yes (cosign attest --type cyclonedx exit 0)

- \* Verify-attestation output (first 30 lines of decoded payload):

```

Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --

```

The following checks were performed on each of these signatures:

&#x20; - The cosign claims were validated

&#x20; - Existence of the claims in the transparency log was verified offline

&#x20; - The signatures were verified against the specified public key

Component count matches Lab 4 source: yes

diff between Lab 4 SBOM and the extracted-from-attestation SBOM: <empty> (success)

## Provenance attestation

- Attached: yes

- Builder ID in predicate: https://localhost/lab8-student

- buildType in predicate: https://example.com/lab8/local-build

## What this gives a Lab 9 verifier

At K8s admission time, a Kyverno verify-images policy can require BOTH signatures AND specific attestation predicates. When the next Log4Shell hits, a "signed but no SBOM" image requires manual inspection to determine if it contains the vulnerable library, whereas a "signed with SBOM" image allows automated admission controllers to instantly query the SBOM and block deployment if the vulnerable package is listed.

# Bonus: Blob Signing (Codecov 2021 mitigation)

## Sign + verify

- Signed: my-tool.tar.gz + my-tool.tar.gz.bundle

- Verify-blob success output:

```

Verified OK

```

## Tamper test failed (correctly)

```

Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature

error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature

```

## Codecov 2021 mitigation

Codecov's bash uploader was distributed via curl | bash without signature verification. If their CI consumers had been running cosign verify-blob before bash-ing the script, the attack would have failed because the attacker modified the script, changing its byte stream and invalidating the signature, which cosign verify-blob would have caught before execution.



