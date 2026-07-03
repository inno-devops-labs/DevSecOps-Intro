\# Lab 8 — Submission



\## Task 1: Sign + Tamper Demo



\### Registry + image push

\- Registry container: `lab8-registry` running on `localhost:5000`

\- Image pushed: `localhost:5000/juice-shop:v20.0.0`

\- Image digest:

```

localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe

```



\### Signing

Output of `cosign sign`:

```

Pushing signature to: localhost:5000/juice-shop

```



\### Verification (PASSED)

Output of `cosign verify` on original digest:

```

WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.



Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --

The following checks were performed on each of these signatures:

&#x20; - The cosign claims were validated

&#x20; - Existence of the claims in the transparency log was verified offline

&#x20; - The signatures were verified against the specified public key



\[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]

```



\### Tamper Demo (FAILED — correctly)

Output of `cosign verify` on tampered digest (alpine re-tagged as juice-shop):

```

WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Error: no signatures found

error during command execution: no signatures found

```



\### Sanity — original still verifies

```

WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.



Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --

The following checks were performed on each of these signatures:

&#x20; - The cosign claims were validated

&#x20; - Existence of the claims in the transparency log was verified offline

&#x20; - The signatures were verified against the specified public key



\[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]

```



\### Why digest binding matters

The signature is bound to the \*\*digest\*\* (content hash), not the tag. If Cosign had signed the tag `v20.0.0`, an attacker could push a malicious image (like alpine) under the same tag, and the signature would still verify because tags are mutable pointers that can be reassigned to different content. By signing the digest `sha256:28870b9d...`, the signature is cryptographically bound to the exact bytes of the image — any change (even a single bit) produces a different digest and invalidates the signature. The tamper demo proves this: the tampered image has digest `sha256:d9e853e8...` (alpine), which is different from the original `sha256:28870b9d...` (juice-shop), so verification fails with "no signatures found". This is the defense-in-depth guarantee that digest-based signing provides over tag-based signing.



\---



\## Task 2: SBOM + Provenance Attestations



\### SBOM attestation

\- Attached: yes (`cosign attest --type cyclonedx` exit 0)

\- Verify-attestation output (first 30 lines of decoded payload):

```json

{

&#x20; "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",

&#x20; "bomFormat": "CycloneDX",

&#x20; "components": \[

&#x20;   {

&#x20;     "author": "Benjamin Byholm <bbyholm@abo.fi> (https://github.com/kkoopa/), Mathias K...",

&#x20;     "bom-ref": "pkg:npm/1to2@1.0.0?package-id=3cea2309a653e6ed",

&#x20;     "cpe": "cpe:2.3:a:nodejs:1to2:1.0.0:\*:\*:\*:\*:\*:\*:\*",

&#x20;     "description": "NAN 1 -> 2 Migration Script",

&#x20;     "externalReferences": \[

&#x20;       {

&#x20;         "type": "distribution",

&#x20;         "url": "git://github.com/nodejs/nan.git"

&#x20;       }

&#x20;     ],

&#x20;     "licenses": \[

&#x20;       {

&#x20;         "license": {

&#x20;           "id": "MIT"

&#x20;         }

&#x20;       }

&#x20;     ],

&#x20;     "name": "1to2",

&#x20;     "properties": \[

&#x20;       {

&#x20;         "name": "syft:package:foundBy",

&#x20;         "value": "javascript-package-cataloger"

&#x20;       },

&#x20;       {

&#x20;         "name": "syft:package:language",

```

\- Component count matches Lab 4 source: yes

\- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: empty (success)



\### Provenance attestation

\- Attached: yes (`cosign attest --type slsaprovenance` exit 0)

\- Builder ID in predicate: `https://localhost/lab8-student`

\- buildType in predicate: `https://example.com/lab8/local-build`

\- Verify-attestation output (base64-decoded payload):

```json

{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJsb2NhbGhvc3Q6NTAwMC9qdWljZS1zaG9wIiwiZGlnZXN0Ijp7InNoYTI1NiI6IjI4ODcwYjlkMmJlYzQ5ZTYwNWQ2ZWJiZjRiMjJlZDFlYzFjYTBhNzIzNDdlZjE5MjE3YmJiYjIxZWE0NGUzZmUifX1dLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YwLjIiLCJwcmVkaWNhdGUiOnsiYnVpbGRUeXBlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9sYWI4L2xvY2FsLWJ1aWxkIiwiYnVpbGRlciI6eyJpZCI6Imh0dHBzOi8vbG9jYWxob3N0L2xhYjgtc3R1ZGVudCJ9LCJpbnZvY2F0aW9uIjp7ImNvbmZpZ1NvdXJjZSI6eyJkaWdlc3QiOnsic2hhMSI6ImFiYzEyMyJ9LCJ1cmkiOiJodHRwczovL2dpdGh1Yi5jb20vc3R1ZGVudC9yZXBvIn19fX0=","payloadType":"application/vnd.in-toto+json","signatures":\[{"sig":"MEUCIEmy/vbn1fYdznV6f1PjkHI7DKfbc+aXrapcmAnmjSN4AiEAu7z6G8kI+fHJodp1fF/3KzbjnVkgXaHCvwIsHIzcmss="}]}

```



\### What this gives a Lab 9 verifier

When the next Log4Shell hits, a "signed but no SBOM" image only tells you that the image came from a trusted source — but you'd have to manually pull the image, inspect its filesystem, and run a scanner to find if it contains vulnerable log4j components. A "signed with SBOM" image lets you query the attestation programmatically via `cosign verify-attestation --type cyclonedx`, which returns the full component list without pulling the image, and you can immediately grep for `log4j` or any other vulnerable package across all your deployments. This turns a days-long manual audit into a minutes-long automated query, dramatically reducing mean-time-to-detect (MTTD) for supply-chain vulnerabilities. The SBOM attestation is cryptographically signed by the same key as the image signature, so you can trust it hasn't been tampered with and was produced by the same trusted builder.



\---



\## Bonus: Blob Signing (Codecov 2021 mitigation)



\### Sign + verify

\- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`

\- Verify-blob success output:

```

WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.

Verified OK

```



\### Tamper test failed (correctly)

```

WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.

Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature

error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature

```



\### Codecov 2021 mitigation

The Codecov bash uploader was distributed via `curl https://codecov.io/bash | bash` without any signature verification. When attackers compromised Codecov's CI pipeline in 2021 and injected malicious code into the uploader script, all downstream consumers blindly executed the poisoned script via `curl | bash`, giving attackers access to environment variables, secrets, and source code across thousands of repositories. If consumers had been running `cosign verify-blob --key codecov.pub --bundle codecov-uploader.bundle codecov-uploader.sh` \*\*before\*\* executing the script, the attack would have failed immediately — the signature wouldn't match the tampered bytes, and `verify-blob` would exit with an error like "invalid signature when validating ASN.1 encoded signature", preventing the malicious code from running. This is the exact use case for `cosign sign-blob`: cryptographic verification of arbitrary files (not just container images) distributed outside of OCI registries. The blob signing creates a cryptographic binding between the file content and the signature, so any modification (even a single byte) invalidates the signature, providing the same supply-chain integrity guarantees for scripts, binaries, and configuration files as Cosign provides for container images.

