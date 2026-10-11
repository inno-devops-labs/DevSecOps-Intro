# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

### Signing
- Output of `cosign sign` (success line):
tlog entry created with index: 2063498557
Pushing signature to: localhost:5000/juice-shop

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
Verification for localhost:5000/juice-shop:v20.0.0 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":{"Bundle":{"SignedEntryTimestamp":"MEUCIDymCsoiIVlfibjlffBQb0tCj1NeQjjMmOL+XeGY5ZMDAiEAgmS4p6dnSmpxX88fsfM6yR5AbdyflwIN2up59nEO9NY=","Payload":{"integratedTime":1783100084,"logIndex":2063498557,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}}}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found

### Sanity — original still verifies
Verification for localhost:5000/juice-shop:v20.0.0 --
The following checks were performed on each of these signatures:
-The cosign claims were validated
-The signatures were verified against the specified public key docker-manifest-digest: sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
	
### Why digest binding matters (Lecture 8 slide 6)
The signature was bound to the original content digest (`sha256:28870b…`), while the tampered
re-tag pointed to a different digest (`sha256:c64c68…`), so verification against that digest found
no signature and failed. If Cosign had signed the *tag* instead of the digest, the signature would
have "followed" the tag: after an attacker re-pushed a malicious image under the same
`juice-shop:v20.0.0` tag, `cosign verify` on the tag could still pass — the tag is mutable, so the
trust anchor would validate whatever content currently sits behind it, defeating the entire purpose
of signing. Digest binding makes the signature attest to exact immutable content, not a movable label.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (decoded payload — structure + component count):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "components": 3069
}
```
- Component count matches Lab 4 source: yes (3069 components in both)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: (empty — no output) success

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
At admission time a Kyverno verify-images policy can require not just a valid signature but a
specific attestation predicate — e.g. a CycloneDX SBOM — bound to the image digest. When the next
Log4Shell drops, a "signed with SBOM" image lets the platform query every running workload's
attested component list and instantly answer "are we exposed?", and a policy can even refuse to
admit images whose SBOM contains the vulnerable version. A "signed but no SBOM" image only proves
provenance — you still have to crack each container open and inventory it by hand under time
pressure, which is exactly the scramble teams faced in December 2021.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
$ cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle --insecure-ignore-tlog my-tool.tar.gz
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Verified OK

### Tamper test failed (correctly)
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Error: invalid signature when validating ASN.1 encoded signature
error during command execution: invalid signature when validating ASN.1 encoded signature

### Codecov 2021 mitigation (2-3 sentences)
Codecov's Bash Uploader was distributed via `curl | bash` with no signature check, so when attackers
modified the script on the server, every CI consumer fetched and executed the tampered version
blindly. If those consumers had run `cosign verify-blob --key cosign.pub --bundle uploader.sh.bundle
uploader.sh` before piping it to `bash`, the check would have failed — the modified bytes no longer
match the signature bound to the original artifact (exactly the `invalid signature` error shown
above), so the pipeline would abort instead of running attacker code. Signing and verifying release
artifacts, not just container images, is what turns a blind `curl | bash` into a verified supply
chain.
