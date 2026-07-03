# Lab 8 — Cosign Image Signing, SBOM & Supply Chain Security

## Task 1 — Image Signing & Verification

### Image digest (local registry)
127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

---

### Generate key pair
cosign generate-key-pair
# cosign.key + cosign.pub created

---

### Sign image
cosign sign \
  --key labs/lab8/keys/cosign.key \
  --allow-http-registry \
  --yes \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

---

### Verify signature (valid image)
cosign verify \
  --key labs/lab8/keys/cosign.pub \
  --allow-http-registry \
  --insecure-ignore-tlog \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

Result:
Signature verified successfully

---

### Tampered image test
cosign verify \
  --key labs/lab8/keys/cosign.pub \
  --allow-http-registry \
  --insecure-ignore-tlog \
  127.0.0.1:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d

Result:
no signatures found

---

## Task 2 — SBOM & Provenance Attestation

### SBOM attestation (CycloneDX)
cosign attest \
  --key labs/lab8/keys/cosign.key \
  --allow-http-registry \
  --yes \
  --predicate labs/lab4/juice-shop.cdx.json \
  --type cyclonedx \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

---

### Verify SBOM attestation
cosign verify-attestation \
  --key labs/lab8/keys/cosign.pub \
  --allow-http-registry \
  --insecure-ignore-tlog \
  --type cyclonedx \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

---

### Extract SBOM predicate
jq -r '.payload' labs/lab8/results/verify-sbom.json | base64 --decode | jq '.predicate'

---

### SBOM comparison (canonicalized)
jq -S . labs/lab4/juice-shop.cdx.json > /tmp/original.json
jq -S . labs/lab8/results/extracted-sbom.json > /tmp/extracted.json
diff /tmp/original.json /tmp/extracted.json

Result:
No differences

---

## Provenance attestation (SLSA)

### Create provenance file
cat labs/lab8/provenance.json

---

### Attest provenance
cosign attest \
  --key labs/lab8/keys/cosign.key \
  --allow-http-registry \
  --yes \
  --predicate labs/lab8/provenance.json \
  --type slsaprovenance \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

---

### Verify provenance
cosign verify-attestation \
  --key labs/lab8/keys/cosign.pub \
  --allow-http-registry \
  --insecure-ignore-tlog \
  --type slsaprovenance \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

---

## Bonus — Blob Signing

### Create artifact
mkdir -p labs/lab8/blob

cat > labs/lab8/blob/install.sh <<EOF
#!/bin/sh
echo "Installing Juice Shop..."
EOF

chmod +x labs/lab8/blob/install.sh

tar -czf labs/lab8/blob/install.tar.gz -C labs/lab8/blob install.sh

---

### Sign blob
cosign sign-blob \
  --key labs/lab8/keys/cosign.key \
  --bundle labs/lab8/blob/install.bundle.json \
  labs/lab8/blob/install.tar.gz

---

### Verify blob (valid)
cosign verify-blob \
  --key labs/lab8/keys/cosign.pub \
  --bundle labs/lab8/blob/install.bundle.json \
  labs/lab8/blob/install.tar.gz

Result:
Verified OK

---

### Tamper test
echo "tampered" >> labs/lab8/blob/install.tar.gz

cosign verify-blob \
  --key labs/lab8/keys/cosign.pub \
  --bundle labs/lab8/blob/install.bundle.json \
  labs/lab8/blob/install.tar.gz

Result:
Verification failed (invalid signature)
