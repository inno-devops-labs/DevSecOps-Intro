# DevSecOps Lab 8 – Cosign Image Signing

## 1. Objective

The goal of this lab was to:

* Sign a Docker image using Cosign
* Verify the signature
* Understand how image digests are used instead of tags
* Save verification results

---

## 2. Environment

* Docker Registry: `localhost:5000`
* Image: `juice-shop:v19.0.0`
* Cosign key pair:

  * Private key: `labs/lab8/signing/cosign.key`
  * Public key: `labs/lab8/signing/cosign.pub`

---

## 3. Obtaining the Image Digest

To ensure correct signing, the image digest was retrieved from the local registry:

```powershell
$DIGEST = (docker inspect localhost:5000/juice-shop:v19.0.0 | ConvertFrom-Json).RepoDigests[0] -replace '^.*@',''

$REF = "localhost:5000/juice-shop@$DIGEST"

echo $REF
```

---

## 4. Signing the Image

The image was signed using Cosign:

```powershell
cosign sign --yes `
  --allow-insecure-registry `
  --key labs/lab8/signing/cosign.key `
  $REF
```

A password for the private key was provided during signing.

---

## 5. Verification of the Signature

The signature was verified using the public key:

```powershell
cosign verify `
  --allow-insecure-registry `
  --insecure-ignore-tlog `
  --key labs/lab8/signing/cosign.pub `
  $REF `
  *>&1 | Out-File -Encoding utf8 labs/lab8/analysis/verification.txt
```

---

## 6. Tampering Test

After attempting to modify or re-tag the image, a new reference digest was obtained:

```powershell
$DIGEST_AFTER = (docker inspect localhost:5000/juice-shop:v19.0.0 | ConvertFrom-Json).RepoDigests[0] -replace '^.*@',''

$REF_AFTER = "localhost:5000/juice-shop@$DIGEST_AFTER"

echo $REF_AFTER | Out-File -Encoding utf8 labs/lab8/analysis/ref-after-tamper.txt
```

---

## 7. Key Observations

* Cosign signs images using **digests**, not tags
* The same tag may point to different images over time
* Registry access requires correct authentication
* Docker Registry may not support HEAD requests for manifests
* Proper Accept headers are required when querying OCI manifests

---


## 8. Artifacts

* `verification.txt` – Cosign verification output
* `ref-after-tamper.txt` – Digest after tampering test
