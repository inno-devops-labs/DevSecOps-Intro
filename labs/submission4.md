# Task 1
## Package Type Distribution
Syft Package Counts:
- **1** binary
- **10** deb
- **1128** npm

Trivy Package Counts:
- **10** bkimminich/juice-shop:v19.0.0 (debian 12.11) - unknown
- **1125** Node.js - unknown
  
**Conclusion**: both tools produced similar outputs, decision on which to use depends on the task at hand

## Licenses
Syft Licenses:
- 1 0BSD
- 1 ad-hoc
- 1 Apache2
- 15 Apache-2.0
- 5 Artistic
- 5 BlueOak-1.0.0
- 1 BSD
- 12 BSD-2-Clause
- 1 (BSD-2-Clause OR MIT OR Apache-2.0)
- 16 BSD-3-Clause
- 4 GFDL-1.2
- 5 GPL
- 1 GPL-1
- 1 GPL-1+
- 6 GPL-2
- 1 GPL-2.0
- 4 GPL-3
- 143 ISC
- 4 LGPL
- 1 LGPL-2.1
- 19 LGPL-3.0
- 890 MIT
- 2 (MIT OR Apache-2.0)
- 1 (MIT OR WTFPL)
- 2 MIT/X11
- 2 MPL-2.0
- 1 public-domain
- 2 sha256:cb992345949ccd6e8394b2cd6c465f7b897c864f845937dbf64e8997f389e164
- 2 Unlicense
- 1 WTFPL
- 1 WTFPL OR ISC
- 1 (WTFPL OR MIT)

Trivy Licenses (OS Packages):
- 1 ad-hoc
- 1 Apache-2.0
- 2 Artistic-2.0
- 1 GFDL-1.2-only
- 1 GPL-1.0-only
- 1 GPL-1.0-or-later
- 3 GPL-2.0-only
- 2 GPL-2.0-or-later
- 1 GPL-3.0-only
- 1 LGPL-2.0-or-later
- 1 LGPL-2.1-only
- 1 public-domain

Trivy Licenses (Node.js):
- 1 0BSD
- 12 Apache-2.0
- 5 BlueOak-1.0.0
- 12 BSD-2-Clause
- 1 (BSD-2-Clause OR MIT OR Apache-2.0)
- 14 BSD-3-Clause
- 1 GPL-2.0-only
- 143 ISC
- 19 LGPL-3.0-only
- 878 MIT
- 2 (MIT OR Apache-2.0)
- 1 (MIT OR WTFPL)
- 2 MIT/X11
- 2 MPL-2.0
- 2 Unlicense
- 1 WTFPL
- 1 WTFPL OR ISC
- 1 (WTFPL OR MIT)

Same with licences: both tools produced similar amounts of data. It should be noted though that Trivy classifies licenses on package sources too 

# Task 2
In `labs/submission4.md`, document:
- **SCA Tool Comparison** - vulnerability detection capabilities
- **Critical Vulnerabilities Analysis** - top 5 most critical findings with remediation
- **License Compliance Assessment** - risky licenses and compliance recommendations
- **Additional Security Features** - secrets scanning results

## Vulnerability detection capabilities

=== Vulnerability Analysis ===

Grype Vulnerabilities by Severity:
- 23 Critical
- 117 High
- 8 Low
- 62 Medium
- 12 Negligible

Trivy Vulnerabilities by Severity:
- 22 CRITICAL
- 105 HIGH
- 21 LOW
- 67 MEDIUM


Tool Comparison:
- Syft found 32 unique license types
- Trivy found 28 unique license types

## Top-5 Vulnerabilities
|NAME|                  INSTALLED|          FIXED IN|                            TYPE|    VULNERABILITY|        SEVERITY|    EPSS|           RISK|   
|-|-|-|-|-|-|-|-|
|ip|                    2.0.1| |                                                  npm|     GHSA-2p57-rm9w-gvfp|  High|        84.6% (99th)|   66.0   |
|vm2|                   3.9.17|         |    3.9.18                              npm  |   GHSA-whpj-8f3w-67p5|  Critical|    70.0% (98th)|   65.8   |
|vm2|                   3.9.17|          |                                       npm |    GHSA-g644-9gfx-q4q4 | Critical|    36.1% (97th)|   33.9   |
|jsonwebtoken|          0.1.0|              4.2.2|                               npm |    GHSA-c7hr-j4mj-j2w6 | Critical|    37.5% (97th)|   33.7   |
|jsonwebtoken|          0.4.0|              4.2.2 |                              npm |    GHSA-c7hr-j4mj-j2w6 | Critical|    37.5% (97th)|   33.7  |

## Secrets details
```text
/juice-shop/build/lib/insecurity.js (secrets)
=============================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: AsymmetricPrivateKey (private-key)
════════════════════════════════════════
Asymmetric Private Key
────────────────────────────────────────
 /juice-shop/build/lib/insecurity.js:47 (offset: 2835 bytes) (added by 'COPY --chown=65532:0 /juice-shop . # bui')
────────────────────────────────────────
  45   const z85 = __importStar(require("z85"));
  46   exports.publicKey = node_fs_1.default ? node_fs_1.default.readFileSync('encryptionkeys/jwt.pub', 'ut
  47 [ ----BEGIN RSA PRIVATE KEY-----****************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END RSA PRIVATE
  48   const hash = (data) => node_crypto_1.default.createHash('md5').update(data).digest('hex');
────────────────────────────────────────



/juice-shop/frontend/src/app/app.guard.spec.ts (secrets)
========================================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

MEDIUM: JWT (jwt-token)
════════════════════════════════════════
JWT token
────────────────────────────────────────
 /juice-shop/frontend/src/app/app.guard.spec.ts:38 (offset: 1466 bytes) (added by 'COPY --chown=65532:0 /juice-shop . # bui')
────────────────────────────────────────
  36   
  37     it('returns payload from decoding a valid JWT', inject([LoginGuard], (guard: LoginGuard) => {
  38 [ ocalStorage.setItem('token', '***********************************************************************************************************************************************************')
  39       expect(guard.tokenDecode()).toEqual({
────────────────────────────────────────



/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts (secrets)
====================================================================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

MEDIUM: JWT (jwt-token)
════════════════════════════════════════
JWT token
────────────────────────────────────────
 /juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:61 (offset: 2220 bytes) (added by 'COPY --chown=65532:0 /juice-shop . # bui')
────────────────────────────────────────
  59   
  60     xit('should set Last-Login IP from JWT as trusted HTML', () => { // FIXME Expected state seems to 
  61 [ ocalStorage.setItem('token', '*******************************************************************************************************************************')
  62       component.ngOnInit()
────────────────────────────────────────



/juice-shop/lib/insecurity.ts (secrets)
=======================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: AsymmetricPrivateKey (private-key)
════════════════════════════════════════
Asymmetric Private Key
────────────────────────────────────────
 /juice-shop/lib/insecurity.ts:23 (offset: 860 bytes) (added by 'COPY --chown=65532:0 /juice-shop . # bui')
────────────────────────────────────────
  21   
  22   export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-publi
  23 [ ----BEGIN RSA PRIVATE KEY-----****************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-----END RSA PRIVATE
  24   
────────────────────────────────────────
```

# Task 3
In `labs/submission4.md`, document:
- **Accuracy Analysis** - package detection and vulnerability overlap quantified
- **Tool Strengths and Weaknesses** - practical observations from your testing
- **Use Case Recommendations** - when to choose Syft+Grype vs Trivy
- **Integration Considerations** - CI/CD, automation, and operational aspects

## Accuracy analysis
**Package Detection Comparison**
- Packages detected by both tools: 1126
- Packages only detected by Syft: 13
- Packages only detected by Trivy: 9

**Vulnerability Detection Overlap**
- CVEs found by Grype: 152
- CVEs found by Trivy: 144
- Common CVEs: 42

## Tools Strengths and Weaknesses
**Syft + Grype** - very in-depth cataloger coverage in Syft, easy formatting, but Syft doesn't scan for vulnerabilities itself, hence the requirement of Grype, which isn't bad in itself, but may cause some mismatch

**Trivy** - all-in-one tool, does everything, and additionally can scan Kubernetes
