## **Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile** 

## **Task 1: Baseline Threat Model** 

## **Risk count by severity** 

|Severity|Count|
|---|---|
|Critical|0|
|High|0|
|Elevated|4|
|Medium|14|
|Low|5|
|**Total**|**23**|



## **Top 5 risks** 

1. **unencrypted-communication** — Unencrypted communication between User 
Browser and Juice Shop Application transferring authentication data; 
severity: Elevated; asset: user-browser. 

2. **unencrypted-communication** — Unencrypted communication between 
Reverse Proxy and Juice Shop Application; severity: Elevated; asset: 
reverse-proxy. 

3. **missing-authentication** — Missing authentication on communication 
link "To App" between Reverse Proxy and Juice Shop Application; severity: 
Elevated; asset: juice-shop. 

4. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice 
Shop Application; severity: Elevated; asset: juice-shop. 

5. **unnecessary-technical-asset** — Unnecessary Technical Asset named 
Persistent Storage; severity: Low; asset: persistent-storage. 

## **STRIDE mapping** 

- Risk 1: **I (Information Disclosure)** — credentials and session 
information can be intercepted over unencrypted communication. 

- Risk 2: **I (Information Disclosure)** — traffic between proxy and 
application can expose sensitive information to attackers. 

- Risk 3: **S (Spoofing), E (Elevation of Privilege)** — missing 
authentication allows unauthorized entities to impersonate trusted 
components and gain access. 

- Risk 4: **T (Tampering), E (Elevation of Privilege)** — malicious 
scripts can alter application behaviour and potentially escalate 
privileges. 

- Risk 5: **T (Tampering)** — unnecessary assets increase the attack 
surface and opportunities for compromise. 

## **Trust boundary observation** 

The communication link between User Browser and Juice Shop Application 
crosses the Internet trust boundary. In the baseline model this traffic 
used HTTP and transferred authentication-related data. 

1 

Attackers positioned on the network could intercept or modify traffic, 
making this communication path an attractive target. 

## **Task 2: Secure Variant & Diff** 

## **Risk count comparison** 

|Severity|Baseline|Secure|Δ|
|---|---|---|---|
|Critical|0|0|0|
|High|0|0|0|
|Elevated|4|2|-2|
|Medium|14|13|-1|
|Low|5|5|0|
|**Total**|**23**|**20**|**-3**|



## **Which rules are gone in the secure variant?** 

1. **unencrypted-communication** — fixed by changing Browser → 
Application communication from HTTP to HTTPS. 

2. **unencrypted-communication** — fixed by changing Reverse Proxy → 
Application communication from HTTP to HTTPS. 

3. **unencrypted-communication related findings** — mitigated through 
encrypted communications and encrypted storage configuration. 

## **Which rules are still there in the secure variant?** 

## **cross-site-scripting** 

The secure variant introduced transport encryption and encrypted storage, 
but it did not modify the application's input validation or output 
encoding. Therefore, XSS vulnerabilities can still exist in the 
application logic. 

## **missing-waf** 

No Web Application Firewall was added to the architecture. While HTTPS 
protects confidentiality and integrity of data in transit, it does not 
provide application-layer attack filtering. 

## **Honesty check** 

No, the total number of risks did not decrease by more than 50%. The risk 
count decreased from 23 to 20 (approximately 13%). This demonstrates that 
enabling HTTPS and encryption is relatively inexpensive and effective 
against specific threats, but many architectural and application-security 
risks remain. Eliminating the remaining findings would require stronger 
authentication mechanisms, network segmentation, secure development 
practices, WAF deployment, and additional infrastructure controls. 

2 

## **Bonus Task: Auth Flow Threat Model** 

## **Risk count** 

|Severity|Count|
|---|---|
|Critical|0|
|High|1|
|Elevated|9|
|Medium|18|
|Low|9|
|**Total**|**37**|



## **Three auth-specific risks (NOT in the baseline model's top 5)** 

## **1. sql-nosql-injection** 

- STRIDE: **T (Tampering), E (Elevation of Privilege)** 

- 

- Mitigation: Use parameterized queries and prepared statements for all 
database access. Validate and sanitize user input before processing 
authentication requests. 

## **2. missing-authentication-second-factor** 

- STRIDE: **S (Spoofing), E (Elevation of Privilege)** 

- 

- Mitigation: Require multi-factor authentication for administrative 
accounts and sensitive operations. Use TOTP, hardware tokens, or 
push-based verification. 

## **3. missing-identity-provider-isolation** 

- STRIDE: **S (Spoofing), E (Elevation of Privilege)** 

- 

- Mitigation: Isolate identity-related components into dedicated protected 
network segments. Restrict communication paths and enforce least-privilege 
access controls. 

## **Reflection** 

The focused authentication model exposed risks that were not visible in 
the broader architecture model. In particular, authentication-specific 
issues such as SQL injection in credential lookups, missing MFA, and 
insufficient isolation of identity services became much more apparent. 
This demonstrates that feature-level threat models can identify security 
weaknesses that architecture-level models may overlook. 

3 


