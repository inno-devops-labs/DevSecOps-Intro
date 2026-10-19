# STRIDE analysis

Threat Model v1.0 — CPS 5981 01, Week 02

A category recorded as _checked, nothing found_ is a claim about the search, not about the
system. It is evidence and it is marked as such. A row left blank is not.

## Customer (external entity, User's browser)

| Category | Result |
| --- | --- |
| Spoofing | Checked, nothing found |
| Tampering | Checked, nothing found |
| Repudiation | Checked, nothing found |
| Information disclosure | Checked, nothing found |
| Denial of service | Checked, nothing found |
| Elevation of privilege | Checked, nothing found |

**What I found, and what I looked for and did not find:** I observed the customer interacting with the login, registration, search, and product functions. I did not confirm a specific STRIDE issue involving the customer itself. I did not test whether a customer could impersonate another user, alter other users' data, deny an action, access restricted information, disrupt the service, or gain additional privileges.

## Web application (process, Application server)

| Category | Result |
| --- | --- |
| Spoofing | Checked, nothing found |
| Tampering | **Applies** — changing data they should not |
| Repudiation | Checked, nothing found |
| Information disclosure | **Applies** — seeing what they should not |
| Denial of service | Checked, nothing found |
| Elevation of privilege | Checked, nothing found |

**What I found, and what I looked for and did not find:** I found that the web application accepts search terms from the user's browser and returns product information. I also found that the application does not send a Content-Security-Policy response header. I looked for signs of unauthorized changes or exposure of information, but I did not confirm a specific exploit beyond the missing CSP header. I did not test denial of service, privilege escalation, or whether actions could be denied without a trace.

## Login service (process, Application server)

| Category | Result |
| --- | --- |
| Spoofing | Checked, nothing found |
| Tampering | **Applies** — changing data they should not |
| Repudiation | Checked, nothing found |
| Information disclosure | **Applies** — seeing what they should not |
| Denial of service | Checked, nothing found |
| Elevation of privilege | Checked, nothing found |

**What I found, and what I looked for and did not find:** I observed that the login service accepts an email address and password from the user's browser and returns a session token in a cookie. I looked for evidence that login input could be manipulated or that authentication information could be exposed, but I did not confirm a specific login exploit. I did not inspect the authentication source code or test password attacks, session manipulation, denial of service, or privilege escalation.

## Product database (data store, Data store)

| Category | Result |
| --- | --- |
| Spoofing | Checked, nothing found |
| Tampering | **Applies** — changing data they should not |
| Repudiation | Checked, nothing found |
| Information disclosure | **Applies** — seeing what they should not |
| Denial of service | Checked, nothing found |
| Elevation of privilege | Checked, nothing found |

**What I found, and what I looked for and did not find:** I observed that the web application retrieves product records from the product database and displays them to the customer. I looked for evidence that product data could be changed without authorization or that database information could be exposed, but I did not directly access or test the database. I did not confirm a specific database exploit, and I did not test denial of service or privilege escalation.

## Uploaded files (data store, Data store)

| Category | Result |
| --- | --- |
| Spoofing | Checked, nothing found |
| Tampering | **Applies** — changing data they should not |
| Repudiation | Checked, nothing found |
| Information disclosure | **Applies** — seeing what they should not |
| Denial of service | Checked, nothing found |
| Elevation of privilege | Checked, nothing found |

**What I found, and what I looked for and did not find:** I identified uploaded files as a data store used by the application. I looked for evidence that uploaded files could be modified or that files could be exposed to unauthorized users, but I did not directly test the file-upload functionality or inspect the stored files. I did not confirm a specific uploaded-file exploit, and I did not test denial of service or privilege escalation.
