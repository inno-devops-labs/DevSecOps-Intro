# Lab 1 — Deploy OWASP Juice Shop & Set Up the Course Workflow

## Triage report

### Asset

* **Image:** `bkimminich/juice-shop:v20.0.0`
* **Image digest:** `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
* **Host OS:** Microsoft Windows 11 Home Single Language
* **Docker version:** `29.6.1, build 8900f1d`

### Deployment

The Juice Shop container was started using the official `bkimminich/juice-shop:v20.0.0` image.

```text
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

The application is available at:

```text
http://127.0.0.1:3000
```

The host port is bound to `127.0.0.1`, so the application is accessible only from the local machine. This is safer than binding the application to all network interfaces because Juice Shop is intentionally vulnerable and should not be exposed to other devices on the network.

The container does not use an explicit restart policy.

### Health

The container was running successfully:

```text
NAMES        STATUS          PORTS
juice-shop   Up 20 seconds   127.0.0.1:3000->3000/tcp
```

The application returned HTTP `200 OK` when accessed through the local web interface.

Application version:

```text
{"version":"20.0.0"}
```

Product count:

```text
46
```

### Surface

The following application areas were inspected:

* **Login and Registration:** the Account menu provides login and registration functionality.
* **Products:** the main page exposes the product catalogue, and individual products can be opened to inspect their details and related requests.
* **Account/Admin:** the Account area exposes user-related functionality. Administrative functionality was also checked as part of the application surface review.
* **Console:** browser developer tools were checked for client-side errors and warnings.
* **Local Storage and Cookies:** the browser Application panel was inspected for locally stored application and authentication-related data.

The product and review functionality was also observed through the browser Network panel to identify the API requests made by the frontend.

### Headers

The following command was used to inspect the HTTP response headers:

```text
curl -sI http://127.0.0.1:3000
```

The observed security-related headers were:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
```

The following headers were not present in the observed response:

* `Content-Security-Policy`
* `Strict-Transport-Security`

Therefore:

| Header                      | Status  |
| --------------------------- | ------- |
| `Content-Security-Policy`   | Missing |
| `Strict-Transport-Security` | Missing |
| `X-Content-Type-Options`    | Present |
| `X-Frame-Options`           | Present |

Missing security headers represent a security misconfiguration because they remove browser-level protections that can reduce the impact of certain attacks.

### Top 3 risks

#### 1. Missing security headers — Security Misconfiguration

The application does not provide all of the expected security headers, including `Content-Security-Policy` and `Strict-Transport-Security`. Missing browser security controls can increase the impact of client-side attacks and reduce the application's defensive security posture.

**OWASP Top 10:2025:** A02 — Security Misconfiguration.

#### 2. Publicly accessible application API — Broken Access Control

The frontend communicates with application API endpoints for products and related functionality. API endpoints that expose application functionality without requiring an authenticated identity can increase the attack surface and may allow unauthorized users to access functionality or data.

**OWASP Top 10:2025:** A01 — Broken Access Control.

#### 3. Client-side authentication data — Injection

Authentication-related information stored in browser-accessible storage can increase the impact of a successful cross-site scripting attack if malicious JavaScript is able to read that information. The risk depends on the exact storage mechanism and the type of authentication data stored by the application.

**OWASP Top 10:2025:** A05 — Injection.

## PR template

**File path:**

```text
.github/PULL_REQUEST_TEMPLATE.md
```

The template contains the required sections:

* Goal
* Changes
* Testing
* Artifacts & Screenshots

The required checklist contains:

* [ ] PR title follows `feat(labN): <topic>`
* [ ] No secrets or large temporary files are committed
* [ ] `submissions/labN.md` exists

**Draft PR:** `<insert draft PR URL here>`

## GitHub community

Stars are useful to open-source maintainers because they provide a visible indication of interest in a project and can help demonstrate the project's popularity. Following course staff and classmates makes it easier to keep track of project updates and coordinate work in team projects.

## Bonus: CI smoke test

Not implemented.
