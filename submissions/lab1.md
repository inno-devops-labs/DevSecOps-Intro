# Lab 1 — OWASP Juice Shop deployment and triage

Date: 11.06.2026.

The browser inspection was completed using DevTools. Observations, screenshots, and the response body were recorded.

OWASP Juice Shop was deployed locally and inspected in a browser. A reusable PR template and a GitHub Actions smoke-test workflow were created, and the smoke-test script was verified locally.

## Triage report

### Asset

| Item | Observed value |
| --- | --- |
| Image tag | `bkimminich/juice-shop:v20.0.0` |
| Registry digest from image `RepoDigests` | `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` |
| Host OS | Microsoft Windows 11 Home, 25H2, 64-bit, version `10.0.26200`, build `26200.9445` |
| Docker Desktop | `4.90.0 (238679)` |
| Docker client / Engine | `29.7.2` / `29.7.2` |
| Docker context / server architecture | `desktop-linux` / `linux/amd64` |
| Container ID | `21e7925f41f8d2e61aa1e5dddf1d4cba18825cb2efc7dc023f93b71f9d9c27b1` |

Docker was installed outside PATH and its Engine was initially stopped. Docker Desktop was started, and its executable directory was added only to the command process's PATH, including the credential helper needed to pull the image. `jq` was unavailable, so the product JSON was parsed with PowerShell instead.

### Deployment

The following command was run after making the installed Docker CLI available in the terminal:

```powershell
$env:PATH = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin;$env:PATH"
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

The application was accessed at `http://127.0.0.1:3000/`.

The output of `docker ps` confirmed that the published port was bound to `127.0.0.1` only. This prevents direct access through the host's LAN interfaces and avoids exposing an intentionally vulnerable application to other devices on the network.

The default restart policy was checked with `docker inspect juice-shop --format '{{json .HostConfig.RestartPolicy}}'`:

```json
{"Name":"no","MaximumRetryCount":0}
```

The container does not automatically restart after it exits. After the initial inspection, the container was stopped with `docker stop juice-shop`, and the `exited` state was confirmed. The container and image were retained for later labs, and the application was reopened for the browser follow-up. The saved container can be resumed with `docker start juice-shop`.

### Health

The following commands were run, and their outputs were recorded:

```text
curl.exe -s -o NUL -w "HTTP %{http_code}\n" http://127.0.0.1:3000
HTTP 200

curl.exe -s http://127.0.0.1:3000/rest/admin/application-version
{"version":"20.0.0"}

(curl.exe -s http://127.0.0.1:3000/api/Products | ConvertFrom-Json).data.Count
46

docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
NAMES        STATUS          PORTS
juice-shop   Up 42 seconds   127.0.0.1:3000->3000/tcp

docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

`NUL` is the Windows equivalent of `/dev/null`. The outputs above were collected while the container was running, before it was stopped after the initial inspection.

### Surface

1. **Login and registration.** The anonymous Account menu contained Login at `/#/login`. The form contained email, password, a password visibility button, Remember me, password recovery, Google login, and a link to `/#/register`. Registration requested email, password, repeated password, a security question, and an answer; its hint stated that passwords must be 5–40 characters long and that the security question cannot be changed later. No account was created, and no credentials were submitted.
2. **Products.** The catalog displayed `1 – 15 of 46`, prices, stock notices, and Add to Basket buttons. Apple Juice (1000ml) was opened without authentication; its description, price `1.99¤`, and two reviews were displayed. The displayed review authors included `admin@juice-sh.op` and `basil@juice-sh.op`; helpful-review rating controls were disabled for the anonymous visitor.
3. **Admin or account area.** Only Login was found in the account menu; no administration entry appeared in the inspected anonymous navigation. The side menu exposed contact, AI chat, company information, photo wall, and tutorial links. The endpoint `/rest/admin/application-version` returned the version without authentication, which is metadata exposure rather than proof that administrative actions are accessible.
4. **Console errors.** The browser's captured warning/error log was checked after opening the product and again after inspecting registration; both checks returned `[]`. No warnings or errors were captured during those checks; this does not establish that all application flows are error-free. Separately, the curl request below produced an HTTP 500 response and the UI displayed the Error Handling challenge notification.
5. **Local Storage and cookies.** In DevTools, Application → Local Storage for `http://127.0.0.1:3000` was checked and found empty. The Cookies panel showed `language=en` and `welcomebanner_status=dismiss`, consistent with an English UI and a dismissed welcome banner. The screenshot contains names and values only. HttpOnly, Secure, SameSite, expiry, domain, and path were not captured, so no conclusions are drawn about those attributes. The earlier root HEAD response contained no `Set-Cookie`; that does not rule out JavaScript-created cookies.

**Anonymous review access and endpoint discrepancy.** The lab's example `/api/Products/1/reviews` returned HTTP 500, with `Unexpected path: /api/Products/1/reviews`. A direct request to `/rest/products/1/reviews` returned HTTP 200 and the same two reviews seen in the product dialog. Both requests were made with curl without cookies or an Authorization header. Reading these reviews therefore does not require authentication; public product reviews alone are not evidence of broken access control.

```text
curl.exe -s -w '\nHTTP %{http_code}\n' http://127.0.0.1:3000/rest/products/1/reviews
```

The following response excerpt was recorded:

```json
{"status":"success","data":[{"message":"One of my favorites!","author":"admin@juice-sh.op","product":1,"likesCount":0,"likedBy":[],"_id":"jT2TPJQGtw9sTGcuA","liked":true},{"message":"Great! We'll have an apple party. Everyone brings an apple and - STUFFS IT DOWN EACH OTHER'S THROAT!","author":"basil@juice-sh.op","product":1,"likesCount":0,"likedBy":[],"_id":"HC5Q7S422FX2CKe5C","liked":true}]}
```

The following request was captured in the Network panel after opening Apple Juice:

```text
Request URL: http://127.0.0.1:3000/rest/products/1/reviews
Request Method: GET
Status Code: 200 OK
Remote Address: 127.0.0.1:3000
Referrer Policy: strict-origin-when-cross-origin
```

The copied browser response had `status: "success"` and two reviews for product `1`, by `admin@juice-sh.op` and `basil@juice-sh.op`. Their messages matched the earlier curl response; the browser response IDs were `YB2HGn9eRjTNNCfKC` and `vgNw5PsZxMvtaKmoj`, respectively. Both had `likesCount: 0`, `likedBy: []`, and `liked: true`. These values were recorded in the later browser session, separately from the earlier curl capture above.

The Network screenshot shows the General section only, so it does not establish whether an Authorization or Cookie request header was sent. The earlier curl check without either header independently established that this endpoint permits anonymous review reads.

### Headers

The following output was recorded from `curl.exe -sI http://127.0.0.1:3000`:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Thu, 10 Sep 2026 12:16:17 GMT
ETag: W/"26af-1a08b3f5188"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Thu, 10 Sep 2026 12:16:48 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

| Required header | Observed status |
| --- | --- |
| `Content-Security-Policy` | Missing |
| `Strict-Transport-Security` | Missing |
| `X-Content-Type-Options` | Present: `nosniff` |
| `X-Frame-Options` | Present: `SAMEORIGIN` |

Missing protective headers map to A02:2025, Security Misconfiguration. HSTS is meaningful over HTTPS; adding it to this plain-HTTP localhost response alone would not secure transport.

### Top 3 risks

The following three risks were identified during triage; a full penetration test was not performed. The risks were mapped using the [OWASP Top 10:2025](https://owasp.org/Top10/2025/).

1. **Internal details disclosed on an unexpected route — A10:2025, Mishandling of Exceptional Conditions.** An anonymous GET to `/api/Products/1/reviews` produced HTTP 500 and exposed `Express ^4.22.1` plus stack frames including `/juice-shop/build/routes/angular.js:42:18` and `/juice-shop/build/lib/utils.js:225:26`. These details help an attacker fingerprint the implementation and plan further tests; unknown routes should return a controlled error while diagnostic stacks remain in server logs.
2. **Missing Content Security Policy — A02:2025, Security Misconfiguration.** The root response did not send a `Content-Security-Policy` header. This removes a browser defense that could limit the impact of injected content; the missing header does not itself prove an exploitable XSS flaw.
3. **Unencrypted application access — A04:2025, Cryptographic Failures.** The tested catalog and account forms were served over plain HTTP, without transport encryption on that access path. Loopback binding limits exposure in this lab, but reusing this deployment on a shared network would put credentials and session traffic at risk unless HTTPS were introduced.

## PR template

The file `.github/PULL_REQUEST_TEMPLATE.md` was created.

The template includes **Goal**, **Changes**, **Testing**, and **Artifacts & Screenshots**, plus a separate **Checklist** section with these items:

- The title follows `feat(labN): <topic>`.
- No secrets or large temporary files are committed.
- `submissions/labN.md` exists for this lab.

The template was published to the fork's default branch, `main`, in commit `d59c907ac57793551ddbea902feee8c8be28b0f2`. Then [test draft PR #1](https://github.com/etern1ty22/DevSecOps-Intro/pull/1) was opened from `feature/lab1` to `main` within `etern1ty22/DevSecOps-Intro`. Its description contains the unchanged template, including all four required sections, instructional comments, and three checklist items.

This PR demonstrates the template within the fork. It is separate from the final submission PR to the course repository, whose default-branch template controls its own PR form.

## GitHub community

Stars signal interest and appreciation to open-source maintainers and help others discover their work. Following instructors and classmates makes their public project activity easier to find and supports awareness of teammates' contributions.

Stars were added to the course repository and `simple-container-com/api`. The accounts `@Cre-eD`, `@Naghme98`, `@pierrepicaud`, and at least three classmates were followed.

## Bonus: CI smoke test

The file `.github/workflows/lab1-smoke.yml` was created.

The workflow uses `pull_request` targeting `main`, an `ubuntu-latest` runner, and workflow-level `permissions: contents: read`. It starts the required image on loopback, polls the version endpoint with `curl --silent --fail` for up to 60 seconds, accepts only HTTP 200, prints the response and elapsed time, and fails when the deadline expires. Failed jobs print container logs; cleanup stops the container.

`js-yaml`, already present in the running Juice Shop image, was used to parse the YAML and check the trigger, target branch, permissions, and runner. The polling script was extracted directly from the workflow, and its Bash syntax was checked successfully. That exact script was then run against the running local container; it exited 0 and printed:

```text
YAML parsed; PR trigger, main filter, read-only permissions and runner verified.
HTTP 200
{"version":"20.0.0"}
Ready after 0 seconds
```

The container was stopped, and the same polling script was run again. It reached its 60-second deadline and exited 1, confirming the failure path:

```text
Juice Shop did not return HTTP 200 within 60 seconds.
```

The zero-second readiness result above applies to an already-running local container, not a cold start in CI. The workflow structure was checked against the [GitHub Actions workflow syntax documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

GitHub Actions verification subsequently passed on [test draft PR #1](https://github.com/etern1ty22/DevSecOps-Intro/pull/1), for commit `3ba92e4b37fcfef0c82e21d69d624cb3a407ca14`:

- Run: [Lab 1 - Juice Shop smoke test #1](https://github.com/etern1ty22/DevSecOps-Intro/actions/runs/34528377621).
- Result: `completed`, `success`.
- Execution duration: approximately 14 seconds for the `smoke` job, measured from its first to last log timestamp (`20:46:41.128` to `20:46:55.073` UTC on 10 September 2026); this excludes queue time.
- The image was pulled on the runner, the version endpoint became ready after 2 seconds of polling, and container cleanup succeeded.

The following curl output excerpt was recorded from the [job log](https://github.com/etern1ty22/DevSecOps-Intro/actions/runs/34528377621/job/103042773299):

```text
HTTP 200
{"version":"20.0.0"}
Ready after 2 seconds
```
