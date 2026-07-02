\## Goal



This PR completes Lab 1 and documents the deployment and initial assessment of OWASP Juice Shop.



\## Changes



\* Added `submissions/lab1.md`

\* Deployed OWASP Juice Shop locally

\* Documented deployment details and security observations



\## Testing



Commands run:



```bash

docker ps

curl.exe -I http://127.0.0.1:3000

curl.exe -s http://127.0.0.1:3000/rest/admin/application-version

```



Observed output:



\* Container running successfully

\* HTTP 200 returned

\* Application version 20.0.0 confirmed



\## Artifacts \& Screenshots



\* `submissions/lab1.md`



\## Checklist



\* \[ ] Title is clear (`feat(labN): <topic>` style)

\* \[ ] No secrets/large temp files committed

\* \[ ] Submission file at `submissions/labN.md` exists



