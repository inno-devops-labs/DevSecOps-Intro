# Goal

Briefly describe what this PR delivers.

Example:

* Complete Lab 1 deployment and triage report for OWASP Juice Shop.

---

# Changes

* Added `submissions/lab1.md`
* Added `.github/PULL_REQUEST_TEMPLATE.md`
* Added supporting screenshots and documentation

---

# Testing

Commands executed:

```bash
docker ps
curl -I http://127.0.0.1:3000
curl -s http://127.0.0.1:3000/rest/admin/application-version
```

Observed results:

* Juice Shop container running
* Homepage returned HTTP 200
* Application version endpoint returned expected JSON

---

# Artifacts & Screenshots

Artifacts:

* `submissions/lab1.md`

Screenshots:

* Docker container running
* Juice Shop homepage
* Login page
* Browser DevTools (Network tab)
* HTTP response headers

---

## Checklist

* [ ] Title is clear (`feat(labN): <topic>`)
* [ ] No secrets/large temp files committed
* [ ] Submission file at `submissions/labN.md` exists

