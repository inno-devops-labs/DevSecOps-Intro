## Goal

<!-- One sentence: what does this PR deliver? -->
<!-- e.g. "Deploys OWASP Juice Shop and produces the Lab 1 triage report." -->

## Changes

<!-- Bullet list of artifacts added or modified in this PR -->

- [ ] `submissions/labN.md` — submission report
- [ ] `.github/PULL_REQUEST_TEMPLATE.md` — this template (Lab 1 only)
- [ ] `.github/workflows/` — CI workflow(s), if applicable

## Testing

<!-- How did you verify that your changes work? Include the exact commands you ran and the observed output. -->

```bash
# Example:
docker ps --filter name=juice-shop --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:3000
```

**Observed output:**

```
<paste output here>
```

## Artifacts & Screenshots

<!-- Link to files added in this PR and embed screenshots where useful -->

- [Submission report](submissions/labN.md)

<!-- Embed screenshots below (drag & drop or paste): -->

---

## Checklist

- [ ] Title is clear (`feat(labN): <topic>` style)
- [ ] No secrets or large temp files committed
- [ ] Submission file at `submissions/labN.md` exists
