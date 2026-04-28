# DefectDojo Setup Evidence - Lab 10

- Date: 2026-04-27
- Upstream cloned locally: `labs/lab10/setup/django-DefectDojo`
- Upstream remote: `https://github.com/DefectDojo/django-DefectDojo.git`
- Upstream commit used: `1a8b491`
- Compose compatibility: `./docker/docker-compose-check.sh` reported a supported Docker Compose version.
- Docker versions:
  - Docker: `29.4.0`
  - Docker Compose: `v5.1.1`
- DefectDojo UI/API: `http://localhost:8081`
- Port note: `localhost:8080` was already in use by a local `kubectl` port-forward, so `DD_PORT=8081` was used.
- Initializer completed successfully and printed the generated admin password in local container logs.
- Sensitive values such as the admin password and API token are intentionally not stored in this artifact.

Container status was captured in `labs/lab10/report/docker-compose-ps.txt`.

