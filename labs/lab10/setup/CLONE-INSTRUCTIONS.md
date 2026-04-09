# DefectDojo local clone (Lab 10)

Upstream repository (not committed to the course fork by default — large tree):

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo
./docker/docker-compose-check.sh || true
docker compose build
docker compose up -d
docker compose ps
```

- UI: `http://localhost:8080`
- **Admin password:** printed by the `initializer` service — `docker compose logs initializer | grep "Admin password:"`
- Optional: create an API token for automation — `docker compose exec -T uwsgi python manage.py drf_create_token admin`

See `compose-ps.txt` in this directory for a sample `docker compose ps` capture after a successful start.
