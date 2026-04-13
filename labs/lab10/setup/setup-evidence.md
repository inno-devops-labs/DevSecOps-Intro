# DefectDojo Setup Evidence — Lab 10

- Date: `2026-04-13`
- URL: `http://localhost:8080`
- Admin username: `admin`
- Admin password evidence: see `admin-password-masked.txt` for the masked initializer output.
- Compose status evidence: see `compose-ps.txt`.

## Context Created

- Product Type: `Engineering`
- Product: `Juice Shop`
- Engagement: `Labs Security Testing`

## Notes

- DefectDojo was started from the upstream `django-DefectDojo` Docker Compose stack under `labs/lab10/setup/django-DefectDojo/`.
- The local macOS environment required bypassing loopback proxying with `NO_PROXY='*'` for `localhost:8080`.
- The provided import helper was updated for macOS Bash compatibility and to choose the correct parser names on this DefectDojo release.
- The saved ZAP report from Lab 5 was JSON, while the `ZAP Scan` parser on this instance expects XML, so the final workflow converts the JSON report to `labs/lab10/imports/zap-report-noauth.xml` before import.
