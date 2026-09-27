#!/usr/bin/env python3
"""Run ZAP with a verified lab-only token; retain evidence without the token."""
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
RESULTS = ROOT / "labs/lab5/results"
BASE = "http://127.0.0.1:3000"


def request(path, token=None, data=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
        headers["Cookie"] = "token=" + token
    req = urllib.request.Request(BASE + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def identity(token):
    status, body = request("/rest/user/whoami", token)
    user = json.loads(body).get("user", {})
    assert status == 200 and user.get("email") == "admin@juice-sh.op", body
    return {"status": status, "email": user["email"], "id": user.get("id")}


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    status, body = request("/rest/user/login", data=json.dumps({
        "email": "admin@juice-sh.op", "password": "admin123"
    }).encode())
    assert status == 200, body
    token = json.loads(body)["authentication"]["token"]
    evidence = {"before": identity(token), "reachability": []}
    for path in ["/rest/basket/1", "/api/Users/", "/profile",
                 "/rest/products/search?q=apple"]:
        anon, _ = request(path)
        auth, _ = request(path, token)
        evidence["reachability"].append({"path": path,
                                       "anonymous_status": anon,
                                       "authenticated_status": auth})
    evidence_path = RESULTS / "auth-evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2))
    env = dict(os.environ, ZAP_AUTH_HEADER_VALUE="Bearer " + token,
               ZAP_AUTH_HEADER_SITE="juice-shop", ZAP_AUTH_HEADER="Authorization")
    plan = RESULTS / "auth-run.yaml"
    template = ROOT / "labs/lab5/scripts/zap-auth-token.yaml"
    plan.write_text(template.read_text().replace("LAB_TOKEN_PLACEHOLDER", token))
    started = time.monotonic()
    try:
        with (RESULTS / "auth-scan.log").open("w") as log:
            result = subprocess.run([
                "docker", "run", "--rm", "--name", "lab5-zap-auth",
                "--network", "lab5-net", "--memory", "2g", "--cpus", "2",
                "-e", "_JAVA_OPTIONS=-Xmx512m",
                "-e", "ZAP_AUTH_HEADER_VALUE", "-e", "ZAP_AUTH_HEADER_SITE",
                "-e", "ZAP_AUTH_HEADER", "-v", f"{ROOT}/labs/lab5:/zap/wrk",
                "ghcr.io/zaproxy/zaproxy:stable", "zap.sh", "-cmd", "-autorun",
                "/zap/wrk/results/auth-run.yaml", "-port", "8090"
            ], env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        plan.unlink(missing_ok=True)
    evidence.update(elapsed_seconds=round(time.monotonic() - started, 2),
                    exit_code=result.returncode, after=identity(token))
    evidence_path.write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, indent=2))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
