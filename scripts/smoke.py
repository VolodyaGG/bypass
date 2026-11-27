"""Run the public demo's main flow against an actual HTTP server."""

import http.cookiejar
import json
import os
import urllib.error
import urllib.parse
import urllib.request

base = os.environ.get("BYPASS_URL", "http://127.0.0.1:18000").rstrip("/")
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def request(path, fields=None):
    data = urllib.parse.urlencode(fields).encode() if fields is not None else None
    return opener.open(base + path, data=data, timeout=180)


assert json.load(request("/api/health")) == {"status": "ok"}
request(
    "/login",
    {
        "profile": os.environ.get("BYPASS_PROFILE", "reviewer"),
        "password": os.environ["BYPASS_PASSWORD"],
    },
).close()
assert "deploy-journal" in request("/").read().decode()
try:
    request(
        "/api/deploy/demo", {"payload": json.dumps({"ip": "", "protocols": {"hysteria2": True}})}
    )
    raise AssertionError("Empty target accepted")
except urllib.error.HTTPError as error:
    assert error.code == 422
try:
    request("/api/deploy", {"payload": "{}"})
    raise AssertionError("Real deployment exposed")
except urllib.error.HTTPError as error:
    assert error.code == 403
job = json.load(
    request(
        "/api/deploy/demo",
        {
            "payload": json.dumps(
                {
                    "ip": "203.0.113.10",
                    "domain": "vpn.example.test",
                    "protocols": {"hysteria2": True},
                    "runtime": "native",
                }
            )
        },
    )
)
stream = request("/api/deploy/stream/" + job["job_id"]).read().decode()
assert '"status": "success"' in stream, "Demo did not succeed"
assert "idempotence" in stream and "verify" in stream
request("/logout", {}).close()
assert request("/").geturl().endswith("/login")
print("Smoke passed: login, validation, Molecule, SSE, logout, public API boundary")
