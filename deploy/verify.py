"""Verify a deployed napibox. Prints IDs of harmless test uploads for cleanup."""
import json
import re
import sys
import base64
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

base = sys.argv[1].rstrip("/")
http = build_opener(ProxyHandler({}))
created_ids = []
authorization = None
if len(sys.argv) > 2:
    credential = json.loads(Path(sys.argv[2]).read_text())
    assert credential["url"].rstrip("/") == base, "Credential origin mismatch"
    authorization = "Basic " + base64.b64encode((credential["username"] + ":" + credential["password"]).encode()).decode()


def remember_link(link):
    identifier = link.removeprefix("/")
    assert len(identifier) <= 10
    assert re.fullmatch(r"[a-z]{3,7}[0-9]{3}", identifier)
    created_ids.append(identifier)


def request(path, data=None, headers=None):
    values = dict(headers or {})
    if authorization:
        values["Authorization"] = authorization
    return http.open(Request(base + path, data=data, headers=values), timeout=15)


try:
    with request("/") as response:
        assert response.status == 200
        page = response.read().decode()
        assert 'id="encrypt"' in page and 'id="message"' in page
        assert '350 МБ' in page
    plain = "napibox production deployment check\nПроверка UTF-8".encode()
    with request("/api/upload?name=napibox-deployment-check.txt", plain) as response:
        assert response.status == 201
        link = json.load(response)["url"]
        remember_link(link)
    with request(link) as response:
        assert response.read() == plain
        assert "attachment" in response.headers["Content-Disposition"]
    with request("/api/upload?name=napibox-deployment-message-check.txt&kind=message", plain) as response:
        assert response.status == 201
        message_link = json.load(response)["url"]
        remember_link(message_link)
    with request(message_link) as response:
        assert '<pre id="message-text">' + plain.decode() + '</pre>' in response.read().decode()
        assert response.headers.get("Content-Disposition") is None
    with request(
        "/api/upload?name=napibox-deployment-pin-check.txt&kind=message&encrypt=1",
        plain,
        {"X-Napibox-Pin": "0427"},
    ) as response:
        assert response.status == 201
        protected = json.load(response)["url"]
        remember_link(protected)
    with request(protected) as response:
        assert "Сообщение доступно по PIN-коду" in response.read().decode()
    try:
        request(protected, urlencode({"pin": "9999"}).encode())
        raise AssertionError("Wrong PIN accepted")
    except HTTPError as error:
        assert error.code == 401
    with request(protected, urlencode({"pin": "0427"}).encode()) as response:
        page = response.read().decode()
        assert '<pre id="message-text">' + plain.decode() + '</pre>' in page
        assert response.headers.get("Content-Disposition") is None
    print(json.dumps({"ok": True, "base": base, "created_ids": created_ids}))
except Exception:
    print(json.dumps({"ok": False, "created_ids": created_ids}))
    raise
