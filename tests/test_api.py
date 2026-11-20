import json
import logging

from fastapi import Depends

from gateway.auth import require_scope
from conftest import bearer


def test_health_needs_no_key(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_missing_key_is_401(client):
    r = client.get("/v1/whoami")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_wrong_scheme_is_401(client, store):
    raw, _ = store.create("agent", {"exec:run"})
    r = client.get("/v1/whoami", headers={"Authorization": f"Basic {raw}"})
    assert r.status_code == 401


def test_valid_key(client, store):
    raw, key = store.create("notebook-agent", {"exec:run", "exec:read"})
    r = client.get("/v1/whoami", headers=bearer(raw))
    assert r.status_code == 200
    body = r.json()
    assert body == {"key_prefix": key.prefix, "name": "notebook-agent",
                    "scopes": ["exec:read", "exec:run"], "expires_at": None}
    assert raw.split("_", 2)[2] not in r.text


def test_all_failures_look_the_same(client, store):
    raw, key = store.create("agent", {"exec:run"})
    store.revoke(key.prefix)
    cases = [raw, "garbage", f"agw_{key.prefix}_{'A' * 43}", "agw_deadbeef_" + "A" * 43]
    bodies = {client.get("/v1/whoami", headers=bearer(c)).text for c in cases}
    assert len(bodies) == 1


def test_scope_enforced(app, client, store):
    @app.post("/v1/test-exec")
    def run(key=Depends(require_scope("exec:run"))):
        return {"ok": True}

    reader, _ = store.create("reader", {"exec:read"})
    runner, _ = store.create("runner", {"exec:run"})
    admin, _ = store.create("ops", {"admin"})
    assert client.post("/v1/test-exec", headers=bearer(reader)).status_code == 403
    assert client.post("/v1/test-exec", headers=bearer(runner)).status_code == 200
    assert client.post("/v1/test-exec", headers=bearer(admin)).status_code == 200


def test_audit_log_has_prefix_but_never_secret(client, store, caplog):
    raw, key = store.create("agent", {"exec:run"})
    secret = raw.split("_", 2)[2]
    with caplog.at_level(logging.INFO, logger="gateway.audit"):
        client.get("/v1/whoami", headers=bearer(raw))
        client.get("/v1/whoami", headers=bearer(f"agw_{key.prefix}_wrong"))
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == "gateway.audit"]
    assert [e["event"] for e in events] == ["auth.success", "auth.failure"]
    assert events[1]["reason"] == "bad_secret" and events[1]["key_prefix"] == key.prefix
    assert all(secret not in r.getMessage() for r in caplog.records)
