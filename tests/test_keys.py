import sqlite3

import pytest

from gateway.keys import InvalidScopeError, hash_key, parse_key


def test_key_format(store):
    raw, key = store.create("agent", {"exec:run"})
    tag, prefix, secret = raw.split("_", 2)
    assert tag == "agw"
    assert prefix == key.prefix and len(prefix) == 8
    assert len(secret) >= 40


def test_raw_key_is_never_stored(store):
    raw, key = store.create("agent", {"exec:run"})
    conn = sqlite3.connect(store.db_path)
    dump = "\n".join(conn.iterdump())
    secret = raw.split("_", 2)[2]
    assert secret not in dump
    assert hash_key(raw) in dump


def test_verify_valid_key(store):
    raw, _ = store.create("agent", {"exec:run"})
    key, reason = store.verify(raw)
    assert reason == "ok"
    assert key.name == "agent"
    assert store.get(key.prefix).last_used_at is not None


@pytest.mark.parametrize("bad", ["", "nonsense", "agw_xyz_abc", "agw_12345678_", "abc_12345678_secret"])
def test_malformed_keys(store, bad):
    assert store.verify(bad) == (None, "malformed")
    assert parse_key(bad) is None


def test_wrong_secret_with_real_prefix(store):
    raw, key = store.create("agent", {"exec:run"})
    forged = f"agw_{key.prefix}_{'A' * 43}"
    assert store.verify(forged) == (None, "bad_secret")


def test_unknown_prefix(store):
    assert store.verify("agw_deadbeef_" + "A" * 43) == (None, "unknown_prefix")


def test_revoked_key(store):
    raw, key = store.create("agent", {"exec:run"})
    assert store.revoke(key.prefix) is True
    assert store.revoke(key.prefix) is False  # already revoked
    assert store.verify(raw) == (None, "revoked")


def test_expired_key(store):
    raw, key = store.create("agent", {"exec:run"}, expires_in_days=1)
    conn = sqlite3.connect(store.db_path)
    with conn:
        conn.execute("UPDATE api_keys SET expires_at = '2000-01-01T00:00:00+00:00' WHERE prefix = ?", (key.prefix,))
    assert store.verify(raw) == (None, "expired")


def test_scopes_are_validated(store):
    with pytest.raises(InvalidScopeError):
        store.create("agent", {"root"})
    with pytest.raises(InvalidScopeError):
        store.create("agent", set())


def test_admin_scope_implies_all(store):
    _, key = store.create("ops", {"admin"})
    assert key.has_scope("exec:run")
