import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.keys import KeyStore


@pytest.fixture
def store(tmp_path):
    return KeyStore(str(tmp_path / "test.db"))


@pytest.fixture
def app(store):
    return create_app(store)


@pytest.fixture
def client(app):
    return TestClient(app)


def bearer(raw_key: str) -> dict:
    return {"Authorization": f"Bearer {raw_key}"}
