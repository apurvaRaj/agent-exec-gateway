"""HTTP API.

Run with:  uvicorn gateway.app:create_app --factory
"""

import logging

from fastapi import Depends, FastAPI

from . import __version__
from .audit import logger as audit_logger
from .auth import require_api_key
from .config import Settings
from .keys import ApiKey, KeyStore


def _setup_audit_logging() -> None:
    if not audit_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        audit_logger.addHandler(handler)
        audit_logger.setLevel(logging.INFO)


def create_app(store: KeyStore | None = None) -> FastAPI:
    if store is None:
        store = KeyStore(Settings.from_env().db_path)
    _setup_audit_logging()

    app = FastAPI(title="Agent Execution Gateway", version=__version__)
    app.state.store = store

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/v1/whoami")
    def whoami(key: ApiKey = Depends(require_api_key)) -> dict:
        return {
            "key_prefix": key.prefix,
            "name": key.name,
            "scopes": sorted(key.scopes),
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
        }

    return app
