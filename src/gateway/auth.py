"""FastAPI dependencies for API-key authentication and scope checks.

Clients send:  Authorization: Bearer agw_<prefix>_<secret>

- 401 when the key is missing, malformed, unknown, wrong, revoked or expired.
  The response is identical in every case; the real reason goes to the audit log.
- 403 when the key is valid but lacks the scope the route needs.
"""

from fastapi import Depends, HTTPException, Request, status

from .audit import audit
from .keys import ApiKey, KeyStore, parse_key

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or missing API key.",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_store(request: Request) -> KeyStore:
    return request.app.state.store


def require_api_key(request: Request, store: KeyStore = Depends(get_store)) -> ApiKey:
    client = request.client.host if request.client else None
    header = request.headers.get("authorization", "")
    scheme, _, raw_key = header.partition(" ")
    raw_key = raw_key.strip()
    if scheme.lower() != "bearer" or not raw_key:
        audit("auth.failure", reason="missing", path=request.url.path, client=client)
        raise _UNAUTHORIZED

    key, reason = store.verify(raw_key)
    if key is None:
        audit("auth.failure", reason=reason, key_prefix=parse_key(raw_key),
              path=request.url.path, client=client)
        raise _UNAUTHORIZED

    audit("auth.success", key_prefix=key.prefix, path=request.url.path, client=client)
    return key


def require_scope(scope: str):
    """Dependency factory: require a valid key that carries `scope`."""

    def checker(request: Request, key: ApiKey = Depends(require_api_key)) -> ApiKey:
        if not key.has_scope(scope):
            audit("auth.forbidden", key_prefix=key.prefix, scope=scope, path=request.url.path)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing scope: {scope}")
        return key

    return checker
