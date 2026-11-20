"""Admin CLI for API keys.

  agw-keys create --name "notebook-agent" --scopes exec:run exec:read [--expires-days 90]
  agw-keys list
  agw-keys revoke <prefix>
"""

import argparse
import sys

from .config import Settings
from .keys import KNOWN_SCOPES, InvalidScopeError, KeyStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agw-keys", description="Manage gateway API keys.")
    parser.add_argument("--db", default=Settings.from_env().db_path, help="SQLite database path")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="create a key (the secret is shown once)")
    create.add_argument("--name", required=True)
    create.add_argument("--scopes", nargs="+", required=True, help=f"any of: {' '.join(sorted(KNOWN_SCOPES))}")
    create.add_argument("--expires-days", type=int, default=None)

    sub.add_parser("list", help="list keys (never shows secrets)")

    revoke = sub.add_parser("revoke", help="revoke a key by prefix")
    revoke.add_argument("prefix")

    args = parser.parse_args(argv)
    store = KeyStore(args.db)

    if args.command == "create":
        try:
            raw_key, key = store.create(args.name, set(args.scopes), args.expires_days)
        except InvalidScopeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(raw_key)
        print(f"Created key {key.prefix} ({key.name}). Store it now: it cannot be shown again.", file=sys.stderr)
        return 0

    if args.command == "list":
        for k in store.list():
            status = "revoked" if k.revoked_at else "active"
            expires = k.expires_at.date().isoformat() if k.expires_at else "never"
            last = k.last_used_at.isoformat(timespec="seconds") if k.last_used_at else "never"
            print(f"{k.prefix}  {status:7}  {k.name}  scopes={','.join(sorted(k.scopes))}  "
                  f"expires={expires}  last_used={last}")
        return 0

    if args.command == "revoke":
        if store.revoke(args.prefix):
            print(f"Revoked {args.prefix}.")
            return 0
        print(f"error: no active key with prefix {args.prefix}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
