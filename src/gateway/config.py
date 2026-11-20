"""Settings read from environment variables."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_path: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(db_path=os.environ.get("GATEWAY_DB_PATH", "gateway.db"))
