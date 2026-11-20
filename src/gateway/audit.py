"""Audit log: one JSON line per security-relevant event.

Never log the raw key. The key prefix is enough to identify which key was used.
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("gateway.audit")


def audit(event: str, **fields) -> None:
    record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
    logger.info(json.dumps(record, sort_keys=True))
