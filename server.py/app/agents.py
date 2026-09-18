"""
Agent identity: per-agent API key lookup and the `verify_agent` dependency
used to authenticate incoming monitoring-agent requests (/register, /ingest).
"""

import sqlite3
import time

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import config
from .db import _hash
from .security import _check_rate_limit

def _lookup_key(raw_key: str) -> sqlite3.Row | None:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM api_keys WHERE key_hash=? AND enabled=1", (_hash(raw_key),)
    ).fetchone()
    if row:
        conn.execute("UPDATE api_keys SET last_seen=? WHERE key_hash=?",
                     (int(time.time()), _hash(raw_key)))
        conn.commit()
    conn.close()
    return row

_bearer_scheme = HTTPBearer()

def verify_agent(credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
                 request: Request = None) -> sqlite3.Row:
    """FastAPI dependency: validate an agent's bearer API key, updating last_seen."""
    agent = _lookup_key(credentials.credentials)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key.")
    # Only rate-limit non-ingest endpoints — ingest is naturally throttled by interval_seconds
    if request and not request.url.path.startswith("/ingest"):
        _check_rate_limit(credentials.credentials)
    return agent
