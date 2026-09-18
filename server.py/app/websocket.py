"""
Live dashboard push channel.

`ws_manager` is the process-wide singleton that tracks authenticated
dashboard connections and broadcasts metric/alert updates to them. It is
driven from two places: the `/ws` route (connect/disconnect) and the sync
alerting/ingest code running on background threads (`broadcast_sync`).
"""

import asyncio
import json
import os
import threading
import time

from fastapi import WebSocket

from . import config

logger = config.logger.getChild("websocket")

class _WSConnection:
    """Metadata attached to each authenticated WebSocket connection."""
    __slots__ = ("ws", "user_id", "email", "is_superuser", "connected_at")

    def __init__(self, ws: WebSocket, user_id: str, email: str,
                 is_superuser: bool) -> None:
        self.ws           = ws
        self.user_id      = user_id
        self.email        = email
        self.is_superuser = is_superuser
        self.connected_at = int(time.time())


# ── JWT helper reused by the WebSocket auth path ─────────────────────────────
_JWT_ISSUER = os.getenv("SYSMON_JWT_ISSUER", "sysmon-server")

def _validate_ws_token(token: str) -> dict:
    """
    Decode and validate a JWT token for WebSocket auth.
    Returns a dict with user DB row fields.
    Raises ValueError with a descriptive message on any failure.

    Hardening applied (OWASP A02:2021):
    - Header inspected BEFORE decode: alg=none blocked explicitly
    - Only HS256 accepted — RS256 / ECDSA attacks blocked
    - exp / nbf automatically verified by python-jose
    - Audience verified manually (fastapi-users stores as list)
    - sub claim required and validated against DB
    - User approval + active status verified at connection time
    """
    from jose import jwt as _jwt, JWTError

    # ── 1. Inspect header BEFORE decoding ────────────────────────────────────
    try:
        header = _jwt.get_unverified_header(token)
    except JWTError as e:
        raise ValueError(f"JWT header parse error: {e}")

    alg = header.get("alg", "").lower()
    if alg in ("none", ""):
        raise ValueError("JWT alg=none is not allowed (CVE-2015-9235)")
    if header.get("alg") != "HS256":
        raise ValueError(f"JWT algorithm '{header.get('alg')}' not accepted — HS256 only")

    # ── 2. Decode with strict options ────────────────────────────────────────
    try:
        payload = _jwt.decode(
            token, config.JWT_SECRET,
            algorithms=["HS256"],
            options={
                "verify_aud": False,   # manual aud check below
                "verify_exp": True,    # always enforce expiration
                "verify_nbf": True,    # enforce not-before if present
            }
        )
    except JWTError as e:
        raise ValueError(f"JWT decode error: {e}")

    # ── 3. Audience check ────────────────────────────────────────────────────
    aud = payload.get("aud", [])
    if "fastapi-users:auth" not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError("wrong audience")

    # ── 4. Subject (user id) required ───────────────────────────────────────
    user_id = payload.get("sub")
    if not user_id:
        raise ValueError("missing sub claim")

    # ── 5. Verify user in DB ─────────────────────────────────────────────────
    import sqlite3 as _sq
    conn = _sq.connect(config.DB_PATH)
    conn.row_factory = _sq.Row
    row = conn.execute(
        "SELECT id, email, is_active, is_approved, is_superuser "
        "FROM fu_users WHERE id=?", (user_id,)
    ).fetchone()
    conn.close()

    if not row:
        raise ValueError("user not found")
    if not row["is_active"]:
        raise ValueError("user revoked")
    if not row["is_approved"] and not row["is_superuser"]:
        raise ValueError("user not approved")

    return dict(row)


# ── Periodic re-validation helper ─────────────────────────────────────────────
def _ws_user_still_valid(user_id: str) -> bool:
    """
    Check whether a connected user is still active and approved.
    Called on every broadcast to silently drop revoked sessions.
    """
    import sqlite3 as _sq
    try:
        conn = _sq.connect(config.DB_PATH)
        conn.row_factory = _sq.Row
        row = conn.execute(
            "SELECT is_active, is_approved, is_superuser FROM fu_users WHERE id=?",
            (user_id,)
        ).fetchone()
        conn.close()
        if not row:
            return False
        return bool(row["is_active"]) and (
            bool(row["is_approved"]) or bool(row["is_superuser"])
        )
    except Exception:
        logger.debug("Session-validity DB check failed", exc_info=True)
        return True  # DB error — keep connection rather than drop


class _WSManager:
    """
    Manages all connected dashboard WebSocket clients.
    Every connection is authenticated via JWT before accept().
    Broadcasts are filtered — revoked users are silently dropped.
    """
    def __init__(self) -> None:
        self._clients: set[_WSConnection] = set()
        self._lock = threading.Lock()

    def connect(self, conn: _WSConnection) -> None:
        """Register a newly authenticated dashboard connection."""
        with self._lock:
            self._clients.add(conn)
        logger.info("WebSocket authenticated: %s (%d total)", conn.email, len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        """Remove a connection, matched by its underlying WebSocket object."""
        with self._lock:
            self._clients = {c for c in self._clients if c.ws is not ws}
        logger.info("WebSocket disconnected (%d remaining)", len(self._clients))

    def broadcast_sync(self, msg: dict) -> None:
        """
        Thread-safe broadcast — called from sync alert/ingest threads.
        Skips connections whose user has been revoked since connect time.
        """
        with self._lock:
            clients = list(self._clients)
        if not clients:
            return
        payload = json.dumps(msg)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                for conn in clients:
                    # Periodic re-validation: drop revoked sessions silently
                    if not _ws_user_still_valid(conn.user_id):
                        asyncio.run_coroutine_threadsafe(
                            _ws_close_revoked(conn.ws), loop
                        )
                        with self._lock:
                            self._clients.discard(conn)
                        logger.info("WebSocket dropped — access revoked: %s", conn.email)
                        continue
                    asyncio.run_coroutine_threadsafe(
                        _safe_send(conn.ws, payload), loop
                    )
        except Exception:
            logger.debug("Broadcast scheduling failed", exc_info=True)

    @property
    def connection_count(self) -> int:
        """Number of currently connected dashboard clients."""
        with self._lock:
            return len(self._clients)


async def _safe_send(ws: WebSocket, payload: str) -> None:
    try:
        await ws.send_text(payload)
    except Exception:
        logger.debug("WebSocket send failed (client likely disconnected)", exc_info=True)


async def _ws_close_revoked(ws: WebSocket) -> None:
    try:
        await ws.close(code=1008, reason="Session revoked")
    except Exception:
        logger.debug("WebSocket close failed (already disconnected)", exc_info=True)

ws_manager = _WSManager()
