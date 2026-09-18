"""
fastapi-users wiring: cookie+JWT auth backend, the SysmonUserManager
(registration/login hooks, password policy), and the two dependencies
routes use to require an authenticated user — `current_active_user` for
the JSON API and `require_session` for server-rendered HTML pages.
"""

import sqlite3
import uuid
from enum import StrEnum
from typing import AsyncGenerator

from fastapi import Depends, HTTPException, Request
from fastapi_users import BaseUserManager, FastAPIUsers, InvalidPasswordException, UUIDIDMixin
from fastapi_users.authentication import AuthenticationBackend, CookieTransport, JWTStrategy
from sqlalchemy.ext.asyncio import create_async_engine

from . import config
from .db import Base, User, _async_db_url, get_user_db
from .security import _audit

logger = config.logger.getChild("auth")

class UserRole(StrEnum):
    """The two roles the admin user-management API accepts."""
    ADMIN  = "admin"
    VIEWER = "viewer"

# ── Cookie + JWT transport ─────────────────────────────────────────────────────
_cookie_transport = CookieTransport(
    cookie_name="sysmon_session",
    cookie_max_age=config.SESSION_TTL,
    cookie_httponly=True,
    cookie_samesite="strict",
    # Secure flag is environment-driven (see config.COOKIE_SECURE). ON by default and
    # always ON in production; set SYSMON_COOKIE_SECURE=0 for local HTTP dev.
    cookie_secure=config.COOKIE_SECURE,
)

def _get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(secret=config.JWT_SECRET, lifetime_seconds=config.SESSION_TTL)

auth_backend = AuthenticationBackend(
    name="cookie",
    transport=_cookie_transport,
    get_strategy=_get_jwt_strategy,
)

# ── User manager ───────────────────────────────────────────────────────────────
class SysmonUserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    """fastapi-users manager: approval workflow, password policy, audit hooks."""

    reset_password_token_secret    = config.JWT_SECRET
    verification_token_secret      = config.JWT_SECRET

    async def on_after_register(self, user: User, request=None) -> None:
        """First registered user is auto-approved as superuser.
        Uses direct sqlite3 so this works inside both async and sync (TestClient) contexts.
        """
        logger.info("User registered: %s", user.email)
        import sqlite3 as _sqlite3
        conn = _sqlite3.connect(config.DB_PATH)
        count = conn.execute("SELECT COUNT(*) FROM fu_users").fetchone()[0]
        if count <= 1:
            # Promote directly via SQL — avoids opening a second async engine
            # which would deadlock when called from a sync TestClient context.
            conn.execute(
                "UPDATE fu_users SET is_superuser=1, is_approved=1, is_active=1 WHERE id=?",
                (str(user.id),)
            )
            conn.commit()
            logger.info("First user (%s): granted superuser + auto-approved", user.email)
        conn.close()

    async def on_after_login(self, user: User, request=None, response=None) -> None:
        """Audit successful logins — OWASP A07:2021 Identification Failures."""
        client_ip = request.client.host if request and request.client else "unknown"
        _audit(user.email, "login_success", user.email,
               f"Login from {client_ip}")
        logger.info("User logged in: %s from %s", user.email, client_ip)

    async def validate_password(self, password: str, user=None) -> None:
        """
        Password policy — OWASP A07:2021.
        Min 8 chars, at least one uppercase, one lowercase, one digit.
        """
        from fastapi_users import InvalidPasswordException
        if len(password) < 8:
            raise InvalidPasswordException(
                "Password must be at least 8 characters.")
        if not any(c.isupper() for c in password):
            raise InvalidPasswordException(
                "Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in password):
            raise InvalidPasswordException(
                "Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in password):
            raise InvalidPasswordException(
                "Password must contain at least one digit.")

async def get_user_manager(user_db=Depends(get_user_db)) -> AsyncGenerator["SysmonUserManager", None]:
    """FastAPI dependency providing a SysmonUserManager for the current request."""
    yield SysmonUserManager(user_db)

fastapi_users_router = FastAPIUsers[User, uuid.UUID](
    get_user_manager,
    [auth_backend],
)

# Convenience dependency — returns current active+approved User or raises 401/403
async def current_active_user(
    user: User = Depends(fastapi_users_router.current_user(active=True))
) -> User:
    """Dependency for JSON API routes: active + admin-approved user, or 401/403."""
    if not user.is_approved and not user.is_superuser:
        raise HTTPException(status_code=403, detail="Account pending admin approval.")
    return user

# require_session — used by HTML page routes; redirects to /login if not authed.
async def require_session(request: Request) -> str:
    """
    Decodes the sysmon_session JWT cookie and returns the user email.
    Redirects to /login if missing, invalid, expired, or not approved.
    """
    token = request.cookies.get("sysmon_session")
    if not token:
        raise HTTPException(status_code=307,
            headers={"Location": "/login"}, detail="Not authenticated")
    try:
        # Decode JWT directly — same secret and algorithm as JWTStrategy
        from jose import jwt as _jwt, JWTError
        # Decode without audience check — jose requires str but fastapi-users
        # stores audience as a list; we verify it manually below.
        payload = _jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"],
                              options={"verify_aud": False})
        aud = payload.get("aud", [])
        if "fastapi-users:auth" not in (aud if isinstance(aud, list) else [aud]):
            raise ValueError("wrong audience")
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("no sub")
        # Look up user in DB using sync sqlite3 — no async engine needed
        import sqlite3 as _sq
        conn = _sq.connect(config.DB_PATH)
        conn.row_factory = _sq.Row
        row = conn.execute(
            "SELECT email, is_active, is_approved, is_superuser "
            "FROM fu_users WHERE id=?", (user_id,)
        ).fetchone()
        conn.close()
        if not row or not row["is_active"]:
            raise ValueError("inactive")
        if not row["is_approved"] and not row["is_superuser"]:
            raise ValueError("not approved")
        return row["email"]
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=307,
            headers={"Location": "/login"}, detail="Not authenticated")

# ── DB init helper for fu_users table ─────────────────────────────────────────
async def init_fu_db() -> None:
    """Create the fastapi-users `fu_users` table if it does not already exist."""
    engine = create_async_engine(_async_db_url())
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()

