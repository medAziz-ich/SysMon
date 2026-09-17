"""
Application composition root: creates the FastAPI app, registers security
middleware, wires the fastapi-users auth router, and defines every HTTP and
WebSocket route.

Routes are kept in this single module rather than split into per-resource
routers because several depend on registration *order* (see the
`/api/users/pending` comment below) — flattening them into one file keeps
that ordering visible and easy to reason about. Splitting into routers is a
reasonable follow-up once the project has enough routes per resource to
justify the extra indirection.
"""

import asyncio
import hmac
import json
import math
import os
import random
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import (Cookie, Depends, FastAPI, HTTPException, Request,
                      Response, WebSocket, WebSocketDisconnect, status)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi_users import InvalidPasswordException
from fastapi_users.password import PasswordHelper
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from . import config
from .agents import verify_agent
from .ai_analysis import _run_ai_analysis
from .alerting import (_check_smart_alerts, _fire_alert, _get_host_config,
                        _get_thresholds, _in_cooldown, _is_monitoring_enabled,
                        _metric_history, _record_alert, _resolve_alert,
                        _send_email_resend, _send_email_smtp, _ssrf_safe_post,
                        check_alerts)
from .auth import (SysmonUserManager, UserRole, auth_backend, current_active_user,
                    fastapi_users_router, get_user_manager, init_fu_db,
                    require_session)
from .db import (Base, EmailProvider, User, _async_db_url, _hash, get_async_session,
                  get_settings, get_user_db, init_db, purge_old_data,
                  save_setting)
from .schemas import AdminUserCreate  # noqa: F401  (used by admin_create_user below)
from .schemas import *  # noqa: F401,F403  (request/response models used throughout the routes)
from .security import (_CSRF_COOKIE, _CSRF_HEADER, _audit, _check_rate_limit,
                        _generate_csrf_token, _require_csrf, _set_csrf_cookie,
                        _validate_webhook_url, ensure_tls_cert)
from .websocket import (_WSConnection, _validate_ws_token,
                         _ws_user_still_valid, ws_manager)

logger = config.logger.getChild("main")

try:
    import urllib.request as urlreq
except ImportError:
    urlreq = None

# ── App ───────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hook: init both DB schemas, seed the default admin, ensure TLS."""
    init_db()
    await init_fu_db()   # create fu_users table via SQLAlchemy async
    await _create_default_admin()
    yield


async def _create_default_admin() -> None:
    """
    If no dashboard users exist, create a default admin account:
        email:    admin@sysmon.local
        password: admin
    A warning is printed on every startup until the password is changed.
    """
    import sqlite3 as _sq
    conn = _sq.connect(config.DB_PATH)
    count = conn.execute("SELECT COUNT(*) FROM fu_users").fetchone()[0]
    conn.close()
    if count > 0:
        return   # users already exist — nothing to do

    from fastapi_users.password import PasswordHelper
    _ph = PasswordHelper()
    # Honour an explicit bootstrap password if provided, else generate a strong
    # random one. Never ship a guessable "admin" credential.
    _default_pw = os.getenv("SYSMON_DEFAULT_ADMIN_PASSWORD") or (
        secrets.token_urlsafe(12) + "A1"  # guarantees upper+digit for policy
    )
    hashed = _ph.hash(_default_pw)

    engine = create_async_engine(_async_db_url())
    async_session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session_maker() as session:
        default_user = User(
            id               = uuid.uuid4(),
            email            = "admin@sysmon.local",
            hashed_password  = hashed,
            display_name     = "Admin",
            is_active        = True,
            is_superuser     = True,
            is_verified      = True,
            is_approved      = True,
        )
        session.add(default_user)
        await session.commit()
    await engine.dispose()

    print("=" * 60)
    print("  ⚠  DEFAULT ADMIN ACCOUNT CREATED")
    print("     Email   : admin@sysmon.local")
    print(f"     Password: {_default_pw}")
    print("  ⚠  CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN")
    print("     (shown once — set SYSMON_DEFAULT_ADMIN_PASSWORD to control it)")
    print("=" * 60)

app = FastAPI(title="sysmon-server", lifespan=lifespan)

# ── Admin: User management ────────────────────────────────────────────────────
@app.get("/api/admin/users", response_model=list[UserAdminInfo],
         summary="List all dashboard users", tags=["admin"])
async def admin_list_users(
    current_user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[dict]:
    """List every user account (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    import sqlalchemy as sa
    result = await session.execute(sa.select(User).order_by(User.is_approved, User.email))
    users  = result.scalars().all()
    return [{"id": str(u.id), "email": u.email, "display_name": u.display_name,
             "is_superuser": u.is_superuser, "is_approved": u.is_approved,
             "is_active": u.is_active}
            for u in users]

@app.post("/api/admin/users",
          summary="Admin creates a new pre-approved user", tags=["admin"],
          status_code=201)
async def admin_create_user(
    body: AdminUserCreate,
    _csrf: None = Depends(_require_csrf),
    current_user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """Create a new user directly without requiring self-registration. Superuser only.
    The created user is immediately active, verified, and approved."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    if body.role not in (UserRole.ADMIN, UserRole.VIEWER):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'viewer'.")

    import sqlalchemy as sa
    existing = await session.execute(
        sa.select(User).where(User.email == body.email.strip().lower())
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered.")

    # Reuse the same password policy as self-registration
    from fastapi_users import InvalidPasswordException
    _tmp_mgr = SysmonUserManager.__new__(SysmonUserManager)
    try:
        await _tmp_mgr.validate_password(body.password)
    except InvalidPasswordException as exc:
        raise HTTPException(status_code=400, detail=str(exc.reason))

    ph = PasswordHelper()
    new_user = User(
        id              = uuid.uuid4(),
        email           = body.email.strip().lower(),
        display_name    = body.display_name.strip(),
        hashed_password = ph.hash(body.password),
        is_active       = True,
        is_verified     = True,
        is_approved     = True,
        is_superuser    = (body.role == UserRole.ADMIN),
    )
    session.add(new_user)
    await session.commit()
    _audit(current_user.email, "create_user", new_user.email,
           f"Admin created user with role={body.role}")
    ws_manager.broadcast_sync({"type": "user_updated", "email": new_user.email,
                                "action": "created"})
    return {"status": "created", "id": str(new_user.id),
            "email": new_user.email, "role": body.role}

@app.patch("/api/users/{user_id}/role",
           summary="Change a user's role (admin/viewer)", tags=["admin"])
async def change_user_role(
    user_id: str,
    body: RoleUpdate,
    _csrf: None = Depends(_require_csrf),
    current_user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """Promote or demote a user between admin and viewer (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    if body.role not in (UserRole.ADMIN, UserRole.VIEWER):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'viewer'.")
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID.")
    import sqlalchemy as sa
    result = await session.execute(sa.select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_superuser = (body.role == UserRole.ADMIN)
    await session.commit()
    _audit(current_user.email, "role_change", user.email,
           f"Role changed to {body.role}")
    ws_manager.broadcast_sync({"type": "user_updated", "email": user.email,
                                "action": "role_change", "role": body.role})
    return {"status": "updated", "email": user.email, "role": body.role}

@app.post("/api/users/{user_id}/reactivate",
          summary="Re-enable a revoked user", tags=["admin"])
async def reactivate_user(
    user_id: str,
    _csrf: None = Depends(_require_csrf),
    current_user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """Re-activate a previously revoked user account (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID.")
    import sqlalchemy as sa
    result = await session.execute(sa.select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_active   = True
    user.is_approved = True
    await session.commit()
    _audit(current_user.email, "reactivate", user.email, "User reactivated")
    ws_manager.broadcast_sync({"type": "user_updated", "email": user.email,
                                "action": "reactivate"})
    return {"status": "reactivated", "id": str(user.id), "email": user.email}

# ── Admin: Agent Key Management ───────────────────────────────────────────────
@app.get("/api/agent-keys", response_model=list[AgentKeyInfo],
         summary="List all registered agent API keys", tags=["admin"])
def list_agent_keys(current_user: User = Depends(current_active_user)) -> list[dict]:
    """List every registered agent and its API-key status (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, agent_name, enabled, created_at, last_seen "
        "FROM api_keys ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.delete("/api/agent-keys/{agent_name}",
            summary="Revoke an agent API key", tags=["admin"])
def revoke_agent_key(agent_name: str,
                     current_user: User = Depends(current_active_user),
                     _csrf: None = Depends(_require_csrf)) -> dict:
    """Disable an agent's API key without deleting its history (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    conn = sqlite3.connect(config.DB_PATH)
    row = conn.execute("SELECT id FROM api_keys WHERE agent_name=?",
                       (agent_name,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Agent not found.")
    conn.execute("UPDATE api_keys SET enabled=0 WHERE agent_name=?", (agent_name,))
    conn.commit()
    conn.close()
    _audit(current_user.email, "revoke", agent_name, "Agent API key revoked")
    ws_manager.broadcast_sync({"type": "agent_updated", "agent_name": agent_name,
                                "action": "revoked"})
    return {"status": "revoked", "agent_name": agent_name}

@app.post("/api/agent-keys/{agent_name}/enable",
          summary="Re-enable a revoked agent API key", tags=["admin"])
def enable_agent_key(agent_name: str,
                     current_user: User = Depends(current_active_user)) -> dict:
    """Re-enable a previously revoked agent API key (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    conn = sqlite3.connect(config.DB_PATH)
    row = conn.execute("SELECT id FROM api_keys WHERE agent_name=?",
                       (agent_name,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Agent not found.")
    conn.execute("UPDATE api_keys SET enabled=1 WHERE agent_name=?", (agent_name,))
    conn.commit()
    conn.close()
    _audit(current_user.email, "enable", agent_name, "Agent API key re-enabled")
    ws_manager.broadcast_sync({"type": "agent_updated", "agent_name": agent_name,
                                "action": "enabled"})
    return {"status": "enabled", "agent_name": agent_name}

@app.post("/api/agent-keys/{agent_name}/rotate",
          response_model=AgentRotateResponse,
          summary="Rotate agent API key — invalidates old key, issues new one",
          tags=["admin"])
def rotate_agent_key(agent_name: str,
                     current_user: User = Depends(current_active_user),
                     _csrf: None = Depends(_require_csrf)) -> dict:
    """Issue a new API key for an agent, invalidating the old one (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    conn = sqlite3.connect(config.DB_PATH)
    row = conn.execute("SELECT id FROM api_keys WHERE agent_name=?",
                       (agent_name,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Agent not found.")
    new_raw  = secrets.token_hex(32)
    new_hash = _hash(new_raw)
    conn.execute(
        "UPDATE api_keys SET key_hash=?, enabled=1, last_seen=NULL WHERE agent_name=?",
        (new_hash, agent_name)
    )
    conn.commit()
    conn.close()
    _audit(current_user.email, "rotate", agent_name, "API key rotated")
    ws_manager.broadcast_sync({"type": "agent_updated", "agent_name": agent_name,
                                "action": "rotated"})
    # Return the new raw key ONCE — never stored in plaintext
    return {"status": "rotated", "new_key": new_raw, "agent_name": agent_name}

# ── Admin: Audit log ───────────────────────────────────────────────────────────
@app.get("/api/audit-log", response_model=list[AuditEntry],
         summary="Paginated audit log of all admin actions", tags=["admin"])
def get_audit_log(
    page:   int = 1,
    limit:  int = 50,
    action: str = "",
    current_user: User = Depends(current_active_user),
) -> list[dict]:
    """Return recent audit-log entries, optionally filtered (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    limit  = min(limit, 200)
    offset = (page - 1) * limit
    conn   = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    if action:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE action=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (action, limit, offset)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── WebSocket endpoint ────────────────────────────────────────────────────────
# ── CSRF token endpoint ───────────────────────────────────────────────────────
@app.get("/api/csrf-token",
         summary="Get a CSRF token (set in cookie + returned in body)",
         tags=["auth"])
async def get_csrf_token(request: Request, response: Response) -> dict:
    """
    Returns a fresh CSRF token.
    Call this before any POST/PUT/PATCH/DELETE request from the frontend.
    The token is set as a non-HttpOnly cookie AND returned in the body
    so JavaScript can read it and include it in X-CSRF-Token header.
    """
    token    = _generate_csrf_token()
    is_https = request.url.scheme == "https"
    _set_csrf_cookie(response, token, is_https)
    return {"csrf_token": token}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """
    Authenticated real-time push endpoint for dashboard clients.

    Auth flow (pre-accept):
      1. Try Cookie: sysmon_session=<JWT>
      2. Fallback: Authorization: Bearer <JWT> header
      3. Validate token — decode HS256, verify audience, verify user in DB
      4. Reject with 1008 Policy Violation if invalid; write audit_log
      5. Only after validation: accept() + ws_manager.connect()

    Message types pushed to clients:
      { "type": "connected", "user": "...", "role": "admin|viewer" }
      { "type": "metric",    "hostname": "...", "cpu_percent": ..., ... }
      { "type": "alert",     "hostname": "...", "severity": "...", ... }
      { "type": "audit",     "actor": "...",    "action": "...", ... }
      { "type": "ping",      "server_time": ... }
    """
    # ── Step 1: Extract token — cookie first, then Authorization header ──────
    token = websocket.cookies.get("sysmon_session")
    if not token:
        auth_header = websocket.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()

    # ── Step 2: Validate token BEFORE accepting the connection ───────────────
    if not token:
        await websocket.close(code=1008, reason="Missing authentication token")
        _audit("anonymous", "websocket_rejected",
               str(websocket.client), "No token provided")
        return

    try:
        user_row = _validate_ws_token(token)
    except ValueError as exc:
        await websocket.close(code=1008, reason=f"Auth failed: {exc}")
        _audit("anonymous", "websocket_rejected",
               str(websocket.client), str(exc))
        return

    # ── Step 3: Accept + register authenticated connection ───────────────────
    await websocket.accept()
    ws_conn = _WSConnection(
        ws           = websocket,
        user_id      = user_row["id"],
        email        = user_row["email"],
        is_superuser = bool(user_row["is_superuser"]),
    )
    ws_manager.connect(ws_conn)

    await websocket.send_text(json.dumps({
        "type":        "connected",
        "server_time": int(time.time()),
        "user":        user_row["email"],
        "role":        UserRole.ADMIN if user_row["is_superuser"] else UserRole.VIEWER,
    }))

    # ── Step 4: Keep-alive loop with periodic re-validation ─────────────────
    try:
        while True:
            await asyncio.sleep(30)
            if not _ws_user_still_valid(user_row["id"]):
                await websocket.close(code=1008,
                                      reason="Session revoked by administrator")
                break
            await websocket.send_text(json.dumps({
                "type":        "ping",
                "server_time": int(time.time()),
            }))
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.debug("WebSocket keep-alive loop ended unexpectedly", exc_info=True)
    finally:
        ws_manager.disconnect(websocket)

# ── Baseline / anomaly API ─────────────────────────────────────────────────────
@app.get("/api/baseline/{hostname}")
def get_baseline(hostname: str) -> dict:
    """
    Return the statistical baseline (mean ± std dev) for a host.
    Used by the dashboard to show normal ranges on charts.
    """
    baseline = _get_baseline(hostname)
    if baseline is None:
        return JSONResponse(status_code=202, content={
            "status":  "insufficient_data",
            "message": f"Need at least {config.ANOMALY_MIN_SAMPLES} samples in the last {config.ANOMALY_LOOKBACK_H}h.",
            "baseline": None,
        })
    return {
        "status":   "ready",
        "baseline": baseline,
        "multiplier": config.ANOMALY_STD_MULTIPLIER,
    }

# ── Mount FastAPI-Users routers ───────────────────────────────────────────────
app.include_router(
    fastapi_users_router.get_auth_router(auth_backend),
    prefix="/api/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users_router.get_register_router(UserRead, UserCreate),
    prefix="/api/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users_router.get_reset_password_router(),
    prefix="/api/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users_router.get_verify_router(UserRead),
    prefix="/api/auth",
    tags=["auth"],
)
# ── User management endpoints — registered BEFORE the generic /{user_id} router
# so /api/users/pending is matched first and not captured as a user_id.
import sqlalchemy as _sa

@app.get("/api/users/pending", tags=["users"])
async def list_pending_users(
    current_user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[dict]:
    """List users awaiting approval. Superuser only."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    result = await session.execute(
        _sa.select(User).where(User.is_approved == False, User.is_superuser == False)
    )
    users = result.scalars().all()
    return [
        {"id": str(u.id), "email": u.email, "display_name": u.display_name,
         "is_approved": u.is_approved, "is_active": u.is_active}
        for u in users
    ]

@app.post("/api/users/{user_id}/approve", tags=["users"])
async def approve_user(
    user_id: str,
    _csrf: None = Depends(_require_csrf),
    current_user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """Approve a pending user. Superuser only."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format.")
    result = await session.execute(_sa.select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_approved = True
    user.is_active   = True
    await session.commit()
    _audit(current_user.email, "approve", user.email, "User approved")
    ws_manager.broadcast_sync({"type": "user_updated", "email": user.email,
                                "action": "approved"})
    return {"status": "approved", "id": str(user.id), "email": user.email}

@app.delete("/api/users/{user_id}/revoke", tags=["users"])
async def revoke_user(
    user_id: str,
    _csrf: None = Depends(_require_csrf),
    current_user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """Deactivate a user account. Superuser only. Cannot revoke own account."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format.")
    if uid == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot revoke your own account.")
    result = await session.execute(_sa.select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_active   = False
    user.is_approved = False
    await session.commit()
    _audit(current_user.email, "revoke", user.email, "User access revoked")
    ws_manager.broadcast_sync({"type": "user_updated", "email": user.email,
                                "action": "revoked"})
    return {"status": "revoked", "id": str(user.id), "email": user.email}

# ── User self-service endpoints — use current_active_user which enforces is_approved
@app.get("/api/users/me", response_model=UserRead, tags=["users"])
async def get_me(current_user: User = Depends(current_active_user)) -> User:
    """Return current authenticated, active, and approved user."""
    return current_user

@app.patch("/api/users/me", response_model=UserRead, tags=["users"])
async def update_me(
    update: UserUpdate,
    current_user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> User:
    """Update current user profile (display_name and/or password)."""
    if update.display_name is not None:
        current_user.display_name = update.display_name
    if update.password is not None:
        from fastapi_users.password import PasswordHelper
        current_user.hashed_password = PasswordHelper().hash(update.password)
    await session.merge(current_user)
    await session.commit()
    return current_user

@app.get("/api/users/{user_id}", response_model=UserRead, tags=["users"])
async def get_user(
    user_id: str,
    current_user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> User:
    """Get a user by ID. Superuser only."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format.")
    result = await session.execute(_sa.select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user

@app.middleware("http")
async def audit_security_events(request: Request, call_next) -> Response:
    """
    Audit middleware — logs security events:
    - Login failures on /api/auth/login
    - 403 Forbidden on admin/sensitive endpoints (privilege escalation attempts)
    """
    response = await call_next(request)
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path

    if (path == "/api/auth/login"
            and request.method == "POST"
            and response.status_code in (400, 401, 403)):
        _audit("anonymous", "login_failure", client_ip,
               f"HTTP {response.status_code} on /api/auth/login")

    elif (path == "/api/auth/logout"
          and request.method == "POST"
          and response.status_code < 400):
        _audit(client_ip, "logout", path, "User logged out")

    elif (response.status_code == 403
          and any(path.startswith(p) for p in
                  ("/api/admin", "/api/users", "/api/agent-keys",
                   "/api/settings", "/api/audit-log"))):
        _audit(client_ip, "permission_denied", path,
               f"403 Forbidden — {request.method} {path}")

    return response

@app.middleware("http")
async def limit_payload_size(request: Request, call_next) -> Response:
    """Middleware: reject request bodies larger than MAX_PAYLOAD_BYTES."""
    cl = request.headers.get("content-length")
    if cl and int(cl) > config.MAX_PAYLOAD_BYTES:
        return JSONResponse(status_code=413,
            content={"detail": f"Payload too large. Max {config.MAX_PAYLOAD_BYTES} bytes."})
    return await call_next(request)

@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    """
    Security headers middleware — hardened for production.
    OWASP A05:2021 Security Misconfiguration mitigation.
    """
    response = await call_next(request)

    # Prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Referrer privacy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Cross-origin isolation hardening
    response.headers["Cross-Origin-Opener-Policy"]   = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    # Restrict browser features
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=(), "
        "payment=(), usb=(), bluetooth=()"
    )
    # Legacy XSS protection (belt-and-suspenders)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Remove server version banner
    response.headers["Server"] = "SysMon"
    # ── Content-Security-Policy ────────────────────────────────────────────────
    # Applied to any HTML response and to all known dashboard page routes
    # (including /host/{hostname}, matched by prefix rather than exact string).
    is_html  = "text/html" in response.headers.get("content-type", "")
    path     = request.url.path
    _PAGE_PREFIXES = ("/", "/login", "/admin", "/settings", "/host")
    is_page  = is_html or path == "/" or any(
        path == p or path.startswith(p + "/") for p in _PAGE_PREFIXES if p != "/"
    )
    if is_page:
        # ── script-src ─────────────────────────────────────────────────────────
        # Charts (Chart.js / ApexCharts / ECharts) load from a CDN in the
        # templates. We allow the three mainstream JS CDNs explicitly — this is
        # still a strict allow-list, NOT a wildcard. Best practice for a PFE is
        # to vendor the library locally and drop the CDN hosts entirely; if you
        # do that, 'self' alone suffices.
        _SCRIPT_CDNS = (
            "https://cdn.jsdelivr.net "
            "https://cdnjs.cloudflare.com "
            "https://unpkg.com"
        )
        # 'unsafe-eval' is opt-in: Chart.js v4 does NOT need it, but Chart.js v3
        # and a few plugins do. Enable with SYSMON_CSP_ALLOW_EVAL=1 if and only
        # if the console shows an 'unsafe-eval' violation.
        script_src = f"script-src 'self' 'unsafe-inline' {_SCRIPT_CDNS}"
        if os.getenv("SYSMON_CSP_ALLOW_EVAL", "0") == "1":
            script_src += " 'unsafe-eval'"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"{script_src}; "
            # style-src mirrors the CDN list for charting libs that inject CSS,
            # plus Google Fonts.
            "style-src 'self' 'unsafe-inline' "
            "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com "
            "https://unpkg.com https://fonts.googleapis.com; "
            "font-src 'self' data: https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            # connect-src must permit the WebSocket (same-origin ws/wss covers
            # both http dev and https prod) AND XHR/fetch back to the API ('self').
            "connect-src 'self' wss: ws:; "
            # Chart.js renders to <canvas>; some plugins spawn blob: workers.
            "worker-src 'self' blob:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
    # HSTS — only over HTTPS
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
    # Cache-Control for sensitive API responses
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

    return response

# ── Registration ──────────────────────────────────────────────────────────────
@app.post("/register", status_code=201, response_model=RegisterResponse,
         summary="Register a new agent", tags=["agent"])
async def register(body: RegisterRequest, request: Request) -> dict:
    # Brute-force protection on the shared registration secret.
    """Register a new monitoring agent and issue it an API key."""
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(f"register:{client_ip}")
    if not hmac.compare_digest(body.secret, config.REGISTRATION_SECRET):
        _audit("agent", "registration_rejected", body.agent_name or "unknown",
               "Invalid registration secret")
        raise HTTPException(status_code=401, detail="Invalid registration secret.")
    agent_name = body.agent_name.strip()
    if not agent_name:
        raise HTTPException(status_code=400, detail="agent_name required.")
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    existing = conn.execute(
        "SELECT id FROM api_keys WHERE agent_name=?", (agent_name,)).fetchone()
    raw_key  = secrets.token_hex(32)
    key_hash = _hash(raw_key)
    if existing:
        conn.execute("UPDATE api_keys SET key_hash=?, enabled=1 WHERE agent_name=?",
                     (key_hash, agent_name))
    else:
        conn.execute("INSERT INTO api_keys (agent_name, key_hash) VALUES (?, ?)",
                     (agent_name, key_hash))
    conn.commit()
    conn.close()
    logger.info("Agent registered: %s", agent_name)
    return {"api_key": raw_key}

# ── Ingest ────────────────────────────────────────────────────────────────────
@app.post("/ingest", status_code=202)
async def ingest(request: Request, agent=Depends(verify_agent)) -> dict:
    """Accept a metrics sample or log event from an authenticated agent."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Payload must be a JSON object.")
    _HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,253}$')
    raw_hostname = body.get("hostname", "")
    if raw_hostname and not _HOSTNAME_RE.match(str(raw_hostname)):
        raise HTTPException(status_code=422, detail="Invalid hostname. Use only: a-z 0-9 . - _")
    if body.get("type") != "log_event":
        if not isinstance(body.get("cpu_percent"), (int, float)):
            raise HTTPException(status_code=422, detail="cpu_percent must be a number.")
        if not isinstance(body.get("ram_percent"), (int, float)):
            raise HTTPException(status_code=422, detail="ram_percent must be a number.")
        if not isinstance(body.get("hostname"), str):
            raise HTTPException(status_code=422, detail="hostname must be a string.")

    purge_old_data()

    conn = sqlite3.connect(config.DB_PATH)
    try:
        if body.get("type") == "log_event":
            conn.execute(
                "INSERT INTO log_events (hostname, timestamp, source, message) VALUES (?,?,?,?)",
                (body.get("hostname", agent["agent_name"]),
                 body.get("timestamp", int(time.time())),
                 str(body.get("source", ""))[:256],
                 str(body.get("message", ""))[:4096]))
        else:
            hostname = body.get("hostname", agent["agent_name"])
            cpu      = float(body["cpu_percent"])
            ram      = float(body["ram_percent"])
            services = body.get("services", [])
            conn.execute(
                "INSERT INTO metrics (hostname, timestamp, cpu_percent, ram_percent, raw_json) "
                "VALUES (?,?,?,?,?)",
                (hostname, body.get("timestamp", int(time.time())),
                 cpu, ram, json.dumps(body)))
            conn.commit()
            # Broadcast real-time update to all connected dashboard WebSocket clients
            ws_manager.broadcast_sync({
                "type":        "metric",
                "hostname":    hostname,
                "timestamp":   body.get("timestamp", int(time.time())),
                "cpu_percent": cpu,
                "ram_percent": ram,
                "disks":       body.get("disks", []),
                "network":     body.get("network", []),
                "services":    services,
            })
            # Run alert checks in background so ingest stays fast
            threading.Thread(
                target=check_alerts,
                args=(hostname, cpu, ram, services),
                daemon=True
            ).start()
            return {"status": "accepted"}
        conn.commit()
    finally:
        conn.close()

    return {"status": "accepted"}

# ── Alert threshold API ───────────────────────────────────────────────────────
# ── Host config API (thresholds + monitoring + tags) ─────────────────────────
@app.get("/api/host-config/{hostname}", response_model=HostConfigResponse,
         summary="Get per-host alert thresholds and config", tags=["config"])
def get_host_config(hostname: str) -> dict:
    """Return one host's effective alert thresholds and monitoring flag."""
    return _get_host_config(hostname)

@app.put("/api/host-config/{hostname}", response_model=HostConfigResponse,
         summary="Update per-host alert thresholds and config", tags=["config"])
async def set_host_config(hostname: str, body: HostConfigUpdate,
                          current_user: User = Depends(current_active_user),
                          _csrf: None = Depends(_require_csrf)) -> dict:
    """Update one host's alert thresholds, monitoring flag, or tags."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    cpu        = body.cpu_threshold
    ram        = body.ram_threshold
    monitoring = body.monitoring
    tags       = body.tags

    # Normalize tags
    if isinstance(tags, list):
        tags_str = ",".join(t.strip() for t in tags if t.strip())
    elif isinstance(tags, str):
        tags_str = ",".join(t.strip() for t in tags.split(",") if t.strip())
    else:
        tags_str = None

    conn = sqlite3.connect(config.DB_PATH)
    # Get existing row
    existing = conn.execute(
        "SELECT * FROM host_config WHERE hostname=?", (hostname,)
    ).fetchone()

    if existing:
        updates, params = [], []
        if cpu        is not None: updates.append("cpu_threshold=?");  params.append(cpu)
        if ram        is not None: updates.append("ram_threshold=?");  params.append(ram)
        if monitoring is not None: updates.append("monitoring=?");     params.append(1 if monitoring else 0)
        if tags_str   is not None: updates.append("tags=?");           params.append(tags_str)
        if updates:
            params.append(hostname)
            conn.execute(f"UPDATE host_config SET {','.join(updates)} WHERE hostname=?", params)
    else:
        conn.execute("""
            INSERT INTO host_config (hostname, cpu_threshold, ram_threshold, monitoring, tags)
            VALUES (?, ?, ?, ?, ?)
        """, (hostname, cpu, ram, 1 if monitoring is not False else 0, tags_str or ""))

    conn.commit()
    conn.close()
    _audit(current_user.email, "host_config_modified", hostname,
           f"cpu={cpu} ram={ram} monitoring={monitoring} tags={tags_str}")
    return _get_host_config(hostname)

# Legacy endpoint — kept for backward compat
@app.get("/api/thresholds/{hostname}")
def get_thresholds(hostname: str) -> dict:
    """Legacy alias for get_host_config, kept for backward compatibility."""
    cfg = _get_host_config(hostname)
    return {"hostname": hostname,
            "cpu_threshold": cfg["cpu_threshold"],
            "ram_threshold": cfg["ram_threshold"]}

@app.put("/api/thresholds/{hostname}")
async def set_thresholds(hostname: str, body: HostConfigUpdate,
                         current_user: User = Depends(current_active_user),
                         _csrf: None = Depends(_require_csrf)) -> dict:
    # Delegate to the canonical handler (auth/CSRF re-checked there too).
    """Legacy alias for set_host_config, kept for backward compatibility."""
    return await set_host_config(hostname, body, current_user=current_user, _csrf=None)

@app.delete("/api/hosts/{hostname}",
           summary="Permanently remove a host and all its data", tags=["metrics"])
def delete_host(hostname: str,
                current_user: User = Depends(current_active_user),
                _csrf: None = Depends(_require_csrf)) -> dict:
    """
    Deletes all metrics, logs, alerts, service state, and config for a host.
    Does NOT revoke any agent API key — a host is just data derived from
    metrics; an agent's key is a separate identity managed under Agent Keys.
    If the host's agent is still running and sending data, it will simply
    reappear on its next successful POST /ingest.
    Superuser only. Irreversible.
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    conn = sqlite3.connect(config.DB_PATH)
    cur = conn.execute("SELECT COUNT(*) FROM metrics WHERE hostname=?", (hostname,))
    if cur.fetchone()[0] == 0:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Host '{hostname}' not found.")
    conn.execute("DELETE FROM metrics         WHERE hostname=?", (hostname,))
    conn.execute("DELETE FROM log_events      WHERE hostname=?", (hostname,))
    conn.execute("DELETE FROM alert_history   WHERE hostname=?", (hostname,))
    conn.execute("DELETE FROM service_state   WHERE hostname=?", (hostname,))
    conn.execute("DELETE FROM host_config     WHERE hostname=?", (hostname,))
    conn.execute("DELETE FROM alert_thresholds WHERE hostname=?", (hostname,))
    conn.commit()
    conn.close()
    _audit(current_user.email, "host_deleted", hostname,
           "Host and all associated data permanently removed")
    ws_manager.broadcast_sync({"type": "host_deleted", "hostname": hostname})
    return {"status": "deleted", "hostname": hostname}

@app.get("/api/alerts/{hostname}", response_model=list[AlertResponse],
         summary="Alert history for a host", tags=["alerts"])
def get_alerts(hostname: str, limit: int = 50, status: str = "") -> list[dict]:
    """List alert history for one host, optionally filtered by status."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    if status:
        rows = conn.execute(
            "SELECT * FROM alert_history WHERE hostname=? AND status=? "
            "ORDER BY fired_at DESC LIMIT ?",
            (hostname, status, min(limit, 500))
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alert_history WHERE hostname=? "
            "ORDER BY fired_at DESC LIMIT ?",
            (hostname, min(limit, 500))
        ).fetchall()
    conn.close()
    return [_fmt_alert(r) for r in rows]

@app.delete("/api/alerts/{hostname}")
def clear_alerts(hostname: str,
                 current_user: User = Depends(current_active_user),
                 _csrf: None = Depends(_require_csrf)) -> dict:
    """Delete all alert history for one host."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("DELETE FROM alert_history WHERE hostname=?", (hostname,))
    conn.commit()
    conn.close()
    _audit(current_user.email, "alerts_cleared", hostname, "Alert history cleared")
    return {"status": "cleared", "hostname": hostname}

@app.post("/api/alerts/{alert_id}/acknowledge", response_model=AcknowledgeResponse,
         summary="Acknowledge an active alert", tags=["alerts"])
async def acknowledge_alert(
    alert_id: int,
    current_user: User = Depends(current_active_user),
) -> dict:
    """Mark a specific alert as acknowledged. Requires authentication."""
    user = current_user.email
    conn  = sqlite3.connect(config.DB_PATH)
    cur   = conn.execute(
        "UPDATE alert_history SET status='acknowledged', acked_at=?, acked_by=? "
        "WHERE id=? AND status='active'",
        (int(time.time()), user, alert_id)
    )
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Alert not found or already resolved.")
    return {"status": "acknowledged", "id": alert_id, "by": user}

@app.get("/api/alerts/{alert_id}/analysis")
def get_alert_analysis(alert_id: int) -> dict:
    """
    Return the AI analysis for a specific alert.
    202 = analysis still being generated.
    200 = ready or disabled.
    """
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT ai_analysis FROM alert_history WHERE id=?", (alert_id,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found.")
    analysis = row["ai_analysis"]
    if analysis is None:
        if not _AI_PROVIDER:
            return JSONResponse(status_code=200, content={
                "status": "disabled",
                "message": "Set config.ANTHROPIC_API_KEY or config.NVIDIA_API_KEY to enable AI analysis.",
                "ai_analysis": None,
            })
        return JSONResponse(status_code=202, content={
            "status":  "pending",
            "message": "Analysis is being generated, check back in a few seconds.",
            "ai_analysis": None,
        })
    return {"status": "ready", "ai_analysis": analysis}

@app.get("/api/alerts", response_model=list[AlertResponse],
         summary="All active alerts across all hosts", tags=["alerts"])
def get_all_alerts(limit: int = 100, status: str = "") -> list[dict]:
    """List alert history across every host, optionally filtered by status."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    if status:
        rows = conn.execute(
            "SELECT * FROM alert_history WHERE status=? ORDER BY fired_at DESC LIMIT ?",
            (status, min(limit, 500))
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alert_history ORDER BY fired_at DESC LIMIT ?",
            (min(limit, 500),)
        ).fetchall()
    conn.close()
    return [_fmt_alert(r) for r in rows]

def _fmt_alert(r) -> dict:
    """Serialize an alert_history DB row into the AlertResponse shape."""
    return {
        "id":          r["id"],
        "hostname":    r["hostname"],
        "alert_type":  r["alert_type"],
        "detail":      r["detail"],
        "severity":    r["severity"],
        "subject":     r["subject"],
        "body":        r["body"],
        "status":      r["status"],
        "fired_at":    r["fired_at"],
        "resolved_at": r["resolved_at"],
        "acked_at":    r["acked_at"],
        "acked_by":    r["acked_by"],
        "ai_analysis": r["ai_analysis"] if "ai_analysis" in r.keys() else None,
    }

# ── Settings API ──────────────────────────────────────────────────────────────
@app.get("/api/settings",
         summary="Get notification and alert settings", tags=["settings"])
def api_get_settings() -> dict:
    """Return current notification settings, with secrets masked."""
    cfg = get_settings()
    # Never expose secrets to the frontend
    cfg["smtp_pass"]      = "••••••••" if cfg["smtp_pass"] else ""
    cfg["resend_api_key"] = "••••••••" if cfg["resend_api_key"] else ""
    return cfg

@app.post("/api/settings",
         summary="Update notification and alert settings", tags=["settings"])
async def api_save_settings(body: SettingsUpdate,
                            current_user: User = Depends(current_active_user),
                            _csrf: None = Depends(_require_csrf)) -> dict:
    """Update notification settings (SMTP/Resend/webhook/thresholds)."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    allowed = ["email_provider","smtp_host","smtp_port","smtp_user","smtp_pass",
               "resend_api_key","resend_from",
               "alert_to","webhook_url","alert_cpu","alert_ram",
               "alert_cooldown","spike_threshold","spike_window"]
    data = body.model_dump(exclude_none=True)
    if "email_provider" in data and data["email_provider"] not in (EmailProvider.SMTP, EmailProvider.RESEND):
        raise HTTPException(status_code=400, detail="email_provider must be 'smtp' or 'resend'.")
    # SSRF guard: validate webhook_url before saving
    if "webhook_url" in data and data["webhook_url"] and \
       data["webhook_url"] not in ("", "••••••••"):
        _validate_webhook_url(data["webhook_url"])
    changed = []
    for key in allowed:
        val = data.get(key)
        if val is not None and str(val) != "" and str(val) != "••••••••":
            save_setting(key, str(val))
            changed.append(key)
    _audit(current_user.email, "settings_modified", "settings",
           f"Keys updated: {changed}")
    return {"status": "saved"}

@app.post("/api/settings/test-email")
async def test_email(current_user: User = Depends(current_active_user),
                     _csrf: None = Depends(_require_csrf)) -> dict:
    """Send a test email using current settings (SMTP or Resend). Superuser only."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    cfg = get_settings()
    if not cfg["alert_to"]:
        raise HTTPException(status_code=400, detail="No recipient configured (Send Alerts To).")
    body_text = "This is a test alert from SysMon. Your email notifications are working correctly."
    try:
        if cfg.get("email_provider") == EmailProvider.RESEND:
            _send_email_resend(cfg, "[SysMon] Test Alert", body_text)
        else:
            _send_email_smtp(cfg, "[SysMon] Test Alert", body_text)
        return {"status": "sent", "to": cfg["alert_to"], "provider": cfg.get("email_provider", EmailProvider.SMTP)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/settings/test-webhook")
async def test_webhook(current_user: User = Depends(current_active_user),
                       _csrf: None = Depends(_require_csrf)) -> dict:
    """Send a test webhook using current settings. Superuser only."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    cfg = get_settings()
    if not cfg["webhook_url"]:
        raise HTTPException(status_code=400, detail="Webhook not configured.")
    payload = json.dumps({
        "username": "SysMon",
        "embeds": [{
            "title":       "✅ SysMon Test Notification",
            "description": "Your webhook notifications are working correctly.",
            "color":       3447003,
            "footer":      {"text": "SysMon"},
            "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]
    }).encode("utf-8")
    try:
        # SSRF-safe: re-validates initial URL and every redirect hop.
        resp = _ssrf_safe_post(
            cfg["webhook_url"],
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "SysMon/1.0"},
            timeout=10,
        )
        resp.close()
        return {"status": "sent"}
    except HTTPException:
        raise   # propagate the 400 SSRF rejection unchanged
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Simulation / Demo mode ────────────────────────────────────────────────────
import random, math

SCENARIOS = {
    "high_cpu": {
        "label":       "High CPU",
        "cpu_percent": lambda: round(random.uniform(88, 99), 1),
        "ram_percent": lambda: round(random.uniform(40, 60), 1),
        "services":    lambda: [{"name": "nginx", "status": "active"},
                                {"name": "postgresql", "status": "active"}],
    },
    "high_ram": {
        "label":       "High RAM",
        "cpu_percent": lambda: round(random.uniform(10, 25), 1),
        "ram_percent": lambda: round(random.uniform(92, 99), 1),
        "services":    lambda: [{"name": "nginx", "status": "active"},
                                {"name": "postgresql", "status": "active"}],
    },
    "service_down": {
        "label":       "Service Down",
        "cpu_percent": lambda: round(random.uniform(5, 20), 1),
        "ram_percent": lambda: round(random.uniform(30, 50), 1),
        "services":    lambda: [{"name": "nginx",      "status": "failed"},
                                {"name": "postgresql",  "status": "active"}],
    },
    "normal": {
        "label":       "Normal Load",
        "cpu_percent": lambda: round(random.uniform(5, 30), 1),
        "ram_percent": lambda: round(random.uniform(20, 50), 1),
        "services":    lambda: [{"name": "nginx",      "status": "active"},
                                {"name": "postgresql",  "status": "active"}],
    },
    "critical": {
        "label":       "Full Crisis",
        "cpu_percent": lambda: round(random.uniform(95, 99.9), 1),
        "ram_percent": lambda: round(random.uniform(95, 99.9), 1),
        "services":    lambda: [{"name": "nginx",      "status": "failed"},
                                {"name": "postgresql",  "status": "failed"}],
    },
}

@app.post("/api/simulate/{hostname}")
async def simulate(hostname: str, request: Request,
                   current_user: User = Depends(current_active_user),
                   _csrf: None = Depends(_require_csrf)) -> dict:
    """
    Inject a fake metrics payload for a host.
    Body: { "scenario": "high_cpu" | "high_ram" | "service_down" | "normal" | "critical" }
    Optionally: { "cpu_percent": 95.0, "ram_percent": 80.0 } for manual values.
    Superuser only — simulation can fire real alerts/notifications.
    """
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    body     = await request.json()
    scenario = body.get("scenario", "normal")
    cfg      = SCENARIOS.get(scenario, SCENARIOS["normal"])

    cpu      = body.get("cpu_percent",  cfg["cpu_percent"]())
    ram      = body.get("ram_percent",  cfg["ram_percent"]())
    services = body.get("services",     cfg["services"]())

    payload = {
        "hostname":    hostname,
        "timestamp":   int(time.time()),
        "cpu_percent": cpu,
        "ram_percent": ram,
        "disks":       [{"path": "/", "percent": round(random.uniform(30, 60), 1)}],
        "network":     [{"interface": "eth0",
                         "rx_bps": round(random.uniform(1e4, 5e6), 0),
                         "tx_bps": round(random.uniform(1e3, 1e6), 0)}],
        "services":    services,
        "_simulated":  True,
    }

    # Store metric
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(
        "INSERT INTO metrics (hostname, timestamp, cpu_percent, ram_percent, raw_json) "
        "VALUES (?,?,?,?,?)",
        (hostname, payload["timestamp"], cpu, ram, json.dumps(payload))
    )
    conn.commit()
    conn.close()

    # Run alert checks
    threading.Thread(
        target=check_alerts,
        args=(hostname, cpu, ram, services),
        daemon=True
    ).start()

    return {"status": "simulated", "scenario": scenario,
            "cpu_percent": cpu, "ram_percent": ram, "services": services}

@app.post("/api/simulate/{hostname}/alert")
async def simulate_alert(hostname: str, request: Request,
                         current_user: User = Depends(current_active_user),
                         _csrf: None = Depends(_require_csrf)) -> dict:
    """Inject a fake alert directly into alert_history for demo purposes. Superuser only."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    body     = await request.json()
    alert_type = body.get("alert_type", "cpu")
    severity   = body.get("severity",   "critical")
    subject    = body.get("subject",    f"[DEMO] {hostname}: simulated {alert_type} alert")
    detail     = body.get("detail",     "demo")
    msg_body   = body.get("body",       f"This is a simulated alert for demonstration purposes.\nHost: {hostname}")

    _record_alert(hostname, alert_type, detail, severity, subject, msg_body)
    return {"status": "injected", "alert_type": alert_type, "severity": severity}

@app.delete("/api/simulate/{hostname}")
async def clear_simulated(hostname: str,
                          current_user: User = Depends(current_active_user),
                          _csrf: None = Depends(_require_csrf)) -> dict:
    """Remove all simulated metrics for a host (cleanup after demo). Superuser only."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required.")
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(
        "DELETE FROM metrics WHERE hostname=? AND raw_json LIKE '%\"_simulated\": true%'",
        (hostname,)
    )
    conn.commit()
    conn.close()
    return {"status": "cleared"}

# ── Dashboard API ─────────────────────────────────────────────────────────────
@app.get("/api/hosts", response_model=list[HostSummary],
         summary="List all monitored hosts", tags=["metrics"])
def api_hosts() -> list[dict]:
    """List every known host with its online status and tags."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT hostname, MAX(timestamp) as last_seen FROM metrics "
        "GROUP BY hostname ORDER BY hostname"
    ).fetchall()
    configs = {r["hostname"]: r for r in conn.execute(
        "SELECT hostname, monitoring, tags FROM host_config"
    ).fetchall()}
    conn.close()
    now = int(time.time())
    result = []
    for r in rows:
        cfg = configs.get(r["hostname"])
        tags = [t.strip() for t in cfg["tags"].split(",") if t.strip()] if cfg and cfg["tags"] else []
        result.append({
            "hostname":   r["hostname"],
            "last_seen":  r["last_seen"],
            "online":     (now - r["last_seen"]) < 180,
            "monitoring": bool(cfg["monitoring"]) if cfg else True,
            "tags":       tags,
        })
    return result

@app.get("/api/metrics/{hostname}", response_model=list[MetricSample],
         summary="Time-series metrics for a host", tags=["metrics"])
def api_metrics(hostname: str, hours: int = 3) -> list[dict]:
    """Return recent metrics samples for one host."""
    cutoff = int(time.time()) - min(hours, 168) * 3600
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT timestamp, cpu_percent, ram_percent, raw_json FROM metrics "
        "WHERE hostname=? AND timestamp>=? ORDER BY timestamp ASC", (hostname, cutoff)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        raw = json.loads(r["raw_json"])
        result.append({"timestamp": r["timestamp"], "cpu_percent": r["cpu_percent"],
                        "ram_percent": r["ram_percent"], "disks": raw.get("disks", []),
                        "network": raw.get("network", []), "services": raw.get("services", [])})
    return result

@app.get("/api/logs/{hostname}", response_model=list[LogEvent],
         summary="Recent log events for a host", tags=["logs"])
def api_logs(hostname: str, limit: int = 200) -> list[dict]:
    """Return recent log events for one host."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, hostname, timestamp, source, message FROM log_events "
        "WHERE hostname=? ORDER BY timestamp DESC LIMIT ?",
        (hostname, min(limit, 1000))
    ).fetchall()
    conn.close()
    return [{"id": r["id"], "hostname": r["hostname"], "timestamp": r["timestamp"],
             "source": r["source"], "message": r["message"]} for r in rows]

@app.get("/api/latest/{hostname}")
def api_latest(hostname: str) -> dict:
    """Return the most recent metrics snapshot for one host."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT raw_json, timestamp FROM metrics "
        "WHERE hostname=? ORDER BY timestamp DESC LIMIT 1", (hostname,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="No data for host.")
    data = json.loads(row["raw_json"])
    data["_db_timestamp"] = row["timestamp"]
    return data

# ── Auth pages ────────────────────────────────────────────────────────────────
# FastAPI-Users handles /api/auth/login, /api/auth/logout, /api/auth/register,
# /api/auth/forgot-password, /api/auth/reset-password, /api/auth/verify,
# and /api/users/me  — all mounted above.
# We keep only the HTML login page route here.

@app.get("/login", response_class=HTMLResponse)
def login_page() -> HTMLResponse:
    """Serve the login page template."""
    tmpl = Path("templates/login.html")
    if tmpl.exists():
        return HTMLResponse(tmpl.read_text())
    return HTMLResponse("<h1>Login template not found</h1>", status_code=500)

# ── Admin page ────────────────────────────────────────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
def admin_page(user: str = Depends(require_session)) -> HTMLResponse:
    """Serve the admin panel template (requires an active session)."""
    tmpl = Path("templates/admin.html")
    if tmpl.exists():
        return HTMLResponse(tmpl.read_text())
    return HTMLResponse("<h1>Admin template not found</h1>", status_code=500)

# ── Host detail page ──────────────────────────────────────────────────────────
@app.get("/host/{hostname}", response_class=HTMLResponse)
def host_detail(hostname: str, user: str = Depends(require_session)) -> HTMLResponse:
    """Serve the per-host detail page template (requires an active session)."""
    tmpl = Path("templates/host_detail.html")
    if tmpl.exists():
        return HTMLResponse(tmpl.read_text())
    return HTMLResponse("<h1>Host detail template not found</h1>", status_code=500)

# ── Settings page ─────────────────────────────────────────────────────────────
@app.get("/settings", response_class=HTMLResponse)
def settings_page(user: str = Depends(require_session)) -> HTMLResponse:
    """Serve the settings page template (requires an active session)."""
    tmpl = Path("templates/settings.html")
    if tmpl.exists():
        return HTMLResponse(tmpl.read_text())
    return HTMLResponse("<h1>Settings template not found</h1>", status_code=500)

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def dashboard(user: str = Depends(require_session)) -> HTMLResponse:
    """Serve the main dashboard page template (requires an active session)."""
    tmpl = Path("templates/dashboard.html")
    if tmpl.exists():
        return HTMLResponse(tmpl.read_text())
    return HTMLResponse("<h1>Dashboard template not found</h1>", status_code=500)

