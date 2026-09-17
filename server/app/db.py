"""
Persistence layer: SQLAlchemy models for authentication (fastapi-users) and
raw-SQL schema/helpers for the application's own tables (metrics, alerts,
audit log, notification settings, ...).

Two storage paths intentionally coexist here:
  - `fu_users` (SQLAlchemy, async) — the fastapi-users identity table.
  - everything else (plain sqlite3, sync) — metrics/alerts/settings/etc.
The sync path is deliberate: most of it runs from background threads
(alert notification, ingest) where spinning up an async engine per call
would add complexity without benefit.

Configuration is always read via `config.<NAME>` rather than imported by
value, so tests (and ops tooling) can override e.g. `config.DB_PATH` at
runtime and have every module observe the change immediately.
"""

import hashlib
import sqlite3
import time
from enum import StrEnum
from typing import AsyncGenerator

from fastapi import Depends
from fastapi_users.db import SQLAlchemyBaseUserTableUUID, SQLAlchemyUserDatabase
from sqlalchemy import Boolean, Column, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

class EmailProvider(StrEnum):
    """The two notification-email backends the settings API accepts."""
    SMTP   = "smtp"
    RESEND = "resend"

from . import config

# SQLAlchemy async engine — uses aiosqlite driver on top of the same DB file
def _async_db_url() -> str:
    return f"sqlite+aiosqlite:///{config.DB_PATH}"

class Base(DeclarativeBase):
    """Declarative base for the fastapi-users SQLAlchemy models."""

    pass

class User(SQLAlchemyBaseUserTableUUID, Base):
    """Extends the fastapi-users base with our extra fields."""
    __tablename__ = "fu_users"
    display_name: str = Column(String(128), nullable=False, default="")
    is_approved:  bool = Column(Boolean, nullable=False, default=False)

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a request-scoped async DB session."""
    engine = create_async_engine(_async_db_url())
    async_session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session_maker() as session:
        yield session

async def get_user_db(session: AsyncSession = Depends(get_async_session)) -> AsyncGenerator[SQLAlchemyUserDatabase, None]:
    """FastAPI dependency providing the fastapi-users database adapter."""
    yield SQLAlchemyUserDatabase(session, User)

# ── Database ──────────────────────────────────────────────────────────────────
def init_db() -> None:
    """Create every application table if it does not already exist.

    Idempotent — safe to call on every startup. Does not touch the
    fastapi-users `fu_users` table, which is managed separately via
    `init_fu_db()` (see auth.py).
    """
    conn = sqlite3.connect(config.DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname    TEXT    NOT NULL,
            timestamp   INTEGER NOT NULL,
            cpu_percent REAL,
            ram_percent REAL,
            raw_json    TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_host_ts ON metrics(hostname, timestamp);

        CREATE TABLE IF NOT EXISTS log_events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname  TEXT    NOT NULL,
            timestamp INTEGER NOT NULL,
            source    TEXT,
            message   TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_logs_host_ts ON log_events(hostname, timestamp);

        CREATE TABLE IF NOT EXISTS api_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_name  TEXT    NOT NULL UNIQUE,
            key_hash    TEXT    NOT NULL UNIQUE,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            last_seen   INTEGER,
            enabled     INTEGER NOT NULL DEFAULT 1
        );

        -- Tracks last known service state per host to detect transitions only
        CREATE TABLE IF NOT EXISTS service_state (
            hostname    TEXT NOT NULL,
            service     TEXT NOT NULL,
            last_status TEXT NOT NULL,
            updated_at  INTEGER NOT NULL,
            PRIMARY KEY (hostname, service)
        );

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- Dashboard user accounts
        CREATE TABLE IF NOT EXISTS dashboard_users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            display_name  TEXT    NOT NULL,
            password_hash TEXT    NOT NULL,
            created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            approved      INTEGER NOT NULL DEFAULT 0
        );

        -- Per-host configuration: thresholds, monitoring toggle, tags
        CREATE TABLE IF NOT EXISTS host_config (
            hostname       TEXT PRIMARY KEY,
            cpu_threshold  REAL,
            ram_threshold  REAL,
            monitoring     INTEGER NOT NULL DEFAULT 1,  -- 1=enabled, 0=disabled
            tags           TEXT    NOT NULL DEFAULT ''  -- comma-separated
        );
        -- Keep old table for migration compatibility
        CREATE TABLE IF NOT EXISTS alert_thresholds (
            hostname       TEXT PRIMARY KEY,
            cpu_threshold  REAL,
            ram_threshold  REAL
        );

        -- Alert history with severity, status, acknowledge support
        CREATE TABLE IF NOT EXISTS alert_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname     TEXT    NOT NULL,
            alert_type   TEXT    NOT NULL,   -- 'cpu', 'ram', 'service'
            detail       TEXT,
            severity     TEXT    NOT NULL DEFAULT 'warning',  -- 'info', 'warning', 'critical'
            subject      TEXT    NOT NULL DEFAULT '',
            body         TEXT    NOT NULL DEFAULT '',
            status       TEXT    NOT NULL DEFAULT 'active',   -- 'active', 'resolved', 'acknowledged'
            fired_at     INTEGER NOT NULL,
            resolved_at  INTEGER,
            acked_at     INTEGER,
            acked_by     TEXT,
            ai_analysis  TEXT    DEFAULT NULL   -- Claude AI root cause analysis
        );
        CREATE INDEX IF NOT EXISTS idx_alert_host ON alert_history(hostname, alert_type, fired_at);
        CREATE INDEX IF NOT EXISTS idx_alert_status ON alert_history(status, fired_at);

        -- Audit log: every admin action
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            actor     TEXT    NOT NULL,
            action    TEXT    NOT NULL,
            target    TEXT    NOT NULL,
            detail    TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log(actor,  timestamp DESC);
    """)
    # Migration: add ai_analysis column to existing DBs that don't have it yet
    try:
        conn.execute("ALTER TABLE alert_history ADD COLUMN ai_analysis TEXT DEFAULT NULL")
    except Exception:
        pass  # column already exists — safe to ignore
    conn.commit()
    conn.close()

def purge_old_data() -> None:
    """Delete metrics/log rows older than RETAIN_HOURS and alerts older than 30 days."""
    cutoff = int(time.time()) - config.RETAIN_HOURS * 3600
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("DELETE FROM metrics    WHERE timestamp < ?", (cutoff,))
    conn.execute("DELETE FROM log_events WHERE timestamp < ?", (cutoff,))
    # Keep alert history for 30 days
    conn.execute("DELETE FROM alert_history WHERE fired_at < ?",
                 (int(time.time()) - 86400 * 30,))
    conn.commit()
    conn.close()

# ── API key hashing ────────────────────────────────────────────────────────────
def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()

# ── Notification / alert settings (persisted in the settings table) ──────────
def get_settings() -> dict:
    """Load notification settings from DB, falling back to env var defaults."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    s = {r["key"]: r["value"] for r in rows}
    return {
        "email_provider": s.get("email_provider", config._EMAIL_PROVIDER_DEFAULT) or EmailProvider.SMTP,
        "smtp_host":    s.get("smtp_host",    config._SMTP_HOST_DEFAULT),
        "smtp_port":    int(s.get("smtp_port", config._SMTP_PORT_DEFAULT) or 587),
        "smtp_user":    s.get("smtp_user",    config._SMTP_USER_DEFAULT),
        "smtp_pass":    s.get("smtp_pass",    config._SMTP_PASS_DEFAULT),
        "resend_api_key": s.get("resend_api_key", config._RESEND_API_KEY_DEFAULT),
        "resend_from":    s.get("resend_from",    config._RESEND_FROM_DEFAULT),
        "alert_to":     s.get("alert_to",     config._ALERT_TO_DEFAULT),
        "webhook_url":  s.get("webhook_url",  config._WEBHOOK_URL_DEFAULT),
        "alert_cpu":    float(s.get("alert_cpu",  str(config.DEFAULT_CPU_THRESHOLD))),
        "alert_ram":    float(s.get("alert_ram",  str(config.DEFAULT_RAM_THRESHOLD))),
        "alert_cooldown": int(s.get("alert_cooldown", str(config.ALERT_COOLDOWN_SEC))),
        "spike_threshold": float(s.get("spike_threshold", str(config.SPIKE_THRESHOLD))),
        "spike_window":    int(s.get("spike_window",    str(config.SPIKE_WINDOW))),
    }

def save_setting(key: str, value: str) -> None:
    """Upsert a single notification-settings key/value pair."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("""
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    """, (key, value))
    conn.commit()
    conn.close()
