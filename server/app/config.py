"""
Central configuration for sysmon-server.

Every tunable is sourced from an environment variable with a sane
development-mode default. Anything security-sensitive (JWT secret,
registration secret) refuses to fall back to a default when
SYSMON_ENV=production, so a misconfigured production deploy fails fast
at startup instead of running with weak or unstable secrets.
"""

import logging
import os
import re
import secrets

# ── Logging ─────────────────────────────────────────────────────────────────────
# One named logger for the whole package; handlers/level are left to the host
# process (uvicorn, systemd, a container runtime) rather than configured here.
logging.basicConfig(
    level=os.getenv("SYSMON_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("sysmon")

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH             = os.getenv("SYSMON_DB",                  "sysmon.db")
RETAIN_HOURS        = int(os.getenv("SYSMON_RETAIN_HOURS",    "168"))
# Runtime environment — "production" enables strict secret/cookie enforcement.
SYSMON_ENV          = os.getenv("SYSMON_ENV", "development").lower()
_IS_PROD            = SYSMON_ENV == "production"

# Registration secret. In production it MUST be set explicitly — refusing the
# weak built-in default prevents anyone who reads the repo from registering agents.
REGISTRATION_SECRET = os.getenv("SYSMON_REGISTRATION_SECRET", "" if _IS_PROD else "register-me")
if _IS_PROD and not REGISTRATION_SECRET:
    raise RuntimeError(
        "SYSMON_REGISTRATION_SECRET must be set when SYSMON_ENV=production")
RATE_LIMIT_REQUESTS = int(os.getenv("SYSMON_RATE_LIMIT",       "120"))  # per window
RATE_LIMIT_WINDOW   = int(os.getenv("SYSMON_RATE_LIMIT_WINDOW", "60"))   # seconds
MAX_PAYLOAD_BYTES   = int(os.getenv("SYSMON_MAX_PAYLOAD",      str(512*1024)))
TLS_CERT            = os.getenv("SYSMON_TLS_CERT", "server.crt")
TLS_KEY             = os.getenv("SYSMON_TLS_KEY",  "server.key")

# ── Default alert thresholds (overridable per-host in DB) ─────────────────────
DEFAULT_CPU_THRESHOLD  = float(os.getenv("SYSMON_ALERT_CPU",     "85"))   # %
DEFAULT_RAM_THRESHOLD  = float(os.getenv("SYSMON_ALERT_RAM",     "90"))   # %
ALERT_COOLDOWN_SEC     = int(os.getenv("SYSMON_ALERT_COOLDOWN",  "300"))  # 5 min between same alerts

# ── Input validation ──────────────────────────────────────────────────────────
# Hostname: RFC-1123 — letters, digits, hyphens, dots. Max 253 chars.
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$')

# ── FastAPI-Users setup ────────────────────────────────────────────────────────
SESSION_TTL = 86400  # 24 hours (JWT lifetime)

# JWT signing secret. A regenerated-per-restart secret silently invalidates all
# live sessions and usually means no stable secret is configured at all, so in
# production we refuse to start without an explicit one.
JWT_SECRET = os.getenv("SYSMON_JWT_SECRET")
if not JWT_SECRET:
    if _IS_PROD:
        raise RuntimeError(
            "SYSMON_JWT_SECRET must be set when SYSMON_ENV=production")
    JWT_SECRET = secrets.token_hex(32)  # development convenience only

# Session cookie Secure flag. Defaults ON; set SYSMON_COOKIE_SECURE=0 only for
# local plain-HTTP development. Always forced ON in production.
COOKIE_SECURE = _IS_PROD or (os.getenv("SYSMON_COOKIE_SECURE", "1") != "0")

# Trusted origins for CSRF Origin/Referer validation. Comma-separated list, e.g.
# "https://soc.example.com,https://soc.internal". When empty, validation falls
# back to comparing against the request's own scheme+host (single-origin deploy).
_ALLOWED_ORIGINS: list[str] = [
    o.strip().rstrip("/")
    for o in os.getenv("SYSMON_ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]

# ── Notification defaults (env vars act as first-run fallbacks; live values
#    are stored in the `settings` table and read via db.get_settings()) ──────
_SMTP_HOST_DEFAULT    = os.getenv("SYSMON_SMTP_HOST",    "")
_SMTP_PORT_DEFAULT    = os.getenv("SYSMON_SMTP_PORT",    "587")
_SMTP_USER_DEFAULT    = os.getenv("SYSMON_SMTP_USER",    "")
_SMTP_PASS_DEFAULT    = os.getenv("SYSMON_SMTP_PASS",    "")
_ALERT_TO_DEFAULT     = os.getenv("SYSMON_ALERT_TO",     "")
_WEBHOOK_URL_DEFAULT  = os.getenv("SYSMON_WEBHOOK_URL",  "")
_EMAIL_PROVIDER_DEFAULT = os.getenv("SYSMON_EMAIL_PROVIDER", "smtp")  # "smtp" | "resend"
_RESEND_API_KEY_DEFAULT = os.getenv("SYSMON_RESEND_API_KEY", "")
_RESEND_FROM_DEFAULT    = os.getenv("SYSMON_RESEND_FROM",
                                     "SysMon Alerts <onboarding@resend.dev>")

# ── Smart alerting / anomaly detection tuning ─────────────────────────────────
HISTORY_WINDOW         = 10    # in-memory samples kept per host
SPIKE_WINDOW           = 3     # samples to look back for spike detection
SPIKE_THRESHOLD        = 20.0  # % jump within SPIKE_WINDOW counts as a spike
ANOMALY_STD_MULTIPLIER = 2.0   # mean + N*std_dev is the anomaly boundary
ANOMALY_MIN_SAMPLES    = 30    # minimum samples before a host has a baseline
ANOMALY_LOOKBACK_H     = 24    # hours of history used to compute the baseline

# ── AI root-cause analysis provider ───────────────────────────────────────────
# Not part of the original project report — added during development. Falls
# back to disabled (no AI analysis) if neither key is configured.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
NVIDIA_API_KEY    = os.getenv("NVIDIA_API_KEY",    "")

# ── WebSocket JWT issuer label ────────────────────────────────────────────────
JWT_ISSUER = os.getenv("SYSMON_JWT_ISSUER", "sysmon-server")
