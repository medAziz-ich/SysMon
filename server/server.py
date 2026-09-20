"""
sysmon-server entry point.

Thin launcher: creates/loads the TLS certificate and starts uvicorn. All
application code lives in the `app` package (see app/main.py for the
FastAPI app and routes). Re-exports a handful of internals for the test
suite, which exercises them directly (tests/conftest.py, tests/test_*.py).
"""

import os
from pathlib import Path

from app import config
from app.agents import _lookup_key, verify_agent
from app.ai_analysis import _run_ai_analysis
from app.alerting import (_cpu_spike, _get_thresholds, _in_cooldown,
                          _metric_history, _push_history, _ram_spike,
                          _record_alert, _resolve_alert, _send_email,
                          _send_webhook, check_alerts)
from app.auth import current_active_user, require_session
from app.db import (Base, _hash, get_settings, init_db, purge_old_data,
                    save_setting)
from app.main import app
from app.security import (_CSRF_COOKIE, _CSRF_HEADER, _check_rate_limit,
                          _rate_buckets, _SSRFGuardRedirectHandler,
                          _validate_webhook_url, ensure_tls_cert)
from app.websocket import _validate_ws_token, ws_manager

# Re-exported for tests / ops tooling that reach for these directly.
DB_PATH             = config.DB_PATH
REGISTRATION_SECRET = config.REGISTRATION_SECRET
DEFAULT_CPU_THRESHOLD = config.DEFAULT_CPU_THRESHOLD
DEFAULT_RAM_THRESHOLD = config.DEFAULT_RAM_THRESHOLD
ALERT_COOLDOWN_SEC    = config.ALERT_COOLDOWN_SEC
RATE_LIMIT_REQUESTS   = config.RATE_LIMIT_REQUESTS
RATE_LIMIT_WINDOW     = config.RATE_LIMIT_WINDOW
RETAIN_HOURS          = config.RETAIN_HOURS
HISTORY_WINDOW        = config.HISTORY_WINDOW
JWT_SECRET            = config.JWT_SECRET
COOKIE_SECURE         = config.COOKIE_SECURE
TLS_CERT              = config.TLS_CERT
TLS_KEY               = config.TLS_KEY

if __name__ == "__main__":
    import uvicorn

    ensure_tls_cert()
    tls_available = Path(config.TLS_CERT).exists() and Path(config.TLS_KEY).exists()
    if tls_available:
        print("🔒 Starting on https://0.0.0.0:8443")
        print(f"   Registration secret : {'*' * len(config.REGISTRATION_SECRET)}  (set via SYSMON_REGISTRATION_SECRET)")
        print(f"   Default CPU alert   : {config.DEFAULT_CPU_THRESHOLD}%")
        print(f"   Default RAM alert   : {config.DEFAULT_RAM_THRESHOLD}%")
        print(f"   Email alerts        : {'✔' if config._SMTP_HOST_DEFAULT else '✘ (configure at /settings)'}")
        print(f"   Webhook alerts      : {'✔' if config._WEBHOOK_URL_DEFAULT else '✘ (configure at /settings)'}")
        uvicorn.run("server:app", host="0.0.0.0", port=8443,
                    ssl_certfile=config.TLS_CERT, ssl_keyfile=config.TLS_KEY, reload=False)
    else:
        print("⚠ Starting on http://0.0.0.0:8000 (no TLS)")
        uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
