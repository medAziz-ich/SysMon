"""
Alerting engine: per-host thresholds, notification dispatch (email/webhook),
rate-of-change ("spike") detection, and statistical anomaly detection.

`check_alerts()` is the single entry point, called once per ingested metrics
sample. It runs three independent alert families — fixed thresholds, smart
(spike/combined) alerts, and statistical anomaly detection — plus service
up/down transition alerts, each with its own cooldown and auto-resolve.
"""

import collections
import json
import smtplib
import sqlite3
import threading
import time
from email.mime.text import MIMEText
from enum import StrEnum

from fastapi import HTTPException

from . import config
from .ai_analysis import _run_ai_analysis
from .db import EmailProvider, get_settings
from .security import _ssrf_safe_post
from .websocket import ws_manager

logger = config.logger.getChild("alerting")

try:
    import urllib.request as urlreq
except ImportError:
    urlreq = None

# ── Alerting engine ───────────────────────────────────────────────────────────

class AlertLevel(StrEnum):
    """Severity of a fired alert — also used as the webhook embed color key."""
    INFO     = "info"
    WARNING  = "warning"
    CRITICAL = "critical"

def _get_thresholds(hostname: str) -> tuple:
    """Return (cpu_threshold, ram_threshold) for a host, falling back to defaults."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT cpu_threshold, ram_threshold FROM host_config WHERE hostname=?",
        (hostname,)
    ).fetchone()
    conn.close()
    cpu = (row["cpu_threshold"] if row and row["cpu_threshold"] is not None
           else config.DEFAULT_CPU_THRESHOLD)
    ram = (row["ram_threshold"] if row and row["ram_threshold"] is not None
           else config.DEFAULT_RAM_THRESHOLD)
    return cpu, ram

def _get_host_config(hostname: str) -> dict:
    """Return full host config with defaults."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM host_config WHERE hostname=?", (hostname,)
    ).fetchone()
    conn.close()
    cfg = get_settings()
    return {
        "hostname":      hostname,
        "cpu_threshold": row["cpu_threshold"] if row and row["cpu_threshold"] is not None else cfg["alert_cpu"],
        "ram_threshold": row["ram_threshold"] if row and row["ram_threshold"] is not None else cfg["alert_ram"],
        "monitoring":    bool(row["monitoring"]) if row else True,
        "tags":          [t.strip() for t in row["tags"].split(",") if t.strip()] if row and row["tags"] else [],
    }

def _is_monitoring_enabled(hostname: str) -> bool:
    conn = sqlite3.connect(config.DB_PATH)
    row = conn.execute(
        "SELECT monitoring FROM host_config WHERE hostname=?", (hostname,)
    ).fetchone()
    conn.close()
    return bool(row[0]) if row else True  # default: enabled

def _in_cooldown(hostname: str, alert_type: str, detail: str = "") -> bool:
    """Return True if same alert is active within cooldown window."""
    cutoff = int(time.time()) - config.ALERT_COOLDOWN_SEC
    conn = sqlite3.connect(config.DB_PATH)
    row = conn.execute(
        "SELECT id FROM alert_history "
        "WHERE hostname=? AND alert_type=? AND detail=? AND fired_at>? AND status='active'",
        (hostname, alert_type, detail, cutoff)
    ).fetchone()
    conn.close()
    return row is not None

def _record_alert(hostname: str, alert_type: str, detail: str,
                  severity: str, subject: str, body: str) -> int:
    """Insert alert into history, returns new row id."""
    conn = sqlite3.connect(config.DB_PATH)
    cur = conn.execute(
        "INSERT INTO alert_history "
        "(hostname, alert_type, detail, severity, subject, body, status, fired_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (hostname, alert_type, detail, severity, subject, body, "active", int(time.time()))
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id

def _resolve_alert(hostname: str, alert_type: str, detail: str) -> None:
    """Mark matching active alerts as resolved."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(
        "UPDATE alert_history SET status='resolved', resolved_at=? "
        "WHERE hostname=? AND alert_type=? AND detail=? AND status='active'",
        (int(time.time()), hostname, alert_type, detail)
    )
    conn.commit()
    conn.close()

def _send_email_smtp(cfg: dict, subject: str, body: str) -> None:
    if not all([cfg["smtp_host"], cfg["smtp_user"], cfg["smtp_pass"], cfg["alert_to"]]):
        raise RuntimeError("SMTP not configured (host/user/password/recipient missing).")
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = cfg["smtp_user"]
    msg["To"]      = cfg["alert_to"]
    with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as s:
        s.starttls()
        s.login(cfg["smtp_user"], cfg["smtp_pass"])
        s.sendmail(cfg["smtp_user"], cfg["alert_to"].split(","), msg.as_string())

def _send_email_resend(cfg: dict, subject: str, body: str) -> None:
    if not all([cfg["resend_api_key"], cfg["resend_from"], cfg["alert_to"]]):
        raise RuntimeError("Resend not configured (API key/from/recipient missing).")
    payload = json.dumps({
        "from":    cfg["resend_from"],
        "to":      [a.strip() for a in cfg["alert_to"].split(",") if a.strip()],
        "subject": subject,
        "text":    body,
    }).encode("utf-8")
    try:
        resp = _ssrf_safe_post(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {cfg['resend_api_key']}",
                "User-Agent":    "SysMon/1.0",
            },
            timeout=10,
        )
    except urlreq.HTTPError as e:
        # urllib raises on 4xx/5xx instead of returning the response — read the
        # body before it's lost, so we can surface Resend's actual error reason
        # (e.g. "You can only send testing emails to your own email address")
        # instead of a bare "HTTP Error 403: Forbidden".
        err_body = e.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(err_body)
            reason = err_json.get("message") or err_json.get("error") or err_body
        except Exception:
            reason = err_body or str(e)
        raise RuntimeError(f"Resend API error ({e.code}): {reason}") from e

    status = getattr(resp, "status", 200)
    resp_body = resp.read().decode("utf-8", errors="replace")
    resp.close()
    if status >= 300:
        raise RuntimeError(f"Resend API error ({status}): {resp_body[:200]}")

def _send_email(subject: str, body: str) -> None:
    cfg = get_settings()
    full_subject = f"[SysMon Alert] {subject}"
    try:
        if cfg.get("email_provider") == EmailProvider.RESEND:
            _send_email_resend(cfg, full_subject, body)
        else:
            _send_email_smtp(cfg, full_subject, body)
        logger.info("Alert email sent (%s): %s", cfg.get("email_provider", EmailProvider.SMTP), subject)
    except Exception as e:
        logger.warning("Alert email failed: %s", e)

def _send_webhook(subject: str, body: str, level: AlertLevel = AlertLevel.WARNING) -> None:
    cfg = get_settings()
    if not cfg["webhook_url"]:
        return
    color = {AlertLevel.CRITICAL: 15158332, AlertLevel.WARNING: 16776960,
              AlertLevel.INFO: 3447003}.get(level, 16776960)
    payload = json.dumps({
        "username": "SysMon",
        "embeds": [{
            "title":       f"🚨 {subject}",
            "description": body,
            "color":       color,
            "footer":      {"text": "SysMon Alert"},
            "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]
    }).encode("utf-8")
    try:
        resp = _ssrf_safe_post(
            cfg["webhook_url"],
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "SysMon/1.0"},
            timeout=10,
        )
        resp.close()
        logger.info("Alert webhook sent: %s", subject)
    except HTTPException as ssrf_e:
        logger.warning("Alert webhook blocked by SSRF guard: %s", ssrf_e.detail)
    except Exception as e:
        logger.warning("Alert webhook failed: %s", e)

def _fire_alert(hostname: str, alert_type: str, detail: str, subject: str, body: str,
                level: AlertLevel = AlertLevel.WARNING) -> None:
    """Record alert in DB and dispatch notifications + AI analysis in background threads."""
    alert_id = _record_alert(hostname, alert_type, detail, level, subject, body)
    logger.info("ALERT [%s] %s — %s", level.upper(), hostname, subject)
    # Broadcast alert to all connected dashboard clients in real-time
    ws_manager.broadcast_sync({
        "type":       "alert",
        "hostname":   hostname,
        "alert_type": alert_type,
        "detail":     detail,
        "severity":   level,
        "subject":    subject,
        "fired_at":   int(time.time()),
    })
    threading.Thread(target=_send_email,       args=(subject, body),        daemon=True).start()
    threading.Thread(target=_send_webhook,     args=(subject, body, level), daemon=True).start()
    threading.Thread(target=_run_ai_analysis,  args=(alert_id, hostname, alert_type, detail, subject),
                     daemon=True).start()

# ── In-memory sliding window: {hostname: deque([(ts, cpu, ram), ...])} ──────
# Keeps the last N samples per host for rate-of-change (spike) detection.
_metric_history: dict = {}

def _get_baseline(hostname: str) -> dict:
    """
    Compute mean and std deviation of CPU and RAM for the last 24 hours.
    Returns dict with cpu_mean, cpu_std, ram_mean, ram_std, sample_count.
    Returns None if not enough data yet.
    """
    import math
    cutoff = int(time.time()) - config.ANOMALY_LOOKBACK_H * 3600
    conn = sqlite3.connect(config.DB_PATH)
    rows = conn.execute(
        "SELECT cpu_percent, ram_percent FROM metrics "
        "WHERE hostname=? AND timestamp>=? ORDER BY timestamp ASC",
        (hostname, cutoff)
    ).fetchall()
    conn.close()

    n = len(rows)
    if n < config.ANOMALY_MIN_SAMPLES:
        return None   # not enough data yet

    cpus = [r[0] for r in rows]
    rams = [r[1] for r in rows]

    cpu_mean = sum(cpus) / n
    ram_mean = sum(rams) / n
    cpu_std  = math.sqrt(sum((x - cpu_mean)**2 for x in cpus) / n)
    ram_std  = math.sqrt(sum((x - ram_mean)**2 for x in rams) / n)

    return {
        "cpu_mean":     cpu_mean,
        "cpu_std":      cpu_std,
        "cpu_upper":    cpu_mean + config.ANOMALY_STD_MULTIPLIER * cpu_std,
        "ram_mean":     ram_mean,
        "ram_std":      ram_std,
        "ram_upper":    ram_mean + config.ANOMALY_STD_MULTIPLIER * ram_std,
        "sample_count": n,
    }

def _check_anomaly_alerts(hostname: str, cpu: float, ram: float) -> None:
    """
    Fire anomaly alerts if current value exceeds mean + 2σ baseline.
    Resolves when value drops back within normal range.
    """
    baseline = _get_baseline(hostname)
    if baseline is None:
        return   # not enough history yet

    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    n       = baseline["sample_count"]

    # ── CPU anomaly ───────────────────────────────────────────────────────────
    cpu_upper = baseline["cpu_upper"]
    if cpu > cpu_upper and not _in_cooldown(hostname, "cpu", "anomaly"):
        subject = (f"{hostname}: CPU anomaly — {cpu:.1f}% "
                   f"(baseline {baseline['cpu_mean']:.1f}% ±{baseline['cpu_std']:.1f}%)")
        body    = (f"Host:          {hostname}\n"
                   f"Current CPU:   {cpu:.1f}%\n"
                   f"24h mean:       {baseline['cpu_mean']:.1f}%\n"
                   f"24h std dev:    {baseline['cpu_std']:.1f}%\n"
                   f"Upper bound:    {cpu_upper:.1f}% (mean + {config.ANOMALY_STD_MULTIPLIER:.0f}σ)\n"
                   f"Samples used:   {n}\n"
                   f"Time:           {now_str}\n\n"
                   f"This host rarely runs above {cpu_upper:.0f}% CPU.\n"
                   f"Current value is statistically anomalous.")
        _fire_alert(hostname, "cpu", "anomaly", subject, body, AlertLevel.WARNING)
    elif cpu <= cpu_upper:
        _resolve_alert(hostname, "cpu", "anomaly")

    # ── RAM anomaly ───────────────────────────────────────────────────────────
    ram_upper = baseline["ram_upper"]
    if ram > ram_upper and not _in_cooldown(hostname, "ram", "anomaly"):
        subject = (f"{hostname}: RAM anomaly — {ram:.1f}% "
                   f"(baseline {baseline['ram_mean']:.1f}% ±{baseline['ram_std']:.1f}%)")
        body    = (f"Host:          {hostname}\n"
                   f"Current RAM:   {ram:.1f}%\n"
                   f"24h mean:       {baseline['ram_mean']:.1f}%\n"
                   f"24h std dev:    {baseline['ram_std']:.1f}%\n"
                   f"Upper bound:    {ram_upper:.1f}% (mean + {config.ANOMALY_STD_MULTIPLIER:.0f}σ)\n"
                   f"Samples used:   {n}\n"
                   f"Time:           {now_str}\n\n"
                   f"This host rarely runs above {ram_upper:.0f}% RAM.\n"
                   f"Current value is statistically anomalous.")
        _fire_alert(hostname, "ram", "anomaly", subject, body, AlertLevel.WARNING)
    elif ram <= ram_upper:
        _resolve_alert(hostname, "ram", "anomaly")

def _push_history(hostname: str, cpu: float, ram: float) -> None:
    """Append current sample and trim to window size."""
    if hostname not in _metric_history:
        _metric_history[hostname] = collections.deque(maxlen=config.HISTORY_WINDOW)
    _metric_history[hostname].append((time.time(), cpu, ram))

def _cpu_spike(hostname: str, spike_thr: float, spike_win: int) -> float | None:
    """
    Returns delta if CPU rose by spike_thr% within spike_win samples, else None.
    """
    h = _metric_history.get(hostname)
    if not h or len(h) < spike_win + 1:
        return None
    samples  = list(h)
    recent   = [s[1] for s in samples[-spike_win:]]
    baseline = samples[-(spike_win + 1)][1]
    delta    = max(recent) - baseline
    return round(delta, 1) if delta >= spike_thr else None

def _ram_spike(hostname: str, spike_thr: float, spike_win: int) -> float | None:
    """Same logic for RAM."""
    h = _metric_history.get(hostname)
    if not h or len(h) < spike_win + 1:
        return None
    samples  = list(h)
    recent   = [s[2] for s in samples[-spike_win:]]
    baseline = samples[-(spike_win + 1)][2]
    delta    = max(recent) - baseline
    return round(delta, 1) if delta >= spike_thr else None

def _check_smart_alerts(hostname: str, cpu: float, ram: float,
                         cpu_thr: float, ram_thr: float) -> None:
    """
    Smart alert checks — runs after basic threshold checks.
    1. CPU spike   — sudden rise detected via rate-of-change
    2. RAM spike   — same for memory
    3. Combined    — both CPU and RAM above threshold simultaneously → CRITICAL
    """
    cfg       = get_settings()
    spike_thr = float(cfg.get("spike_threshold", config.SPIKE_THRESHOLD))
    spike_win = int(cfg.get("spike_window",      config.SPIKE_WINDOW))
    now_str   = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # ── 1. CPU spike ──────────────────────────────────────────────────────────
    cpu_delta = _cpu_spike(hostname, spike_thr, spike_win)
    if cpu_delta and not _in_cooldown(hostname, "cpu", "spike"):
        subject = f"{hostname}: CPU spike +{cpu_delta:.0f}% detected (now {cpu:.1f}%)"
        body    = (f"Host:    {hostname}\n"
                   f"CPU now: {cpu:.1f}%\n"
                   f"Spike:   +{cpu_delta:.1f}% over {spike_win} samples\n"
                   f"Time:    {now_str}\n\n"
                   f"Rate-of-change alert — threshold may not be breached yet.")
        _fire_alert(hostname, "cpu", "spike", subject, body, AlertLevel.WARNING)
    elif not cpu_delta:
        _resolve_alert(hostname, "cpu", "spike")

    # ── 2. RAM spike ──────────────────────────────────────────────────────────
    ram_delta = _ram_spike(hostname, spike_thr, spike_win)
    if ram_delta and not _in_cooldown(hostname, "ram", "spike"):
        subject = f"{hostname}: RAM spike +{ram_delta:.0f}% detected (now {ram:.1f}%)"
        body    = (f"Host:    {hostname}\n"
                   f"RAM now: {ram:.1f}%\n"
                   f"Spike:   +{ram_delta:.1f}% over {spike_win} samples\n"
                   f"Time:    {now_str}\n\n"
                   f"Rate-of-change alert — threshold may not be breached yet.")
        _fire_alert(hostname, "ram", "spike", subject, body, AlertLevel.WARNING)
    elif not ram_delta:
        _resolve_alert(hostname, "ram", "spike")

    # ── 3. Combined CPU + RAM pressure ────────────────────────────────────────
    both_high = cpu > cpu_thr and ram > ram_thr
    if both_high and not _in_cooldown(hostname, "combined", "cpu+ram"):
        subject = f"{hostname}: CRITICAL — CPU {cpu:.1f}% + RAM {ram:.1f}% both high"
        body    = (f"Host:      {hostname}\n"
                   f"CPU usage: {cpu:.1f}%  (threshold {cpu_thr:.0f}%)\n"
                   f"RAM usage: {ram:.1f}%  (threshold {ram_thr:.0f}%)\n"
                   f"Time:      {now_str}\n\n"
                   f"Combined pressure alert: system is under severe load.\n"
                   f"Investigate running processes or consider scaling.")
        _fire_alert(hostname, "combined", "cpu+ram", subject, body, AlertLevel.CRITICAL)
    elif not both_high:
        _resolve_alert(hostname, "combined", "cpu+ram")


def check_alerts(hostname: str, cpu: float, ram: float, services: list[dict]) -> None:
    """Called on every ingest. Evaluates all alert conditions."""
    if not _is_monitoring_enabled(hostname):
        return
    cfg = get_settings()
    cpu_thr, ram_thr = _get_thresholds(hostname)

    # Feed sliding window — must happen before smart checks
    _push_history(hostname, cpu, ram)

    # ── Basic threshold alerts ────────────────────────────────────────────────
    # CPU
    if cpu > cpu_thr and not _in_cooldown(hostname, "cpu", "high"):
        subject = f"{hostname}: CPU at {cpu:.1f}% (threshold {cpu_thr:.0f}%)"
        body    = (f"Host:      {hostname}\n"
                   f"CPU usage: {cpu:.1f}%\n"
                   f"Threshold: {cpu_thr:.0f}%\n"
                   f"Time:      {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
        _fire_alert(hostname, "cpu", "high", subject, body,
                    AlertLevel.CRITICAL if cpu > 95 else AlertLevel.WARNING)
    elif cpu <= cpu_thr:
        _resolve_alert(hostname, "cpu", "high")

    # RAM
    if ram > ram_thr and not _in_cooldown(hostname, "ram", "high"):
        subject = f"{hostname}: RAM at {ram:.1f}% (threshold {ram_thr:.0f}%)"
        body    = (f"Host:      {hostname}\n"
                   f"RAM usage: {ram:.1f}%\n"
                   f"Threshold: {ram_thr:.0f}%\n"
                   f"Time:      {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
        _fire_alert(hostname, "ram", "high", subject, body,
                    AlertLevel.CRITICAL if ram > 95 else AlertLevel.WARNING)
    elif ram <= ram_thr:
        _resolve_alert(hostname, "ram", "high")

    # ── Smart alerts (rate-of-change + combined) ──────────────────────────────
    _check_smart_alerts(hostname, cpu, ram, cpu_thr, ram_thr)

    # ── Anomaly detection (statistical baseline) ──────────────────────────────
    _check_anomaly_alerts(hostname, cpu, ram)

    # Service alerts — fire only on state transition (up→down or down→up)
    for svc in services:
        name       = svc.get("name", "")
        cur_status = svc.get("status", "unknown")
        is_up      = cur_status in ("active", "running")

        conn = sqlite3.connect(config.DB_PATH)
        conn.row_factory = sqlite3.Row
        prev = conn.execute(
            "SELECT last_status FROM service_state WHERE hostname=? AND service=?",
            (hostname, name)
        ).fetchone()

        prev_status = prev["last_status"] if prev else None
        prev_up     = prev_status in ("active", "running") if prev_status else None

        # Update state
        conn.execute("""
            INSERT INTO service_state (hostname, service, last_status, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(hostname, service) DO UPDATE SET
                last_status=excluded.last_status,
                updated_at=excluded.updated_at
        """, (hostname, name, cur_status, int(time.time())))
        conn.commit()
        conn.close()

        if prev_status is None:
            continue

        # Transition: was up, now down → fire "down" alert
        if prev_up and not is_up:
            subject = f"{hostname}: service '{name}' went DOWN ({cur_status})"
            body    = (f"Host:    {hostname}\n"
                       f"Service: {name}\n"
                       f"Status:  {cur_status}  (was: {prev_status})\n"
                       f"Time:    {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
            _fire_alert(hostname, "service", f"{name}:down", subject, body, AlertLevel.CRITICAL)

        # Transition: was down, now up → auto-resolve the down alert + fire info
        elif not prev_up and is_up:
            _resolve_alert(hostname, "service", f"{name}:down")
            subject = f"{hostname}: service '{name}' RECOVERED ({cur_status})"
            body    = (f"Host:    {hostname}\n"
                       f"Service: {name}\n"
                       f"Status:  {cur_status}  (was: {prev_status})\n"
                       f"Time:    {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
            _fire_alert(hostname, "service", f"{name}:up", subject, body, AlertLevel.INFO)
