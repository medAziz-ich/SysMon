"""
AI root-cause analysis for fired alerts.

Not part of the original project report — added during development. Builds
a context-rich prompt from recent metrics/alert history and calls whichever
provider has a configured API key (Anthropic preferred, NVIDIA NIM as a
fallback). Disabled entirely if neither key is set.
"""

import json
import sqlite3
import time

try:
    import urllib.request as urlreq
except ImportError:
    urlreq = None

from . import config

logger = config.logger.getChild("ai_analysis")


# Determine which AI provider to use
if config.ANTHROPIC_API_KEY:
    _AI_PROVIDER = "anthropic"
    _AI_MODEL    = "claude-haiku-4-5"
    logger.info("AI analysis enabled — provider: Anthropic (%s)", _AI_MODEL)
elif config.NVIDIA_API_KEY:
    _AI_PROVIDER = "nvidia"
    _AI_MODEL    = "meta/llama-3.3-70b-instruct"
    logger.info("AI analysis enabled — provider: NVIDIA NIM (%s)", _AI_MODEL)
else:
    _AI_PROVIDER = ""
    logger.info("AI analysis disabled — set ANTHROPIC_API_KEY or NVIDIA_API_KEY to enable")

def _build_ai_prompt(hostname: str, alert_type: str, detail: str,
                     subject: str) -> str:
    """Build a rich context prompt using live DB data."""
    # Fetch last 10 metric snapshots for this host
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    metrics = conn.execute(
        "SELECT timestamp, cpu_percent, ram_percent, raw_json "
        "FROM metrics WHERE hostname=? ORDER BY timestamp DESC LIMIT 10",
        (hostname,)
    ).fetchall()
    # Fetch last 5 alerts for context
    recent_alerts = conn.execute(
        "SELECT alert_type, detail, severity, status, fired_at "
        "FROM alert_history WHERE hostname=? ORDER BY fired_at DESC LIMIT 5",
        (hostname,)
    ).fetchall()
    # Fetch host config
    cfg = conn.execute(
        "SELECT cpu_threshold, ram_threshold, tags FROM host_config WHERE hostname=?",
        (hostname,)
    ).fetchone()
    conn.close()

    # Build metrics summary
    metrics_lines = []
    for m in reversed(metrics):
        t = time.strftime("%H:%M:%S", time.gmtime(m["timestamp"]))
        try:
            raw = json.loads(m["raw_json"])
            disks = ", ".join(
                f"{d.get('path','?')}:{d.get('percent',0):.0f}%"
                for d in raw.get("disks", [])
            )
            svcs  = ", ".join(
                f"{s.get('name','?')}={s.get('status','?')}"
                for s in raw.get("services", [])
            )
        except Exception:
            disks, svcs = "n/a", "n/a"
        metrics_lines.append(
            f"  {t}  CPU={m['cpu_percent']:.1f}%  RAM={m['ram_percent']:.1f}%"
            f"  disks=[{disks}]  services=[{svcs}]"
        )

    alerts_lines = []
    for a in recent_alerts:
        t = time.strftime("%Y-%m-%d %H:%M", time.gmtime(a["fired_at"]))
        alerts_lines.append(f"  [{t}] {a['alert_type']}:{a['detail']} ({a['severity']}) — {a['status']}")

    cpu_thr = cfg["cpu_threshold"] if cfg else 85
    ram_thr = cfg["ram_threshold"] if cfg else 90
    tags    = cfg["tags"] if cfg else ""

    return f"""You are an expert Linux systems administrator and monitoring specialist.
Analyze the following alert and provide a concise, actionable diagnosis.

## Alert
- Host:     {hostname}
- Type:     {alert_type}
- Detail:   {detail}
- Subject:  {subject}
- Tags:     {tags or "none"}
- Thresholds: CPU={cpu_thr}%  RAM={ram_thr}%

## Recent metric history (oldest → newest)
{chr(10).join(metrics_lines) if metrics_lines else "  No recent metrics available"}

## Recent alert history for this host
{chr(10).join(alerts_lines) if alerts_lines else "  No recent alerts"}

## Your response (be concise — 3 sections max)

**Root Cause Analysis** (2-3 sentences): What is most likely causing this alert based on the metrics pattern?

**Recommended Actions** (bullet list, max 4 items): Specific Linux commands or steps the admin should take right now.

**Risk Assessment** (1 sentence): What happens if this is ignored?"""


def _call_anthropic(prompt: str) -> str:
    """Call Anthropic Claude API and return the response text."""
    payload = json.dumps({
        "model":    _AI_MODEL,
        "max_tokens": 600,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urlreq.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         config.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
        }
    )
    with urlreq.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["content"][0]["text"].strip()


def _call_nvidia(prompt: str) -> str:
    """Call NVIDIA NIM API (OpenAI-compatible) and return the response text."""
    payload = json.dumps({
        "model":      _AI_MODEL,
        "max_tokens": 600,
        "messages":   [{"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urlreq.Request(
        "https://integrate.api.nvidia.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {config.NVIDIA_API_KEY}",
        }
    )
    with urlreq.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"].strip()


def _run_ai_analysis(alert_id: int, hostname: str, alert_type: str,
                     detail: str, subject: str) -> None:
    """Call the configured AI provider and store the analysis in the alert row."""
    if not _AI_PROVIDER:
        return  # AI disabled — no key configured

    prompt = _build_ai_prompt(hostname, alert_type, detail, subject)

    try:
        if _AI_PROVIDER == "anthropic":
            analysis = _call_anthropic(prompt)
        else:
            analysis = _call_nvidia(prompt)

        conn = sqlite3.connect(config.DB_PATH)
        conn.execute(
            "UPDATE alert_history SET ai_analysis=? WHERE id=?",
            (analysis, alert_id)
        )
        conn.commit()
        conn.close()
        logger.info("AI analysis stored for alert #%s (via %s)", alert_id, _AI_PROVIDER)

    except urlreq.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        logger.warning("AI analysis failed for alert #%s: HTTP %s — %s", alert_id, e.code, body[:300])
    except Exception as e:
        logger.warning("AI analysis failed for alert #%s: %s", alert_id, e)
