# SysMon — System Monitoring Suite

A lightweight system monitoring solution consisting of:
- **sysmon-agent** — a C daemon that collects CPU, RAM, disk, network, and service metrics
- **sysmon-server** — a FastAPI backend with web dashboard, alerting, and FastAPI-Users auth

---

## Project Structure

```
sysmon/
├── agent/                  # C agent source
│   ├── main.c
│   ├── queue.c / queue.h   # SQLite-backed persistent queue
│   ├── cJSON.c / cJSON.h   # JSON library
│   ├── config.json         # Agent configuration
│   ├── Makefile
│   └── sysmon-agent.service
│
├── server/                 # Python FastAPI server
│   ├── server.py           # thin entry point (creates TLS cert, runs uvicorn)
│   ├── app/                # application package
│   │   ├── config.py       # env-driven settings & tunables
│   │   ├── schemas.py      # Pydantic request/response models
│   │   ├── db.py           # SQLAlchemy models + raw-SQL schema/helpers
│   │   ├── security.py     # CSRF, rate limiting, TLS, SSRF guard, audit log
│   │   ├── websocket.py    # live dashboard push (ws_manager)
│   │   ├── auth.py         # fastapi-users wiring (cookie + JWT)
│   │   ├── agents.py       # agent API-key verification
│   │   ├── ai_analysis.py  # AI root-cause analysis (Anthropic / NVIDIA)
│   │   ├── alerting.py     # thresholds, notifications, anomaly detection
│   │   └── main.py         # FastAPI app, routes, middleware
│   ├── requirements.txt
│   ├── migrate_passwords.py   # one-time legacy dashboard_users -> bcrypt migration
│   ├── seed_demo.py           # populates the DB with realistic demo data
│   └── templates/             # HTML dashboard pages
│       ├── login.html
│       ├── dashboard.html
│       ├── host_detail.html
│       ├── admin.html
│       └── settings.html
│
├── tests/                  # pytest suite
│   ├── test_server.py
│   ├── test_security.py
│   └── conftest.py
│
├── docs/
│   └── sysmon_uml.html     # UML diagrams
│
└── pytest.ini
```

> `server/server.crt`, `server/server.key`, and `server/sysmon.db` are not
> checked in — they're generated on first run (`ensure_tls_cert()` and
> `init_db()` in `server.py`) and are covered by `.gitignore`.

---

## Quick Start — Server

```bash
cd server
pip install -r requirements.txt
export SYSMON_REGISTRATION_SECRET="your-secret-token"
export SYSMON_JWT_SECRET="your-jwt-secret"
python server.py
```

Dashboard → https://localhost:8443
API docs  → https://localhost:8443/docs

---

## Quick Start — Agent

```bash
cd agent

# Edit config.json:
# - set server_url to your server address
# - set registration_secret to match SYSMON_REGISTRATION_SECRET
# - set ca_cert to path of server.crt for SSL verification

make
sudo make install          # creates sysmon user, installs service
sudo systemctl start sysmon-agent
sudo systemctl enable sysmon-agent
```

---

## Running Tests

```bash
pip install pytest pytest-asyncio httpx
pytest tests/ -v
```

---

## Agent Configuration (`config.json`)

```json
{
  "server_url":           "https://YOUR_SERVER_IP:8443/ingest",
  "auth_token":           "",
  "registration_secret":  "your-secret-token",
  "ca_cert":              "/etc/sysmon-agent/server.crt",
  "interval_seconds":     60,
  "disk_paths":           ["/"],
  "network_interfaces":   ["eth0"],
  "services":             ["nginx", "postgresql", "ssh"]
}
```

---

## AI-Assisted Alert Analysis (optional)

When an alert fires, the server can ask an LLM for a root-cause summary based
on the host's recent metrics and alert history. This is entirely optional —
disabled by default, and the rest of the alerting pipeline (thresholds,
email/webhook notifications) works the same with or without it.

To enable it, set **one** of:

```bash
export ANTHROPIC_API_KEY="your-key"   # preferred if both are set
export NVIDIA_API_KEY="your-key"      # NVIDIA NIM fallback
```

With neither set, the server logs `AI analysis disabled` on startup and skips
this step silently. The result (if any) is stored per-alert and returned by
`GET /api/alerts/{alert_id}/analysis`.

---

## Authentication

The primary auth system is **fastapi-users** (cookie + JWT, bcrypt password
hashing, admin-approval workflow for new accounts).

The schema also keeps a `dashboard_users` table with SHA-256 password
hashes — this is a legacy table from an earlier version of the project,
retained only so existing installs can migrate forward via
`server/migrate_passwords.py` rather than losing accounts on upgrade. New
deployments only ever touch the fastapi-users tables; the legacy table plays
no role in day-to-day authentication.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | Agent registers and gets API key |
| `POST` | `/ingest` | Agent posts metrics (Bearer token) |
| `GET`  | `/api/hosts` | List all hosts + online status |
| `GET`  | `/api/metrics/{hostname}` | Time-series metrics |
| `GET`  | `/api/logs/{hostname}` | Recent log events |
| `GET`  | `/api/latest/{hostname}` | Latest snapshot |
| `GET`  | `/api/alerts/{hostname}` | Alert history |
| `GET`  | `/api/alerts/{alert_id}/analysis` | AI root-cause analysis for one alert (if enabled) |
| `GET`  | `/api/users/me` | Current user info |
| `GET`  | `/api/users/pending` | Pending users (superuser) |
| `POST` | `/api/users/{id}/approve` | Approve user (superuser) |

---

## Security Features

- TLS (HTTPS) with self-signed certificate
- Per-agent API keys (SHA-256 hashed in DB)
- FastAPI-Users JWT cookie authentication
- bcrypt password hashing (cost factor 12)
- CSRF protection (double-submit cookie) on all state-changing routes
- SSRF-safe outbound requests for webhook/email-API calls, including on redirects
- Rate limiting on agent API endpoints
- Input validation & hostname sanitization
- Security headers (X-Frame-Options, CSP, HSTS)
- Audit log of security-relevant events (logins, permission denials, CSRF/SSRF blocks)
- Systemd hardening (non-root user, restricted capabilities)
- SSL certificate verification in agent (via `ca_cert`)
