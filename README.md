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
| `GET`  | `/api/users/me` | Current user info |
| `GET`  | `/api/users/pending` | Pending users (superuser) |
| `POST` | `/api/users/{id}/approve` | Approve user (superuser) |

---

## Security Features

- TLS (HTTPS) with self-signed certificate
- Per-agent API keys (SHA-256 hashed in DB)
- FastAPI-Users JWT cookie authentication
- bcrypt password hashing (cost factor 12)
- Rate limiting on agent API endpoints
- Input validation & hostname sanitization
- Security headers (X-Frame-Options, CSP, HSTS)
- Systemd hardening (non-root user, restricted capabilities)
- SSL certificate verification in agent (via `ca_cert`)
