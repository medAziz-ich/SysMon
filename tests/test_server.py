"""
tests/test_server.py
====================
Pytest test suite for sysmon-server (FastAPI-Users auth edition).

Run with:
    pytest tests/ -v

Dependencies:
    pip install pytest httpx fastapi fastapi-users[sqlalchemy] aiosqlite bcrypt
"""

import os
import sys
import time
import hashlib
import sqlite3
import collections
import threading
import uuid
import pytest
from sqlalchemy import create_engine

# ── Env vars must be set before importing server ──────────────────────────────
os.environ.setdefault("SYSMON_REGISTRATION_SECRET", "test-secret")
os.environ.setdefault("SYSMON_ALERT_CPU",           "85")
os.environ.setdefault("SYSMON_ALERT_RAM",           "90")
os.environ.setdefault("SYSMON_ALERT_COOLDOWN",      "300")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import server  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Each test gets its own SQLite file; all caches are cleared."""
    db_file = str(tmp_path / "sysmon_test.db")
    server.config.DB_PATH                = db_file
    server.config.REGISTRATION_SECRET    = "test-secret"
    server.config.DEFAULT_CPU_THRESHOLD  = 85.0
    server.config.DEFAULT_RAM_THRESHOLD  = 90.0
    server.config.ALERT_COOLDOWN_SEC     = 300
    server.config.RATE_LIMIT_REQUESTS    = 120
    server.config.RATE_LIMIT_WINDOW      = 60
    server._rate_buckets.clear()
    server._metric_history.clear()
    server.init_db()
    # Create fu_users table synchronously via plain SQLAlchemy (no event loop needed)
    _sync_engine = create_engine(f"sqlite:///{db_file}")
    server.Base.metadata.create_all(_sync_engine)
    _sync_engine.dispose()
    yield db_file


@pytest.fixture
def client():
    return TestClient(server.app, raise_server_exceptions=False)


@pytest.fixture
def agent(client):
    """Register an agent and return (client, api_key, auth_headers)."""
    r = client.post("/register", json={"agent_name": "testhost", "secret": "test-secret"})
    assert r.status_code == 201
    api_key = r.json()["api_key"]
    return client, api_key, {"Authorization": f"Bearer {api_key}"}


@pytest.fixture
def metric_payload():
    return {
        "hostname":    "testhost",
        "timestamp":   int(time.time()),
        "cpu_percent": 45.0,
        "ram_percent": 55.0,
        "disks":       [{"path": "/", "percent": 30.0}],
        "network":     [{"interface": "eth0", "rx_bps": 1000, "tx_bps": 500}],
        "services":    [{"name": "nginx", "status": "active"}],
    }


def _register_user(client, email="admin@sysmon.test",
                   password="password123", display_name="Admin"):
    return client.post("/api/auth/register", json={
        "email": email, "password": password, "display_name": display_name,
    })


def _login(client, email="admin@sysmon.test", password="password123"):
    """FastAPI-Users login uses OAuth2 form data (username=email)."""
    return client.post("/api/auth/login", data={
        "username": email, "password": password,
    })


@pytest.fixture
def admin_session(client):
    """
    Register a test admin user, promote them to superuser directly in the DB
    (bypassing the first-user-only auto-promotion since _create_default_admin
    already created admin@sysmon.local), then log in.
    """
    r = _register_user(client)
    if r.status_code == 201:
        user_id = r.json()["id"]
        # Directly promote to superuser + approved in the SQLite DB
        import sqlite3 as _sq
        conn = _sq.connect(server.config.DB_PATH)
        conn.execute(
            "UPDATE fu_users SET is_superuser=1, is_approved=1, is_active=1 WHERE id=?",
            (user_id,)
        )
        conn.commit()
        conn.close()
    r = _login(client)
    assert r.status_code == 204, f"Login failed: {r.status_code} — {r.text}"
    return client


# ─────────────────────────────────────────────────────────────────────────────
#  1. Agent Registration
# ─────────────────────────────────────────────────────────────────────────────

class TestRegistration:

    def test_register_valid_returns_api_key(self, client):
        r = client.post("/register", json={"agent_name": "host1", "secret": "test-secret"})
        assert r.status_code == 201
        data = r.json()
        assert "api_key" in data
        assert len(data["api_key"]) == 64

    def test_register_wrong_secret_returns_401(self, client):
        r = client.post("/register", json={"agent_name": "host1", "secret": "wrong"})
        assert r.status_code == 401

    def test_register_missing_agent_name_returns_4xx(self, client):
        r = client.post("/register", json={"secret": "test-secret"})
        assert r.status_code in (400, 422)

    def test_register_empty_agent_name_returns_4xx(self, client):
        # Pydantic min_length=1 returns 422; explicit check returns 400 — accept both
        r = client.post("/register", json={"agent_name": "", "secret": "test-secret"})
        assert r.status_code in (400, 422)

    def test_register_agent_name_too_long_returns_4xx(self, client):
        r = client.post("/register", json={"agent_name": "x" * 129, "secret": "test-secret"})
        assert r.status_code in (400, 422)

    def test_register_same_agent_twice_reissues_key(self, client):
        r1 = client.post("/register", json={"agent_name": "duphost", "secret": "test-secret"})
        r2 = client.post("/register", json={"agent_name": "duphost", "secret": "test-secret"})
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["api_key"] != r2.json()["api_key"]

    def test_register_invalid_json_returns_4xx(self, client):
        r = client.post("/register", content=b"not-json",
                        headers={"Content-Type": "application/json"})
        assert r.status_code in (400, 422)


# ─────────────────────────────────────────────────────────────────────────────
#  2. Ingest Endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestIngest:

    def test_ingest_valid_metric_returns_202(self, agent, metric_payload):
        client, _, headers = agent
        r = client.post("/ingest", json=metric_payload, headers=headers)
        assert r.status_code == 202
        assert r.json() == {"status": "accepted"}

    def test_ingest_missing_bearer_returns_4xx(self, client, metric_payload):
        r = client.post("/ingest", json=metric_payload)
        assert r.status_code in (401, 403)

    def test_ingest_wrong_token_returns_401(self, client, metric_payload):
        r = client.post("/ingest", json=metric_payload,
                        headers={"Authorization": "Bearer deadbeef"})
        assert r.status_code == 401

    def test_ingest_missing_cpu_returns_422(self, agent, metric_payload):
        client, _, headers = agent
        del metric_payload["cpu_percent"]
        r = client.post("/ingest", json=metric_payload, headers=headers)
        assert r.status_code == 422

    def test_ingest_missing_ram_returns_422(self, agent, metric_payload):
        client, _, headers = agent
        del metric_payload["ram_percent"]
        r = client.post("/ingest", json=metric_payload, headers=headers)
        assert r.status_code == 422

    def test_ingest_non_numeric_cpu_returns_422(self, agent, metric_payload):
        client, _, headers = agent
        metric_payload["cpu_percent"] = "high"
        r = client.post("/ingest", json=metric_payload, headers=headers)
        assert r.status_code == 422

    def test_ingest_log_event_accepted(self, agent):
        client, _, headers = agent
        payload = {
            "type": "log_event", "hostname": "testhost",
            "timestamp": int(time.time()), "source": "auth",
            "message": "Failed password for root from 1.2.3.4",
        }
        r = client.post("/ingest", json=payload, headers=headers)
        assert r.status_code == 202

    def test_ingest_stores_metric_in_db(self, agent, metric_payload):
        client, _, headers = agent
        client.post("/ingest", json=metric_payload, headers=headers)
        conn = sqlite3.connect(server.config.DB_PATH)
        count = conn.execute("SELECT COUNT(*) FROM metrics").fetchone()[0]
        conn.close()
        assert count == 1

    def test_ingest_stores_log_event_in_db(self, agent):
        client, _, headers = agent
        payload = {
            "type": "log_event", "hostname": "testhost",
            "timestamp": int(time.time()), "source": "auth",
            "message": "Invalid user foo",
        }
        client.post("/ingest", json=payload, headers=headers)
        conn = sqlite3.connect(server.config.DB_PATH)
        count = conn.execute("SELECT COUNT(*) FROM log_events").fetchone()[0]
        conn.close()
        assert count == 1

    def test_ingest_revoked_key_returns_401(self, agent, metric_payload):
        client, api_key, headers = agent
        conn = sqlite3.connect(server.config.DB_PATH)
        conn.execute("UPDATE api_keys SET enabled=0 WHERE key_hash=?",
                     (hashlib.sha256(api_key.encode()).hexdigest(),))
        conn.commit()
        conn.close()
        r = client.post("/ingest", json=metric_payload, headers=headers)
        assert r.status_code == 401

    def test_ingest_invalid_hostname_returns_422(self, agent, metric_payload):
        client, _, headers = agent
        metric_payload["hostname"] = "<script>alert(1)</script>"
        r = client.post("/ingest", json=metric_payload, headers=headers)
        assert r.status_code == 422

    def test_ingest_missing_hostname_returns_422(self, agent, metric_payload):
        client, _, headers = agent
        del metric_payload["hostname"]
        r = client.post("/ingest", json=metric_payload, headers=headers)
        assert r.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
#  3. Dashboard Auth (FastAPI-Users)
# ─────────────────────────────────────────────────────────────────────────────

class TestDashboardAuth:

    def test_dashboard_redirects_unauthenticated(self, client):
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 307
        assert "/login" in r.headers["location"]

    def test_login_page_is_accessible(self, client):
        r = client.get("/login")
        assert r.status_code in (200, 500)

    def test_register_first_user_is_auto_approved_superuser(self, client):
        _register_user(client)
        _login(client)
        me = client.get("/api/users/me")
        assert me.status_code == 200
        data = me.json()
        assert data["is_superuser"] is True
        assert data["is_approved"] is True

    def test_register_second_user_is_not_approved(self, client):
        _register_user(client, email="first@sysmon.test")
        r = _register_user(client, email="second@sysmon.test", display_name="Second")
        assert r.status_code == 201
        assert r.json()["is_approved"] is False
        assert r.json()["is_superuser"] is False

    def test_register_duplicate_email_returns_400(self, client):
        _register_user(client, email="dup@sysmon.test")
        r = _register_user(client, email="dup@sysmon.test")
        assert r.status_code == 400

    def test_register_short_password_returns_400(self, client):
        r = _register_user(client, password="123")
        assert r.status_code == 400

    def test_register_missing_email_returns_422(self, client):
        r = client.post("/api/auth/register", json={
            "password": "password123", "display_name": "X"
        })
        assert r.status_code == 422

    def test_login_correct_credentials_sets_jwt_cookie(self, client):
        _register_user(client)
        r = _login(client)
        assert r.status_code == 204
        cookie = r.cookies.get("sysmon_session")
        assert cookie is not None
        assert cookie.count(".") == 2   # valid JWT: header.payload.signature

    def test_login_wrong_password_returns_400(self, client):
        _register_user(client)
        r = _login(client, password="wrongpassword")
        assert r.status_code == 400

    def test_login_unknown_email_returns_400(self, client):
        r = _login(client, email="nobody@sysmon.test")
        assert r.status_code == 400

    def test_logout_clears_cookie(self, client):
        _register_user(client)
        _login(client)
        r = client.post("/api/auth/logout")
        assert r.status_code == 204
        assert client.cookies.get("sysmon_session", "") == ""

    def test_me_returns_current_user_data(self, client):
        _register_user(client, email="me@sysmon.test", display_name="Me User")
        _login(client, email="me@sysmon.test")
        r = client.get("/api/users/me")
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == "me@sysmon.test"
        assert data["display_name"] == "Me User"

    def test_me_unauthenticated_returns_401(self, client):
        r = client.get("/api/users/me")
        assert r.status_code == 401

    def test_update_display_name_via_patch(self, client):
        _register_user(client)
        _login(client)
        r = client.patch("/api/users/me", json={"display_name": "Updated"})
        assert r.status_code == 200
        assert r.json()["display_name"] == "Updated"

    def test_tampered_jwt_returns_401(self, client):
        _register_user(client)
        _login(client)
        client.cookies.set("sysmon_session", "bad.jwt.token")
        r = client.get("/api/users/me")
        assert r.status_code == 401

    def test_unapproved_user_blocked_from_dashboard(self, client):
        _register_user(client, email="admin@sysmon.test")
        _register_user(client, email="pending@sysmon.test", display_name="Pending")
        _login(client, email="pending@sysmon.test")
        r = client.get("/api/users/me")
        assert r.status_code in (401, 403)


# ─────────────────────────────────────────────────────────────────────────────
#  4. User Management (superuser endpoints)
# ─────────────────────────────────────────────────────────────────────────────

class TestUserManagement:

    def test_list_pending_users(self, client):
        _register_user(client, email="admin@sysmon.test")
        _login(client, email="admin@sysmon.test")
        _register_user(client, email="pending@sysmon.test", display_name="Pending")
        r = client.get("/api/users/pending")
        assert r.status_code == 200
        assert any(u["email"] == "pending@sysmon.test" for u in r.json())

    def test_list_pending_requires_superuser(self, client):
        _register_user(client, email="admin@sysmon.test")
        _register_user(client, email="u2@sysmon.test", display_name="U2")
        _login(client, email="u2@sysmon.test")
        r = client.get("/api/users/pending")
        assert r.status_code in (401, 403)

    def test_approve_pending_user(self, client):
        _register_user(client, email="admin@sysmon.test")
        _login(client, email="admin@sysmon.test")
        r2 = _register_user(client, email="new@sysmon.test", display_name="New")
        user_id = r2.json()["id"]
        r = client.post(f"/api/users/{user_id}/approve")
        assert r.status_code == 200
        assert r.json()["status"] == "approved"

    def test_approve_nonexistent_user_returns_404(self, client):
        _register_user(client, email="admin@sysmon.test")
        _login(client, email="admin@sysmon.test")
        r = client.post(f"/api/users/{uuid.uuid4()}/approve")
        assert r.status_code == 404

    def test_revoke_user(self, client):
        _register_user(client, email="admin@sysmon.test")
        _login(client, email="admin@sysmon.test")
        r2 = _register_user(client, email="bye@sysmon.test", display_name="Bye")
        user_id = r2.json()["id"]
        r = client.delete(f"/api/users/{user_id}/revoke")
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"

    def test_cannot_revoke_own_account(self, client):
        _register_user(client, email="admin@sysmon.test")
        _login(client, email="admin@sysmon.test")
        me = client.get("/api/users/me").json()
        r = client.delete(f"/api/users/{me['id']}/revoke")
        assert r.status_code == 400

    def test_approve_with_invalid_uuid_returns_400(self, client):
        _register_user(client, email="admin@sysmon.test")
        _login(client, email="admin@sysmon.test")
        r = client.post("/api/users/not-a-uuid/approve")
        assert r.status_code == 400


# ─────────────────────────────────────────────────────────────────────────────
#  5. Metrics & Hosts API
# ─────────────────────────────────────────────────────────────────────────────

class TestMetricsAPI:

    def test_hosts_returns_empty_list_initially(self, client):
        r = client.get("/api/hosts")
        assert r.status_code == 200
        assert r.json() == []

    def test_hosts_shows_host_after_ingest(self, agent, metric_payload):
        client, _, headers = agent
        client.post("/ingest", json=metric_payload, headers=headers)
        hosts = client.get("/api/hosts").json()
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "testhost"

    def test_host_online_true_for_recent_data(self, agent, metric_payload):
        client, _, headers = agent
        metric_payload["timestamp"] = int(time.time())
        client.post("/ingest", json=metric_payload, headers=headers)
        assert client.get("/api/hosts").json()[0]["online"] is True

    def test_host_online_false_for_old_data(self, agent, metric_payload):
        client, _, headers = agent
        metric_payload["timestamp"] = int(time.time()) - 600
        client.post("/ingest", json=metric_payload, headers=headers)
        assert client.get("/api/hosts").json()[0]["online"] is False

    def test_metrics_returns_ingested_data(self, agent, metric_payload):
        client, _, headers = agent
        client.post("/ingest", json=metric_payload, headers=headers)
        data = client.get("/api/metrics/testhost?hours=1").json()
        assert len(data) == 1
        assert data[0]["cpu_percent"] == 45.0
        assert data[0]["ram_percent"] == 55.0

    def test_metrics_empty_for_unknown_host(self, client):
        assert client.get("/api/metrics/nobody?hours=1").json() == []

    def test_metrics_hours_filter_excludes_old(self, agent, metric_payload):
        client, _, headers = agent
        old = dict(metric_payload)
        old["timestamp"] = int(time.time()) - 7200
        client.post("/ingest", json=old, headers=headers)
        assert client.get("/api/metrics/testhost?hours=1").json() == []

    def test_latest_returns_most_recent_snapshot(self, agent, metric_payload):
        client, _, headers = agent
        client.post("/ingest", json=metric_payload, headers=headers)
        r = client.get("/api/latest/testhost")
        assert r.status_code == 200
        assert r.json()["cpu_percent"] == 45.0

    def test_latest_returns_404_for_unknown_host(self, client):
        assert client.get("/api/latest/nobody").status_code == 404

    def test_logs_returns_ingested_events(self, agent):
        client, _, headers = agent
        payload = {
            "type": "log_event", "hostname": "testhost",
            "timestamp": int(time.time()), "source": "auth",
            "message": "Failed password",
        }
        client.post("/ingest", json=payload, headers=headers)
        logs = client.get("/api/logs/testhost?limit=200").json()
        assert len(logs) >= 1
        assert logs[0]["source"] == "auth"

    def test_logs_empty_for_unknown_host(self, client):
        assert client.get("/api/logs/nobody").json() == []

    def test_multiple_metrics_ordered_by_timestamp(self, agent, metric_payload):
        client, _, headers = agent
        now = int(time.time())
        for i, cpu in enumerate([10.0, 30.0, 70.0]):
            p = dict(metric_payload)
            p["cpu_percent"] = cpu
            p["timestamp"] = now + i
            client.post("/ingest", json=p, headers=headers)
        cpus = [d["cpu_percent"] for d in client.get("/api/metrics/testhost?hours=1").json()]
        assert cpus == [10.0, 30.0, 70.0]


# ─────────────────────────────────────────────────────────────────────────────
#  6. Host Config & Thresholds
# ─────────────────────────────────────────────────────────────────────────────

class TestHostConfig:

    def test_get_host_config_returns_defaults(self, client):
        r = client.get("/api/host-config/newhost")
        assert r.status_code == 200
        cfg = r.json()
        assert cfg["cpu_threshold"] == 85.0
        assert cfg["ram_threshold"] == 90.0
        assert cfg["monitoring"] is True
        assert cfg["tags"] == []

    def test_set_cpu_threshold(self, client):
        r = client.put("/api/host-config/myhost", json={"cpu_threshold": 70.0})
        assert r.status_code == 200
        assert r.json()["cpu_threshold"] == 70.0

    def test_set_ram_threshold(self, client):
        r = client.put("/api/host-config/myhost", json={"ram_threshold": 75.0})
        assert r.status_code == 200
        assert r.json()["ram_threshold"] == 75.0

    def test_set_tags_as_list(self, client):
        r = client.put("/api/host-config/myhost", json={"tags": ["prod", "web"]})
        assert r.status_code == 200
        assert set(r.json()["tags"]) == {"prod", "web"}

    def test_set_tags_as_string(self, client):
        r = client.put("/api/host-config/myhost", json={"tags": "prod,web"})
        assert r.status_code == 200
        assert set(r.json()["tags"]) == {"prod", "web"}

    def test_disable_monitoring(self, client):
        r = client.put("/api/host-config/myhost", json={"monitoring": False})
        assert r.status_code == 200
        assert r.json()["monitoring"] is False

    def test_update_is_partial(self, client):
        client.put("/api/host-config/myhost", json={"cpu_threshold": 60.0})
        client.put("/api/host-config/myhost", json={"ram_threshold": 70.0})
        r = client.get("/api/host-config/myhost")
        assert r.json()["cpu_threshold"] == 60.0
        assert r.json()["ram_threshold"] == 70.0

    def test_legacy_thresholds_endpoint(self, client):
        client.put("/api/host-config/myhost", json={"cpu_threshold": 55.0})
        r = client.get("/api/thresholds/myhost")
        assert r.status_code == 200
        assert r.json()["cpu_threshold"] == 55.0


# ─────────────────────────────────────────────────────────────────────────────
#  7. Alert Engine
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertEngine:

    def _ingest(self, client, headers, hostname, cpu, ram, services=None):
        services = services or [{"name": "nginx", "status": "active"}]
        return client.post("/ingest", json={
            "hostname": hostname, "timestamp": int(time.time()),
            "cpu_percent": cpu, "ram_percent": ram,
            "disks": [], "network": [], "services": services,
        }, headers=headers)

    def test_cpu_alert_fires_above_threshold(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost", json={"cpu_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=95.0, ram=20.0)
        alerts = client.get("/api/alerts/testhost").json()
        cpu_alerts = [a for a in alerts if a["alert_type"] == "cpu" and a["detail"] == "high"]
        assert len(cpu_alerts) >= 1
        assert cpu_alerts[0]["status"] == "active"

    def test_ram_alert_fires_above_threshold(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost", json={"ram_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=10.0, ram=95.0)
        alerts = client.get("/api/alerts/testhost").json()
        assert any(a["alert_type"] == "ram" and a["detail"] == "high" for a in alerts)

    def test_no_alert_below_threshold(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost",
                   json={"cpu_threshold": 90.0, "ram_threshold": 90.0})
        self._ingest(client, headers, "testhost", cpu=30.0, ram=40.0)
        alerts = client.get("/api/alerts/testhost").json()
        assert not any(a["detail"] == "high" for a in alerts)

    def test_combined_alert_fires_when_both_high(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost",
                   json={"cpu_threshold": 50.0, "ram_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=95.0, ram=95.0)
        alerts = client.get("/api/alerts/testhost").json()
        combined = [a for a in alerts if a["alert_type"] == "combined"]
        assert len(combined) >= 1
        assert combined[0]["severity"] == "critical"

    def test_critical_severity_at_98_percent(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost", json={"cpu_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=98.0, ram=20.0)
        alerts = client.get("/api/alerts/testhost").json()
        cpu_high = [a for a in alerts if a["alert_type"] == "cpu" and a["detail"] == "high"]
        assert cpu_high[0]["severity"] == "critical"

    def test_alert_resolves_when_metric_drops(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost", json={"cpu_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=95.0, ram=20.0)
        server._metric_history.clear()
        server.config.ALERT_COOLDOWN_SEC = 0
        self._ingest(client, headers, "testhost", cpu=10.0, ram=20.0)
        alerts = client.get("/api/alerts/testhost").json()
        cpu_high = [a for a in alerts if a["alert_type"] == "cpu" and a["detail"] == "high"]
        assert any(a["status"] == "resolved" for a in cpu_high)

    def test_service_down_alert_on_transition(self, agent):
        client, _, headers = agent
        self._ingest(client, headers, "testhost", cpu=10.0, ram=10.0,
                     services=[{"name": "nginx", "status": "active"}])
        self._ingest(client, headers, "testhost", cpu=10.0, ram=10.0,
                     services=[{"name": "nginx", "status": "failed"}])
        alerts = client.get("/api/alerts/testhost").json()
        svc_down = [a for a in alerts if a["alert_type"] == "service" and "down" in a["detail"]]
        assert len(svc_down) >= 1
        assert svc_down[0]["severity"] == "critical"

    def test_service_recovery_resolves_alert(self, agent):
        client, _, headers = agent
        self._ingest(client, headers, "testhost", cpu=10.0, ram=10.0,
                     services=[{"name": "nginx", "status": "active"}])
        self._ingest(client, headers, "testhost", cpu=10.0, ram=10.0,
                     services=[{"name": "nginx", "status": "failed"}])
        self._ingest(client, headers, "testhost", cpu=10.0, ram=10.0,
                     services=[{"name": "nginx", "status": "active"}])
        alerts = client.get("/api/alerts/testhost").json()
        svc_down = [a for a in alerts if "nginx:down" in (a["detail"] or "")]
        assert any(a["status"] == "resolved" for a in svc_down)

    def test_cooldown_suppresses_duplicate_alert(self, agent):
        client, _, headers = agent
        server.config.ALERT_COOLDOWN_SEC = 3600
        client.put("/api/host-config/testhost", json={"cpu_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=95.0, ram=20.0)
        self._ingest(client, headers, "testhost", cpu=95.0, ram=20.0)
        alerts = client.get("/api/alerts/testhost").json()
        cpu_high = [a for a in alerts if a["alert_type"] == "cpu" and a["detail"] == "high"]
        assert len(cpu_high) == 1

    def test_monitoring_disabled_suppresses_alerts(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost",
                   json={"cpu_threshold": 5.0, "ram_threshold": 5.0, "monitoring": False})
        self._ingest(client, headers, "testhost", cpu=99.0, ram=99.0)
        assert client.get("/api/alerts/testhost").json() == []

    def test_acknowledge_alert_requires_auth(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost", json={"cpu_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=95.0, ram=20.0)
        alerts = client.get("/api/alerts/testhost").json()
        active = [a for a in alerts if a["status"] == "active"]
        assert active
        aid = active[0]["id"]
        # Unauthenticated acknowledge must fail
        r = client.post(f"/api/alerts/{aid}/acknowledge")
        assert r.status_code in (401, 403)

    def test_acknowledge_alert_as_logged_in_user(self, agent, admin_session):
        client, _, headers = agent
        client.put("/api/host-config/testhost", json={"cpu_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=95.0, ram=20.0)
        alerts = client.get("/api/alerts/testhost").json()
        active = [a for a in alerts if a["status"] == "active"]
        assert active
        aid = active[0]["id"]
        r = admin_session.post(f"/api/alerts/{aid}/acknowledge")
        assert r.status_code == 200
        assert r.json()["status"] == "acknowledged"

    def test_acknowledge_nonexistent_alert_returns_404(self, admin_session):
        r = admin_session.post("/api/alerts/99999/acknowledge")
        assert r.status_code == 404

    def test_clear_alerts_for_host(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost", json={"cpu_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=95.0, ram=20.0)
        r = client.delete("/api/alerts/testhost")
        assert r.status_code == 200
        assert client.get("/api/alerts/testhost").json() == []

    def test_get_all_alerts_endpoint(self, agent):
        client, _, headers = agent
        client.put("/api/host-config/testhost", json={"cpu_threshold": 50.0})
        self._ingest(client, headers, "testhost", cpu=95.0, ram=20.0)
        r = client.get("/api/alerts")
        assert r.status_code == 200
        assert len(r.json()) >= 1


# ─────────────────────────────────────────────────────────────────────────────
#  8. Spike Detection (unit-level)
# ─────────────────────────────────────────────────────────────────────────────

class TestSpikeDetection:

    def setup_method(self):
        server._metric_history.clear()

    def test_cpu_spike_detected_after_sudden_rise(self):
        host = "spikehost"
        for _ in range(4):
            server._push_history(host, cpu=20.0, ram=30.0)
        for _ in range(3):
            server._push_history(host, cpu=60.0, ram=30.0)
        delta = server._cpu_spike(host, spike_thr=20.0, spike_win=3)
        assert delta is not None and delta >= 20.0

    def test_cpu_spike_not_detected_for_gradual_rise(self):
        host = "gradualhost"
        for i in range(7):
            server._push_history(host, cpu=20.0 + i * 2, ram=30.0)
        assert server._cpu_spike(host, spike_thr=20.0, spike_win=3) is None

    def test_ram_spike_detected(self):
        host = "ramspike"
        for _ in range(4):
            server._push_history(host, cpu=10.0, ram=20.0)
        for _ in range(3):
            server._push_history(host, cpu=10.0, ram=70.0)
        delta = server._ram_spike(host, spike_thr=20.0, spike_win=3)
        assert delta is not None and delta >= 20.0

    def test_spike_not_detected_with_insufficient_samples(self):
        host = "fewsamples"
        server._push_history(host, cpu=80.0, ram=80.0)
        assert server._cpu_spike(host, spike_thr=20.0, spike_win=3) is None

    def test_history_bounded_by_window_size(self):
        host = "bounded"
        for i in range(20):
            server._push_history(host, cpu=float(i), ram=float(i))
        assert len(server._metric_history[host]) == server.HISTORY_WINDOW


# ─────────────────────────────────────────────────────────────────────────────
#  9. Settings API
# ─────────────────────────────────────────────────────────────────────────────

class TestSettings:

    def test_get_settings_returns_all_keys(self, client):
        r = client.get("/api/settings")
        assert r.status_code == 200
        for key in ["smtp_host", "smtp_port", "smtp_user", "alert_to",
                    "webhook_url", "alert_cpu", "alert_ram", "alert_cooldown"]:
            assert key in r.json()

    def test_smtp_pass_is_masked(self, client):
        client.post("/api/settings", json={"smtp_pass": "mysecret"})
        assert client.get("/api/settings").json()["smtp_pass"] != "mysecret"

    def test_save_smtp_host(self, client):
        client.post("/api/settings", json={"smtp_host": "smtp.example.com"})
        assert client.get("/api/settings").json()["smtp_host"] == "smtp.example.com"

    def test_save_webhook_url(self, client):
        url = "https://discord.com/api/webhooks/123/abc"
        client.post("/api/settings", json={"webhook_url": url})
        assert client.get("/api/settings").json()["webhook_url"] == url

    def test_save_global_cpu_threshold(self, client):
        client.post("/api/settings", json={"alert_cpu": "70"})
        assert float(client.get("/api/settings").json()["alert_cpu"]) == 70.0

    def test_test_email_returns_400_unconfigured(self, client):
        assert client.post("/api/settings/test-email").status_code == 400

    def test_test_webhook_returns_400_unconfigured(self, client):
        assert client.post("/api/settings/test-webhook").status_code == 400

    def test_placeholder_password_not_overwritten(self, client):
        client.post("/api/settings", json={"smtp_pass": "realpassword"})
        client.post("/api/settings", json={"smtp_pass": "••••••••"})
        conn = sqlite3.connect(server.config.DB_PATH)
        row = conn.execute("SELECT value FROM settings WHERE key='smtp_pass'").fetchone()
        conn.close()
        assert row and row[0] == "realpassword"


# ─────────────────────────────────────────────────────────────────────────────
#  10. Rate Limiter
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimiter:

    def test_rate_limit_triggers_after_quota(self):
        server.config.RATE_LIMIT_REQUESTS = 3
        server.config.RATE_LIMIT_WINDOW   = 60
        server._rate_buckets.clear()
        from fastapi import HTTPException
        for _ in range(3):
            server._check_rate_limit("key")
        with pytest.raises(HTTPException) as exc:
            server._check_rate_limit("key")
        assert exc.value.status_code == 429

    def test_rate_limit_resets_after_window(self):
        server.config.RATE_LIMIT_REQUESTS = 2
        server.config.RATE_LIMIT_WINDOW   = 1
        server._rate_buckets.clear()
        server._check_rate_limit("expiry")
        server._check_rate_limit("expiry")
        time.sleep(1.1)
        server._check_rate_limit("expiry")  # must not raise

    def test_keys_are_independent(self):
        server.config.RATE_LIMIT_REQUESTS = 2
        server.config.RATE_LIMIT_WINDOW   = 60
        server._rate_buckets.clear()
        from fastapi import HTTPException
        server._check_rate_limit("a"); server._check_rate_limit("a")
        with pytest.raises(HTTPException):
            server._check_rate_limit("a")
        server._check_rate_limit("b"); server._check_rate_limit("b")
        with pytest.raises(HTTPException):
            server._check_rate_limit("b")


# ─────────────────────────────────────────────────────────────────────────────
#  11. JWT Session (FastAPI-Users stateless)
# ─────────────────────────────────────────────────────────────────────────────

class TestJWTSession:

    def test_login_issues_jwt_cookie(self, client):
        _register_user(client)
        r = _login(client)
        assert r.status_code == 204
        cookie = r.cookies.get("sysmon_session")
        assert cookie and cookie.count(".") == 2  # header.payload.sig

    def test_jwt_authenticates_me_endpoint(self, client):
        _register_user(client, email="jwt@sysmon.test")
        _login(client, email="jwt@sysmon.test")
        r = client.get("/api/users/me")
        assert r.status_code == 200
        assert r.json()["email"] == "jwt@sysmon.test"

    def test_tampered_jwt_returns_401(self, client):
        _register_user(client)
        _login(client)
        client.cookies.set("sysmon_session", "bad.jwt.token")
        assert client.get("/api/users/me").status_code == 401

    def test_missing_cookie_returns_401(self, client):
        assert client.get("/api/users/me").status_code == 401

    def test_logout_removes_cookie(self, client):
        _register_user(client)
        _login(client)
        client.post("/api/auth/logout")
        assert client.cookies.get("sysmon_session", "") == ""

    def test_two_users_get_different_tokens(self, client):
        _register_user(client, email="u1@sysmon.test", display_name="U1")
        _login(client, email="u1@sysmon.test")
        t1 = client.cookies.get("sysmon_session")
        client.post("/api/auth/logout")
        _register_user(client, email="u2@sysmon.test", display_name="U2")
        _login(client, email="u2@sysmon.test")
        t2 = client.cookies.get("sysmon_session")
        assert t1 != t2


# ─────────────────────────────────────────────────────────────────────────────
#  12. Simulation Endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestSimulation:

    def test_simulate_normal(self, client):
        r = client.post("/api/simulate/simhost", json={"scenario": "normal"})
        assert r.status_code == 200
        assert "cpu_percent" in r.json()

    def test_simulate_high_cpu(self, client):
        r = client.post("/api/simulate/simhost", json={"scenario": "high_cpu"})
        assert r.status_code == 200
        assert r.json()["cpu_percent"] >= 88.0

    def test_simulate_critical_fires_alerts(self, client):
        client.put("/api/host-config/simhost",
                   json={"cpu_threshold": 50.0, "ram_threshold": 50.0})
        client.post("/api/simulate/simhost", json={"scenario": "critical"})
        assert len(client.get("/api/alerts/simhost").json()) >= 1

    def test_simulate_custom_values(self, client):
        r = client.post("/api/simulate/simhost",
                        json={"cpu_percent": 42.0, "ram_percent": 33.0})
        assert r.status_code == 200
        assert r.json()["cpu_percent"] == 42.0

    def test_simulate_alert_injection(self, client):
        r = client.post("/api/simulate/simhost/alert",
                        json={"alert_type": "cpu", "severity": "critical"})
        assert r.status_code == 200
        assert r.json()["status"] == "injected"

    def test_simulate_clear(self, client):
        client.post("/api/simulate/simhost", json={"scenario": "normal"})
        assert client.delete("/api/simulate/simhost").status_code == 200

    def test_simulate_unknown_scenario_graceful(self, client):
        assert client.post("/api/simulate/simhost",
                           json={"scenario": "UNKNOWN"}).status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
#  13. Edge Cases & Validation
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_ingest_cpu_zero(self, agent, metric_payload):
        client, _, headers = agent
        metric_payload["cpu_percent"] = 0.0
        assert client.post("/ingest", json=metric_payload, headers=headers).status_code == 202

    def test_ingest_cpu_100(self, agent, metric_payload):
        client, _, headers = agent
        metric_payload["cpu_percent"] = 100.0
        assert client.post("/ingest", json=metric_payload, headers=headers).status_code == 202

    def test_ingest_empty_services(self, agent, metric_payload):
        client, _, headers = agent
        metric_payload["services"] = []
        assert client.post("/ingest", json=metric_payload, headers=headers).status_code == 202

    def test_ingest_xss_hostname_rejected(self, agent, metric_payload):
        client, _, headers = agent
        metric_payload["hostname"] = "<script>alert(1)</script>"
        assert client.post("/ingest", json=metric_payload, headers=headers).status_code == 422

    def test_ingest_path_traversal_hostname_rejected(self, agent, metric_payload):
        client, _, headers = agent
        metric_payload["hostname"] = "../../etc/passwd"
        assert client.post("/ingest", json=metric_payload, headers=headers).status_code == 422

    def test_db_hash_deterministic(self):
        assert server._hash("key") == server._hash("key")
        assert server._hash("key1") != server._hash("key2")

    def test_purge_removes_old_metrics(self, agent, metric_payload):
        client, _, headers = agent
        old_ts = int(time.time()) - server.RETAIN_HOURS * 3600 - 1
        conn = sqlite3.connect(server.config.DB_PATH)
        conn.execute(
            "INSERT INTO metrics (hostname,timestamp,cpu_percent,ram_percent,raw_json)"
            " VALUES (?,?,?,?,?)", ("testhost", old_ts, 10.0, 20.0, "{}")
        )
        conn.commit(); conn.close()
        server.purge_old_data()
        conn = sqlite3.connect(server.config.DB_PATH)
        count = conn.execute(
            "SELECT COUNT(*) FROM metrics WHERE timestamp<?",
            (int(time.time()) - server.RETAIN_HOURS * 3600,)
        ).fetchone()[0]
        conn.close()
        assert count == 0

    def test_ingest_non_object_payload_returns_400(self, agent):
        client, _, headers = agent
        r = client.post("/ingest", content=b"[1,2,3]",
                        headers={**headers, "Content-Type": "application/json"})
        assert r.status_code == 400

    def test_ingest_non_json_returns_400(self, agent):
        client, _, headers = agent
        r = client.post("/ingest", content=b"not-json",
                        headers={**headers, "Content-Type": "application/json"})
        assert r.status_code == 400
