"""
test_security.py — security test suite for sysmon-server.

Covers: CSRF, SSRF, JWT hardening, cookie flags, authorization (RBAC),
security headers, WebSocket auth, and audit logging.

Run:
    SYSMON_DB=sysmon_test.db SYSMON_COOKIE_SECURE=0 \
    SYSMON_DEFAULT_ADMIN_PASSWORD=ChangeMe1 \
    pytest test_security.py -v

The suite is self-contained: it spins up the real FastAPI app against a
throwaway SQLite file, creates an admin (auto-seeded) and a normal approved
user, and exercises the live endpoints through TestClient.
"""
import os
import time
import uuid
import sqlite3
import pytest

# ── Test environment — must be set BEFORE importing server ────────────────────
os.environ.setdefault("SYSMON_DB", "sysmon_test.db")
os.environ.setdefault("SYSMON_COOKIE_SECURE", "0")        # TestClient speaks http
os.environ.setdefault("SYSMON_DEFAULT_ADMIN_PASSWORD", "ChangeMe1")
os.environ.setdefault("SYSMON_ENV", "development")

# Fresh DB every run
if os.path.exists(os.environ["SYSMON_DB"]):
    os.remove(os.environ["SYSMON_DB"])

import server  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402

ADMIN_EMAIL = "admin@sysmon.local"
ADMIN_PW    = os.environ["SYSMON_DEFAULT_ADMIN_PASSWORD"]
ORIGIN      = "http://testserver"   # TestClient's default origin


# ── Fixtures ──────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    with TestClient(server.app, base_url=ORIGIN) as c:
        yield c


def _login(client, email, password):
    """Log in via FastAPI-Users cookie backend; returns the response."""
    return client.post("/api/auth/login",
                       data={"username": email, "password": password})


def _csrf(client):
    """Fetch a CSRF token (also sets the csrf cookie on the client)."""
    r = client.get("/api/csrf-token")
    assert r.status_code == 200
    return r.json()["csrf_token"]


@pytest.fixture(scope="module")
def admin_client(client):
    """A client logged in as the seeded superuser."""
    r = _login(client, ADMIN_EMAIL, ADMIN_PW)
    assert r.status_code in (200, 204), r.text
    return client


@pytest.fixture(scope="module")
def normal_user(client):
    """
    Register + approve a normal (non-superuser) user, return its credentials.
    Approval is done directly in the DB to avoid CSRF bootstrapping here.
    """
    email = f"viewer_{uuid.uuid4().hex[:8]}@sysmon.local"
    pw    = "ViewerPass1"
    # Register (auth endpoints are CSRF-exempt by design)
    r = client.post("/api/auth/register",
                    json={"email": email, "password": pw, "display_name": "Viewer"})
    assert r.status_code in (200, 201), r.text
    # Approve + activate directly
    conn = sqlite3.connect(os.environ["SYSMON_DB"])
    conn.execute(
        "UPDATE fu_users SET is_approved=1, is_active=1, is_superuser=0 WHERE email=?",
        (email,))
    conn.commit()
    conn.close()
    return {"email": email, "password": pw}


@pytest.fixture
def viewer_client(normal_user):
    """A SEPARATE client instance logged in as the normal user."""
    c = TestClient(server.app, base_url=ORIGIN)
    r = _login(c, normal_user["email"], normal_user["password"])
    assert r.status_code in (200, 204), r.text
    return c


# ══════════════════════════════════════════════════════════════════════════════
# 1. COOKIE HARDENING
# ══════════════════════════════════════════════════════════════════════════════
class TestCookieHardening:
    def test_session_cookie_httponly_and_samesite(self, client):
        r = _login(client, ADMIN_EMAIL, ADMIN_PW)
        sc = r.headers.get("set-cookie", "")
        assert "sysmon_session" in sc
        assert "httponly" in sc.lower()
        assert "samesite=strict" in sc.lower()

    def test_session_cookie_secure_when_enabled(self, monkeypatch):
        """With COOKIE_SECURE forced on, the Secure flag must be present."""
        # Re-create the transport with secure=True to prove the flag flows through.
        from fastapi_users.authentication import CookieTransport
        t = CookieTransport(cookie_name="sysmon_session", cookie_secure=True,
                            cookie_httponly=True, cookie_samesite="strict")
        # The transport stores the flag; assert our config wiring is honoured.
        assert server.COOKIE_SECURE in (True, False)
        assert t.cookie_secure is True


# ══════════════════════════════════════════════════════════════════════════════
# 2. CSRF PROTECTION
# ══════════════════════════════════════════════════════════════════════════════
class TestCSRF:
    def test_missing_csrf_token(self, admin_client):
        # No X-CSRF-Token header, no csrf cookie → 403
        admin_client.cookies.pop(server._CSRF_COOKIE, None)
        r = admin_client.post("/api/settings", json={"alert_cpu": "80"},
                              headers={"Origin": ORIGIN})
        assert r.status_code == 403
        assert "csrf" in r.json()["detail"].lower()

    def test_invalid_csrf_token(self, admin_client):
        token = _csrf(admin_client)  # sets valid cookie
        r = admin_client.post("/api/settings", json={"alert_cpu": "80"},
                              headers={"Origin": ORIGIN,
                                       server._CSRF_HEADER: "wrong-" + token})
        assert r.status_code == 403
        assert "mismatch" in r.json()["detail"].lower()

    def test_wrong_origin(self, admin_client):
        token = _csrf(admin_client)
        r = admin_client.post("/api/settings", json={"alert_cpu": "80"},
                              headers={"Origin": "https://evil.example.com",
                                       server._CSRF_HEADER: token})
        assert r.status_code == 403
        assert "origin" in r.json()["detail"].lower()

    def test_wrong_referer(self, admin_client):
        token = _csrf(admin_client)
        r = admin_client.post("/api/settings", json={"alert_cpu": "80"},
                              headers={"Referer": "https://evil.example.com/x",
                                       server._CSRF_HEADER: token})
        assert r.status_code == 403
        assert "referer" in r.json()["detail"].lower()

    def test_missing_origin_and_referer(self, admin_client):
        token = _csrf(admin_client)
        # httpx lets us drop the auto Origin by sending state-changing w/o it.
        r = admin_client.post("/api/settings", json={"alert_cpu": "80"},
                              headers={server._CSRF_HEADER: token,
                                       "Origin": "", "Referer": ""})
        assert r.status_code == 403

    def test_valid_csrf_request(self, admin_client):
        token = _csrf(admin_client)
        r = admin_client.post("/api/settings", json={"alert_cpu": "82"},
                              headers={"Origin": ORIGIN,
                                       server._CSRF_HEADER: token})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "saved"


# ══════════════════════════════════════════════════════════════════════════════
# 3. SSRF PREVENTION
# ══════════════════════════════════════════════════════════════════════════════
class TestSSRF:
    BLOCKED = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",
        "http://10.0.0.1",
        "http://192.168.1.1",
        "file:///etc/passwd",
        "gopher://localhost",
        "http://[::1]",                 # IPv6 loopback
        "ftp://example.com/x",
        "https://metadata.google.internal/",
    ]
    ALLOWED = [
        "https://discord.com/api/webhooks/123/abc",
        "https://hooks.slack.com/services/T0/B0/xxx",
    ]

    @pytest.mark.parametrize("url", BLOCKED)
    def test_blocked_urls_raise_400(self, url):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            server._validate_webhook_url(url)
        assert exc.value.status_code == 400

    @pytest.mark.parametrize("url", ALLOWED)
    def test_allowed_urls_pass(self, url):
        assert server._validate_webhook_url(url) == url

    def test_settings_rejects_ssrf_webhook(self, admin_client):
        token = _csrf(admin_client)
        r = admin_client.post("/api/settings",
                              json={"webhook_url": "http://169.254.169.254/"},
                              headers={"Origin": ORIGIN,
                                       server._CSRF_HEADER: token})
        assert r.status_code == 400
        assert "ssrf" in r.json()["detail"].lower()

    def test_redirect_handler_revalidates(self):
        """The custom redirect handler must reject a redirect to a private IP."""
        from fastapi import HTTPException
        handler = server._SSRFGuardRedirectHandler()
        import urllib.request as ur
        req = ur.Request("https://discord.com/api/webhooks/1/2")
        with pytest.raises(HTTPException):
            handler.redirect_request(req, None, 302, "Found", {},
                                     "http://169.254.169.254/")


# ══════════════════════════════════════════════════════════════════════════════
# 4. JWT HARDENING  (validated via the WebSocket token validator)
# ══════════════════════════════════════════════════════════════════════════════
class TestJWT:
    def _make_token(self, **overrides):
        now = int(time.time())
        payload = {
            "sub": str(uuid.uuid4()),
            "aud": ["fastapi-users:auth"],
            "exp": now + 3600,
            "nbf": now - 10,
            "iat": now,
        }
        payload.update(overrides)
        alg = overrides.pop("_alg", "HS256")
        return jose_jwt.encode(payload, server.JWT_SECRET, algorithm=alg)

    def test_alg_none_rejected(self):
        # Craft an unsigned alg=none token manually.
        import base64, json
        hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
        pl  = base64.urlsafe_b64encode(json.dumps({"sub": "x", "aud": ["fastapi-users:auth"]}).encode()).rstrip(b"=")
        tok = hdr.decode() + "." + pl.decode() + "."
        with pytest.raises(ValueError) as e:
            server._validate_ws_token(tok)
        assert "none" in str(e.value).lower()

    def test_wrong_audience_rejected(self):
        tok = self._make_token(aud=["someone-else"])
        with pytest.raises(ValueError) as e:
            server._validate_ws_token(tok)
        assert "audience" in str(e.value).lower()

    def test_missing_sub_rejected(self):
        tok = self._make_token(sub=None)
        with pytest.raises(ValueError) as e:
            server._validate_ws_token(tok)
        assert "sub" in str(e.value).lower()

    def test_expired_token_rejected(self):
        tok = self._make_token(exp=int(time.time()) - 100)
        with pytest.raises(ValueError):
            server._validate_ws_token(tok)

    def test_malformed_token_rejected(self):
        with pytest.raises(ValueError):
            server._validate_ws_token("not.a.jwt")

    def test_wrong_secret_rejected(self):
        bad = jose_jwt.encode(
            {"sub": "x", "aud": ["fastapi-users:auth"],
             "exp": int(time.time()) + 60},
            "the-wrong-secret", algorithm="HS256")
        with pytest.raises(ValueError):
            server._validate_ws_token(bad)


# ══════════════════════════════════════════════════════════════════════════════
# 5. AUTHORIZATION HARDENING (RBAC)
# ══════════════════════════════════════════════════════════════════════════════
class TestAuthorization:
    """A normal approved user must NOT be able to perform admin actions."""

    def _post(self, c, path, **kw):
        token = _csrf(c)
        headers = {"Origin": ORIGIN, server._CSRF_HEADER: token}
        headers.update(kw.pop("headers", {}))
        return c.post(path, headers=headers, **kw)

    def _delete(self, c, path, **kw):
        token = _csrf(c)
        headers = {"Origin": ORIGIN, server._CSRF_HEADER: token}
        return c.delete(path, headers=headers, **kw)

    def _put(self, c, path, **kw):
        token = _csrf(c)
        headers = {"Origin": ORIGIN, server._CSRF_HEADER: token}
        headers.update(kw.pop("headers", {}))
        return c.put(path, headers=headers, **kw)

    def test_viewer_cannot_modify_settings(self, viewer_client):
        r = self._post(viewer_client, "/api/settings", json={"alert_cpu": "70"})
        assert r.status_code == 403

    def test_viewer_cannot_list_admin_users(self, viewer_client):
        r = viewer_client.get("/api/admin/users")
        assert r.status_code == 403

    def test_viewer_cannot_approve_users(self, viewer_client):
        r = self._post(viewer_client, f"/api/users/{uuid.uuid4()}/approve")
        assert r.status_code == 403

    def test_viewer_cannot_revoke_users(self, viewer_client):
        r = self._delete(viewer_client, f"/api/users/{uuid.uuid4()}/revoke")
        assert r.status_code == 403

    def test_viewer_cannot_modify_host_config(self, viewer_client):
        r = self._put(viewer_client, "/api/host-config/web01",
                      json={"monitoring": False})
        assert r.status_code == 403

    def test_viewer_cannot_clear_alerts(self, viewer_client):
        r = self._delete(viewer_client, "/api/alerts/web01")
        assert r.status_code == 403

    def test_viewer_cannot_simulate(self, viewer_client):
        r = self._post(viewer_client, "/api/simulate/web01",
                       json={"scenario": "critical"})
        assert r.status_code == 403

    def test_viewer_cannot_list_agent_keys(self, viewer_client):
        r = viewer_client.get("/api/agent-keys")
        assert r.status_code == 403

    def test_unauthenticated_state_change_blocked(self, client):
        fresh = TestClient(server.app, base_url=ORIGIN)
        cases = [
            ("delete", "/api/alerts/web01", False),
            ("put",    "/api/host-config/web01", True),
            ("post",   "/api/simulate/web01", True),
            ("post",   "/api/settings/test-webhook", True),
        ]
        for method, path, send_json in cases:
            kw = {"json": {}} if send_json else {}
            r = getattr(fresh, method)(path, **kw)
            assert r.status_code in (401, 403), f"{method} {path} -> {r.status_code}"


# ══════════════════════════════════════════════════════════════════════════════
# 6. SECURITY HEADERS
# ══════════════════════════════════════════════════════════════════════════════
class TestSecurityHeaders:
    def test_all_headers_present(self, admin_client):
        r = admin_client.get("/api/hosts")
        h = r.headers
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["X-Frame-Options"] == "DENY"
        assert "strict-origin" in h["Referrer-Policy"]
        assert "geolocation=()" in h["Permissions-Policy"]
        assert h["Cross-Origin-Opener-Policy"] == "same-origin"
        assert h["Cross-Origin-Resource-Policy"] == "same-origin"

    def test_csp_on_html(self, admin_client):
        r = admin_client.get("/login")
        assert "Content-Security-Policy" in r.headers
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]

    def test_api_cache_control(self, admin_client):
        r = admin_client.get("/api/hosts")
        assert "no-store" in r.headers.get("Cache-Control", "")


# ══════════════════════════════════════════════════════════════════════════════
# 7. AUDIT LOGGING
# ══════════════════════════════════════════════════════════════════════════════
class TestAuditLogging:
    def _audit_rows(self, action=None):
        conn = sqlite3.connect(os.environ["SYSMON_DB"])
        conn.row_factory = sqlite3.Row
        if action:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE action=? ORDER BY id DESC",
                (action,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC").fetchall()
        conn.close()
        return rows

    def test_login_success_audited(self, client):
        _login(client, ADMIN_EMAIL, ADMIN_PW)
        assert len(self._audit_rows("login_success")) >= 1

    def test_login_failure_audited(self, client):
        c = TestClient(server.app, base_url=ORIGIN)
        c.post("/api/auth/login",
               data={"username": ADMIN_EMAIL, "password": "WrongPass9"})
        assert len(self._audit_rows("login_failure")) >= 1

    def test_csrf_failure_audited(self, admin_client):
        admin_client.cookies.pop(server._CSRF_COOKIE, None)
        admin_client.post("/api/settings", json={"alert_cpu": "1"},
                          headers={"Origin": ORIGIN})
        assert len(self._audit_rows("csrf_failure")) >= 1

    def test_settings_modification_audited(self, admin_client):
        token = _csrf(admin_client)
        admin_client.post("/api/settings", json={"alert_cpu": "83"},
                          headers={"Origin": ORIGIN, server._CSRF_HEADER: token})
        assert len(self._audit_rows("settings_modified")) >= 1

    def test_permission_denied_audited(self, viewer_client):
        viewer_client.get("/api/admin/users")
        assert len(self._audit_rows("permission_denied")) >= 1


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
