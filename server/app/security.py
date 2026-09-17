"""
Security middleware and helpers: CSRF protection, request rate limiting,
self-signed TLS certificate bootstrap, SSRF-safe outbound HTTP, and the
audit log writer.

`_audit()` lives here (rather than in db.py) because most of its callers
are other security-relevant checks (CSRF rejection, SSRF blocks) and it
also broadcasts to `ws_manager`, so keeping it beside them avoids a
db <-> websocket import cycle.
"""

import collections
import hmac
import secrets
import sqlite3
import time
from pathlib import Path

from fastapi import HTTPException, Request, Response

try:
    import urllib.request as urlreq
except ImportError:
    urlreq = None

from . import config
from .websocket import ws_manager

logger = config.logger.getChild("security")

# ── Rate limiter ──────────────────────────────────────────────────────────────
_rate_buckets: dict = {}

def _check_rate_limit(key: str) -> None:
    now = time.time()
    bucket = _rate_buckets.setdefault(key, collections.deque())
    while bucket and now - bucket[0] > config.RATE_LIMIT_WINDOW:
        bucket.popleft()
    if len(bucket) >= config.RATE_LIMIT_REQUESTS:
        retry_after = int(config.RATE_LIMIT_WINDOW - (now - bucket[0])) + 1
        raise HTTPException(status_code=429,
            detail=f"Rate limit exceeded. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)})
    bucket.append(now)

# ── TLS ───────────────────────────────────────────────────────────────────────
def ensure_tls_cert() -> None:
    """Generate a self-signed TLS cert/key pair on first run if none exists."""
    if Path(config.TLS_CERT).exists() and Path(config.TLS_KEY).exists():
        logger.info("TLS cert found: %s", config.TLS_CERT); return
    logger.info("Generating self-signed TLS certificate...")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime, ipaddress
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"sysmon-server")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]), critical=False)
            .sign(key, hashes.SHA256())
        )
        Path(config.TLS_KEY).write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        Path(config.TLS_CERT).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        logger.info("Self-signed TLS cert generated (valid 10 years)")
    except ImportError:
        logger.warning("cryptography package not installed — falling back to HTTP")

# ── CSRF Protection (Double-Submit Cookie Pattern) ────────────────────────────
_CSRF_COOKIE   = "sysmon_csrf"
_CSRF_HEADER   = "X-CSRF-Token"
_CSRF_TTL      = 3600          # 1 hour
_CSRF_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# config._ALLOWED_ORIGINS is defined in the config section and populated from
# SYSMON_ALLOWED_ORIGINS. When empty, _require_csrf falls back to same-origin.

def _generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)

def _set_csrf_cookie(response: Response, token: str, is_https: bool) -> None:
    """Set the CSRF double-submit cookie on the response."""
    response.set_cookie(
        key      = _CSRF_COOKIE,
        value    = token,
        httponly = False,    # JavaScript must be able to read it for double-submit
        secure   = is_https,
        samesite = "strict",
        max_age  = _CSRF_TTL,
        path     = "/",
    )

async def _require_csrf(request: Request) -> None:
    """
    FastAPI dependency — validates CSRF token on state-changing requests.
    Skips safe HTTP methods (GET, HEAD, OPTIONS).
    Skips FastAPI-Users auth endpoints (/api/auth/*) — they use credentials
    not cookies, so CSRF doesn't apply (no session cookie exists yet).
    Strategy: Double-Submit Cookie — token must appear in BOTH
      • Cookie: sysmon_csrf=<token>
      • Header: X-CSRF-Token: <token>
    Also validates Origin / Referer headers.
    """
    if request.method in _CSRF_SAFE_METHODS:
        return

    # Auth endpoints are exempt — no session cookie exists at login time
    _CSRF_EXEMPT_PATHS = {
        "/api/auth/login", "/api/auth/logout",
        "/api/auth/register", "/register",
    }
    if request.url.path in _CSRF_EXEMPT_PATHS:
        return

    def _reject(detail: str) -> None:
        """Audit the CSRF failure, then raise 403."""
        client_ip = request.client.host if request.client else "unknown"
        try:
            _audit(client_ip, "csrf_failure", request.url.path, detail)
        except Exception:
            logger.debug("Audit write failed for csrf_failure", exc_info=True)
            # never let an audit-log failure mask the security response itself
        raise HTTPException(status_code=403, detail=detail)

    # ── Origin / Referer validation ────────────────────────────────────────
    origin  = request.headers.get("origin", "")
    referer = request.headers.get("referer", "")

    # Same-origin baseline built from the request itself.
    server_origin = f"{request.url.scheme}://{request.url.netloc}"
    # Trusted set = configured allow-list ∪ request's own origin.
    trusted = set(config._ALLOWED_ORIGINS) | {server_origin}

    if origin:
        if origin.rstrip("/") not in trusted:
            _reject(f"CSRF: origin '{origin}' not in trusted origins")
    elif referer:
        # No Origin header (some same-origin requests) — fall back to Referer.
        if not any(referer.startswith(t) for t in trusted):
            _reject("CSRF: referer not in trusted origins")
    else:
        # Neither Origin nor Referer present on a state-changing request — reject.
        _reject("CSRF: missing Origin and Referer headers")

    # When both are present, Referer must also be consistent.
    if referer and not any(referer.startswith(t) for t in trusted):
        _reject("CSRF: referer mismatch")

    # ── Double-submit cookie check ─────────────────────────────────────────
    cookie_token = request.cookies.get(_CSRF_COOKIE, "")
    header_token = request.headers.get(_CSRF_HEADER, "")

    if not cookie_token:
        _reject("CSRF: missing token cookie")
    if not header_token:
        _reject("CSRF: missing X-CSRF-Token header")
    if not hmac.compare_digest(cookie_token, header_token):
        _reject("CSRF: token mismatch")

# ── Audit helper ───────────────────────────────────────────────────────────────
def _audit(actor: str, action: str, target: str, detail: str = "") -> None:
    """Write one audit log entry + broadcast to connected admin tabs."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(
        "INSERT INTO audit_log (actor, action, target, detail) VALUES (?,?,?,?)",
        (actor, action, target, detail)
    )
    conn.commit()
    conn.close()
    ws_manager.broadcast_sync({
        "type":   "audit",
        "actor":  actor,
        "action": action,
        "target": target,
        "detail": detail,
        "ts":     int(time.time()),
    })

# ── SSRF Protection ──────────────────────────────────────────────────────────
import ipaddress as _ipaddress
import socket    as _socket

_BLOCKED_SCHEMES   = {"file", "ftp", "gopher", "dict", "smb", "ldap", "tftp"}
_PRIVATE_NETWORKS  = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("127.0.0.0/8"),
    _ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    _ipaddress.ip_network("0.0.0.0/8"),
    _ipaddress.ip_network("::1/128"),           # IPv6 loopback
    _ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    _ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]
_BLOCKED_HOSTS = {
    "localhost", "metadata.google.internal",
    "169.254.169.254",                          # AWS/Azure/GCP metadata
    "metadata.internal",
}

def _validate_webhook_url(url: str) -> str:
    """
    Validate a webhook URL against SSRF attack vectors.
    Returns the URL unchanged if safe. Raises HTTPException(400) if unsafe.

    Blocks:
    - Non-HTTPS schemes
    - Dangerous schemes (file://, gopher://, ftp://, dict://, smb://)
    - Private / loopback IP ranges (RFC 1918, link-local, metadata endpoints)
    - Blocked hostnames (localhost, metadata.google.internal, etc.)
    - DNS rebinding: resolves the hostname and checks the resulting IP
    """
    from urllib.parse import urlparse as _urlparse
    import socket as _sock

    def _block(detail: str) -> None:
        """Audit the blocked SSRF attempt, then raise 400."""
        try:
            _audit("system", "ssrf_blocked", url[:200] if url else "", detail)
        except Exception:
            logger.debug("Audit write failed for ssrf_blocked", exc_info=True)
            # never let an audit-log failure mask the security response itself
        raise HTTPException(status_code=400, detail=detail)

    if not url or not url.strip():
        raise HTTPException(status_code=400, detail="SSRF: webhook URL is empty")

    try:
        parsed = _urlparse(url.strip())
    except Exception:
        _block("SSRF: invalid URL format")

    scheme = parsed.scheme.lower()

    # Block dangerous schemes
    if scheme in _BLOCKED_SCHEMES:
        _block(f"SSRF: scheme '{scheme}' not allowed")

    # Enforce HTTPS only
    if scheme != "https":
        _block("SSRF: only HTTPS webhook URLs are allowed")

    host = parsed.hostname or ""
    if not host:
        _block("SSRF: missing hostname")

    # Block known dangerous hostnames
    if host.lower() in _BLOCKED_HOSTS:
        _block(f"SSRF: hostname '{host}' is blocked")

    # Block raw IP addresses in private ranges
    try:
        ip_obj = _ipaddress.ip_address(host)
        for net in _PRIVATE_NETWORKS:
            if ip_obj in net:
                _block(f"SSRF: IP address '{host}' is in a private range")
    except ValueError:
        pass  # not a raw IP — do DNS resolution below

    # DNS resolution check — prevent DNS rebinding to private IPs
    try:
        resolved_ips = _sock.getaddrinfo(host, None)
        for family, _type, _proto, _canonname, sockaddr in resolved_ips:
            ip_str = sockaddr[0]
            try:
                ip_obj = _ipaddress.ip_address(ip_str)
                for net in _PRIVATE_NETWORKS:
                    if ip_obj in net:
                        _block(f"SSRF: hostname '{host}' resolves to private IP {ip_str}")
            except ValueError:
                pass
    except HTTPException:
        raise
    except Exception as e:
        _block(f"SSRF: could not resolve hostname '{host}': {e}")

    return url.strip()


# ── SSRF-safe HTTP client wrapper ─────────────────────────────────────────────
# urllib follows 3xx redirects by default; a validated https://good.example that
# 302-redirects to http://169.254.169.254/ would otherwise be followed. This
# handler re-runs _validate_webhook_url on every redirect target.
class _SSRFGuardRedirectHandler(urlreq.HTTPRedirectHandler):
    """Re-validates every HTTP redirect hop against the same SSRF rules."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Re-run the SSRF check on the redirect target before following it."""
        # Raises HTTPException(400) if the redirect target is unsafe.
        _validate_webhook_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_ssrf_safe_opener = urlreq.build_opener(_SSRFGuardRedirectHandler())


def _ssrf_safe_post(url: str, data: bytes, headers: dict, timeout: int = 10):
    """
    POST to an external URL with SSRF protection on the initial target AND on
    every redirect hop. Returns the response object. Raises HTTPException(400)
    if any hop is unsafe.
    """
    safe_url = _validate_webhook_url(url)
    req = urlreq.Request(safe_url, data=data, headers=headers)
    return _ssrf_safe_opener.open(req, timeout=timeout)
