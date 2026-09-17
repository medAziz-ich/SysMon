"""
Pydantic request/response models shared across the API routes.

Includes the fastapi-users schema overrides (UserRead/UserCreate/UserUpdate) —
email is kept as a plain `str` rather than `EmailStr` so `.local` / `.internal`
hostnames used in self-hosted deployments are accepted.
"""

import uuid

from fastapi_users import schemas as fu_schemas
from pydantic import BaseModel, Field, field_validator

class UserRead(fu_schemas.BaseUser[uuid.UUID]):
    """Public user representation returned by /api/auth/* and /api/me."""
    display_name: str
    is_approved:  bool
    # Override email field so .local / .internal / custom TLDs are accepted
    email: str

class UserCreate(fu_schemas.BaseUserCreate):
    """Custom create schema — uses str for email so .local / internal domains work."""
    display_name: str
    email: str  # Override EmailStr with plain str

    @field_validator("email", mode="before")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        v = str(v).strip().lower()
        if "@" not in v or v.startswith("@") or v.endswith("@") or len(v) < 5:
            raise ValueError("Invalid email address format.")
        local, _, domain = v.partition("@")
        if not local or not domain or "." not in domain:
            raise ValueError("Invalid email address format.")
        return v

class UserUpdate(fu_schemas.BaseUserUpdate):
    """Fields a user may change about their own account via PATCH /api/me."""
    display_name: str | None = None

class DiskItem(BaseModel):
    """One mounted filesystem's usage, as reported by an agent."""
    path:    str   = Field(...)
    percent: float = Field(..., ge=0, le=100)

class NetworkItem(BaseModel):
    """One network interface's throughput, as reported by an agent."""
    interface: str   = Field(...)
    rx_bps:    float = Field(0.0, ge=0)
    tx_bps:    float = Field(0.0, ge=0)

class ServiceItem(BaseModel):
    """A monitored systemd service and its current state."""
    name:   str = Field(...)
    status: str = Field(...)

class MetricPayload(BaseModel):
    """Body of POST /ingest — one metrics sample from an agent."""
    hostname:    str   = Field(..., min_length=1, max_length=253,
                               pattern=r'^[a-zA-Z0-9._-]+$')
    timestamp:   int | None   = Field(None)
    cpu_percent: float = Field(..., ge=0, le=100)
    ram_percent: float = Field(..., ge=0, le=100)
    disks:       list[DiskItem]    = Field(default_factory=list)
    network:     list[NetworkItem] = Field(default_factory=list)
    services:    list[ServiceItem] = Field(default_factory=list)

class LogEventPayload(BaseModel):
    """Body of POST /ingest for a tailed log line forwarded by an agent."""
    type:      str = Field("log_event")
    hostname:  str = Field(..., min_length=1, max_length=253,
                           pattern=r'^[a-zA-Z0-9._-]+$')
    timestamp: int | None = Field(None)
    source:    str = Field(..., max_length=256)
    message:   str = Field(..., max_length=4096)

class RegisterRequest(BaseModel):
    """Body of POST /register — a new agent requesting an API key."""
    agent_name: str = Field(..., min_length=1, max_length=128)
    secret:     str = Field(...)

class RegisterResponse(BaseModel):
    """Response to a successful agent registration."""
    api_key: str = Field(...)

class HostConfigUpdate(BaseModel):
    """Partial update body for PATCH /api/hosts/{hostname}/config."""
    cpu_threshold: float | None = Field(None, ge=1, le=100)
    ram_threshold: float | None = Field(None, ge=1, le=100)
    monitoring:    bool | None  = Field(None)
    tags:          list[str] | str | None = Field(None)

class HostConfigResponse(BaseModel):
    """A host's effective alert thresholds and monitoring state."""
    hostname:      str
    cpu_threshold: float
    ram_threshold: float
    monitoring:    bool
    tags:          list[str]

class AlertResponse(BaseModel):
    """A row from alert_history, as returned by the alerts API."""
    id:          int
    hostname:    str
    alert_type:  str
    detail:      str | None
    severity:    str
    subject:     str
    body:        str
    status:      str
    fired_at:    int
    resolved_at: int | None
    acked_at:    int | None
    acked_by:    str | None
    ai_analysis: str | None

class HostSummary(BaseModel):
    """One row of the /api/hosts listing."""
    hostname:   str
    last_seen:  int
    online:     bool
    monitoring: bool
    tags:       list[str]

class MetricSample(BaseModel):
    """One stored metrics row, as returned by /api/hosts/{hostname}/metrics."""
    timestamp:   int
    cpu_percent: float
    ram_percent: float
    disks:       list[DiskItem]
    network:     list[NetworkItem]
    services:    list[ServiceItem]

class LogEvent(BaseModel):
    """One stored log line, as returned by /api/hosts/{hostname}/logs."""
    id:        int
    hostname:  str
    timestamp: int
    source:    str
    message:   str

class SettingsUpdate(BaseModel):
    """Partial update body for PUT /api/settings. Unset fields are left unchanged."""
    email_provider:  str | None = None   # "smtp" | "resend"
    smtp_host:       str | None = None
    smtp_port:       str | None = None
    smtp_user:       str | None = None
    smtp_pass:       str | None = None
    resend_api_key:  str | None = None
    resend_from:     str | None = None
    alert_to:        str | None = None
    webhook_url:     str | None = None
    alert_cpu:       str | None = None
    alert_ram:       str | None = None
    alert_cooldown:  str | None = None
    spike_threshold: str | None = None
    spike_window:    str | None = None

class AcknowledgeResponse(BaseModel):
    """Response to POST /api/alerts/{id}/ack."""
    status: str
    id:     int
    by:     str

class AgentKeyInfo(BaseModel):
    """One row of the admin agent-key listing."""
    id:         int
    agent_name: str
    enabled:    bool
    created_at: int
    last_seen:  int | None

class AuditEntry(BaseModel):
    """One row of the audit log, as returned to admins."""
    id:        int
    timestamp: int
    actor:     str
    action:    str
    target:    str
    detail:    str | None

class UserAdminInfo(BaseModel):
    """One row of the admin user-management listing."""
    id:           str
    email:        str
    display_name: str
    is_superuser: bool
    is_approved:  bool
    is_active:    bool

class RoleUpdate(BaseModel):
    """Body of PATCH /api/admin/users/{id}/role."""
    role: str  # "admin" or "viewer"

class AgentRotateResponse(BaseModel):
    """Response to POST /api/admin/agent-keys/{id}/rotate — includes the new key once."""
    status:     str
    new_key:    str
    agent_name: str


class AdminUserCreate(BaseModel):
    """Body for POST /api/admin/users — admin-created, pre-approved account."""
    email:        str
    display_name: str
    password:     str
    role:         str = "viewer"  # "admin" or "viewer"
