"""DTO cho API (Pydantic v2).

Tách khỏi models.py có chủ đích: model ORM là hình dạng LƯU TRỮ, schema là hình
dạng HỢP ĐỒNG với bên ngoài. Nhờ tách, thêm cột nội bộ vào bảng không vô tình
lộ ra API, và FastAPI tự sinh tài liệu OpenAPI từ chính các schema này.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

# Danh sách loại event agent được phép gửi. Loại lạ bị từ chối ngay ở cổng ingest.
EVENT_TYPES = {
    "process_create",
    "process_exit",
    "file_modify",
    "file_create",
    "network_connect",
    "network_flow",
    "registry_set",
    "email_received",
    "honeypot_hit",
}


# ---------------------------------------------------------------------------
# Xác thực
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    # Cố tình dùng `str` chứ không phải `EmailStr`: bộ kiểm tra email từ chối các
    # tên miền dùng riêng như `.local`, trong khi SMB triển khai nội bộ hay đặt
    # tài khoản kiểu `admin@congty.local`. Đăng nhập chỉ cần tra cứu một chuỗi;
    # chặn ở đây sẽ khoá luôn những tài khoản hoàn toàn hợp lệ.
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------
class AgentEnrollRequest(BaseModel):
    enroll_token: str
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(pattern="^(windows|linux|macos)$")
    version: str = Field(default="", max_length=32)


class AgentEnrollResponse(BaseModel):
    agent_id: int
    api_key: str = Field(description="Chỉ trả về đúng một lần — hãy lưu lại ngay")


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    platform: str
    version: str
    is_active: bool
    last_seen: Optional[datetime]
    created_at: datetime


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------
class EventIn(BaseModel):
    """Đúng một event theo schema chung (agent/event_schema.json)."""

    timestamp: Optional[datetime] = None  # thiếu thì server tự điền
    host: str = Field(min_length=1, max_length=255)
    platform: str = Field(default="unknown", max_length=32)
    event_type: str = Field(min_length=1, max_length=64)
    data: Dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    """Agent gửi theo lô để giảm số round-trip."""

    events: List[EventIn] = Field(min_length=1, max_length=500)


class IngestResponse(BaseModel):
    accepted: int
    rejected: int
    reasons: List[str] = Field(default_factory=list)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    host: str
    platform: str
    event_type: str
    data: Dict[str, Any]


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------
class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    source: str
    rule_id: str
    title: str
    severity: str
    status: str
    technique: str
    technique_name: str
    tactic: str
    host: str
    event_id: Optional[int]
    evidence: Dict[str, Any]
    confidence: Optional[float]
    ai_summary: Optional[str]
    ai_actions: Optional[Any]
    ai_model: Optional[str]


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[AlertOut]


class AlertStatusUpdate(BaseModel):
    status: str = Field(pattern="^(new|triaged|closed)$")


# ---------------------------------------------------------------------------
# Thống kê cho dashboard
# ---------------------------------------------------------------------------
class SeverityCount(BaseModel):
    severity: str
    count: int


class TechniqueCount(BaseModel):
    technique: str
    technique_name: str
    count: int


class TimelinePoint(BaseModel):
    bucket: datetime
    count: int


class StatsOverview(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    alerts_by_severity: List[SeverityCount]
    top_techniques: List[TechniqueCount]
    timeline: List[TimelinePoint]
    agents_online: int
