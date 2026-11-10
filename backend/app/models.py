"""Mô hình dữ liệu dùng chung cho toàn bộ 6 lớp.

Bốn bảng lõi:
    User    — người dùng dashboard (JWT)
    Agent   — endpoint được giám sát (API key riêng cho từng máy)
    Event   — telemetry thô đã chuẩn hoá (lớp 1)
    Alert   — cảnh báo do bất kỳ lớp phát hiện nào sinh ra (lớp 2, 4, 5, 6)

`Alert.source` là chỗ mọi lớp gặp nhau: rule engine, mô hình ML mạng, bộ phát
hiện hành vi ransomware, honeypot, scanner, phishing đều ghi vào cùng một bảng
với cùng cấu trúc — nhờ vậy dashboard chỉ cần biết đúng một dạng cảnh báo.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

# JSONB trên Postgres (index được, truy vấn được), JSON thường trên SQLite khi test.
JSONType = JSON().with_variant(JSONB(), "postgresql")
# SQLite không tự tăng khoá BigInteger, nên khi test thì hạ xuống Integer.
PK = BigInteger().with_variant(Integer(), "sqlite")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class AlertStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    CLOSED = "closed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # Chỉ lưu hash Argon2id, không bao giờ lưu mật khẩu gốc.
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="analyst")  # admin | analyst
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Agent(Base):
    """Một endpoint được giám sát."""

    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    platform: Mapped[str] = mapped_column(String(32))  # windows | linux | macos
    # API key cũng chỉ lưu hash — rò rỉ CSDL không cho phép giả mạo agent.
    api_key_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    version: Mapped[str] = mapped_column(String(32), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Event(Base):
    """Telemetry thô sau khi chuẩn hoá (lớp 1)."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(PK, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    host: Mapped[str] = mapped_column(String(255), index=True)
    platform: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    # Trường theo từng loại event. JSONB cho phép thêm loại telemetry mới
    # (network_flow, email, honeypot_hit...) mà không phải đổi schema.
    data: Mapped[dict] = mapped_column(JSONType, default=dict)

    __table_args__ = (
        Index("ix_events_host_ts", "host", "ts"),
        Index("ix_events_type_ts", "event_type", "ts"),
    )


class ProcessedMessage(Base):
    """Idempotency ledger, committed atomically with its event and alerts.

    A new table avoids altering existing event columns on installed databases.
    Do not prune independently of the retry horizon.
    """
    __tablename__ = "processed_messages"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionState(Base):
    """Per-host checkpoint committed together with events and idempotency receipts."""
    __tablename__ = "detection_states"

    host: Mapped[str] = mapped_column(String(255), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSONType, default=dict)


class Alert(Base):
    """Cảnh báo — đầu ra chung của mọi lớp phát hiện."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(PK, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    # Lớp nào sinh ra: rule | ml_network | ransomware | honeypot | scanner | phishing
    source: Mapped[str] = mapped_column(String(32), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), default="")
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default=AlertStatus.NEW.value, index=True)

    # Ánh xạ MITRE ATT&CK
    technique: Mapped[str] = mapped_column(String(32), default="", index=True)
    technique_name: Mapped[str] = mapped_column(String(128), default="")
    tactic: Mapped[str] = mapped_column(String(64), default="")

    host: Mapped[str] = mapped_column(String(255), default="", index=True)
    event_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("events.id", ondelete="SET NULL"), nullable=True
    )
    # Bằng chứng: command line, đường dẫn file, điểm số mô hình, số event trong cửa sổ...
    evidence: Mapped[dict] = mapped_column(JSONType, default=dict)
    # Điểm tin cậy của mô hình ML (lớp 2); rule engine để None.
    confidence: Mapped[Optional[float]] = mapped_column(nullable=True)

    # --- Lớp 3 điền vào (bất đồng bộ, có thể null lúc mới tạo) ---
    ai_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_actions: Mapped[Optional[Any]] = mapped_column(JSONType, nullable=True)
    ai_model: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_alerts_sev_ts", "severity", "ts"),
        Index("ix_alerts_status_ts", "status", "ts"),
    )
