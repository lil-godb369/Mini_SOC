"""Số liệu tổng hợp cho dashboard."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user
from ..models import Agent, Alert, AlertStatus, Event
from ..schemas import (
    SeverityCount,
    StatsOverview,
    TechniqueCount,
    TimelinePoint,
)

router = APIRouter(prefix="/stats", tags=["stats"])

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


@router.get("/overview", response_model=StatsOverview)
def overview(
    hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> StatsOverview:
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    total_events = db.execute(
        select(func.count()).select_from(Event).where(Event.ts >= since)
    ).scalar_one()
    total_alerts = db.execute(
        select(func.count()).select_from(Alert).where(Alert.ts >= since)
    ).scalar_one()
    open_alerts = db.execute(
        select(func.count()).select_from(Alert).where(Alert.status != AlertStatus.CLOSED.value)
    ).scalar_one()

    # --- Cảnh báo theo mức nghiêm trọng ---
    sev_rows = db.execute(
        select(Alert.severity, func.count()).where(Alert.ts >= since).group_by(Alert.severity)
    ).all()
    sev_map = {row[0]: row[1] for row in sev_rows}
    alerts_by_severity = [
        SeverityCount(severity=s, count=sev_map.get(s, 0)) for s in SEVERITY_ORDER
    ]

    # --- Kỹ thuật ATT&CK xuất hiện nhiều nhất ---
    tech_rows = db.execute(
        select(Alert.technique, Alert.technique_name, func.count())
        .where(Alert.ts >= since, Alert.technique != "")
        .group_by(Alert.technique, Alert.technique_name)
        .order_by(func.count().desc())
        .limit(10)
    ).all()
    top_techniques = [
        TechniqueCount(technique=r[0], technique_name=r[1], count=r[2]) for r in tech_rows
    ]

    # --- Dòng thời gian, gom theo giờ ---
    # Gom trong Python thay vì date_trunc của Postgres để test bằng SQLite vẫn
    # chạy được. Số cảnh báo trong 30 ngày ở quy mô SMB là vài nghìn, không đáng
    # kể; nếu sau này lên hàng triệu thì chuyển sang date_trunc phía CSDL.
    ts_rows = db.execute(select(Alert.ts).where(Alert.ts >= since)).scalars()
    buckets: Counter = Counter()
    for ts in ts_rows:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        buckets[ts.replace(minute=0, second=0, microsecond=0)] += 1

    timeline: List[TimelinePoint] = []
    cursor = since.replace(minute=0, second=0, microsecond=0)
    end = now.replace(minute=0, second=0, microsecond=0)
    while cursor <= end:
        timeline.append(TimelinePoint(bucket=cursor, count=buckets.get(cursor, 0)))
        cursor += timedelta(hours=1)

    # Agent được coi là "online" nếu có liên lạc trong 5 phút gần nhất.
    agents_online = db.execute(
        select(func.count()).select_from(Agent)
        .where(Agent.is_active.is_(True), Agent.last_seen >= now - timedelta(minutes=5))
    ).scalar_one()

    return StatsOverview(
        total_events=total_events,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        alerts_by_severity=alerts_by_severity,
        top_techniques=top_techniques,
        timeline=timeline,
        agents_online=agents_online,
    )
