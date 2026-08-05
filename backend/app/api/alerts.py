"""Đọc và phân loại cảnh báo."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user
from ..models import Alert, Event
from ..schemas import AlertOut, AlertPage, AlertStatusUpdate, EventOut

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertPage)
def list_alerts(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
    severity: Optional[str] = Query(default=None, pattern="^(low|medium|high|critical)$"),
    alert_status: Optional[str] = Query(default=None, alias="status", pattern="^(new|triaged|closed)$"),
    source: Optional[str] = None,
    host: Optional[str] = None,
    technique: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AlertPage:
    """Danh sách cảnh báo, mới nhất trước, lọc được theo nhiều chiều."""
    filters = []
    if severity:
        filters.append(Alert.severity == severity)
    if alert_status:
        filters.append(Alert.status == alert_status)
    if source:
        filters.append(Alert.source == source)
    if host:
        filters.append(Alert.host == host)
    if technique:
        filters.append(Alert.technique == technique)
    if since:
        filters.append(Alert.ts >= since)
    if until:
        filters.append(Alert.ts <= until)

    total = db.execute(select(func.count()).select_from(Alert).where(*filters)).scalar_one()
    rows = db.execute(
        select(Alert).where(*filters).order_by(Alert.ts.desc(), Alert.id.desc())
        .limit(limit).offset(offset)
    ).scalars()

    return AlertPage(
        total=total,
        limit=limit,
        offset=offset,
        items=[AlertOut.model_validate(r) for r in rows],
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db), _=Depends(get_current_user)) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy cảnh báo")
    return alert


@router.get("/{alert_id}/context", response_model=List[EventOut])
def alert_context(
    alert_id: int,
    window_seconds: int = Query(default=60, ge=1, le=3600),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> List[Event]:
    """Các event xảy ra quanh thời điểm cảnh báo, trên cùng host.

    Đây là thứ người phân tích cần đầu tiên khi mở một cảnh báo: chuyện gì đã
    xảy ra ngay trước và ngay sau đó. Lớp 3 cũng dùng chính ngữ cảnh này để
    LLM tóm tắt cho sát thực tế.
    """
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy cảnh báo")

    from datetime import timedelta

    delta = timedelta(seconds=window_seconds)
    rows = db.execute(
        select(Event)
        .where(Event.host == alert.host, Event.ts >= alert.ts - delta, Event.ts <= alert.ts + delta)
        .order_by(Event.ts.asc())
        .limit(limit)
    ).scalars()
    return list(rows)


@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy cảnh báo")
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return alert
