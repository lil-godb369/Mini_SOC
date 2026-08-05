"""Tra cứu telemetry thô — phục vụ điều tra sự cố."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user
from ..models import Event
from ..schemas import EventOut

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=list[EventOut])
def list_events(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
    host: Optional[str] = None,
    event_type: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[Event]:
    filters = []
    if host:
        filters.append(Event.host == host)
    if event_type:
        filters.append(Event.event_type == event_type)
    if since:
        filters.append(Event.ts >= since)
    if until:
        filters.append(Event.ts <= until)

    rows = db.execute(
        select(Event).where(*filters).order_by(Event.ts.desc(), Event.id.desc())
        .limit(limit).offset(offset)
    ).scalars()
    return list(rows)
