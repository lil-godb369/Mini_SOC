"""Cổng thu thập telemetry — lớp 1.

Đây là endpoint chịu tải cao nhất hệ thống, nên nó cố tình làm rất ít việc:
xác thực agent, kiểm tra tính hợp lệ, đẩy vào Redis Stream, trả lời. Mọi công
việc nặng (chuẩn hoá, so rule, chấm điểm ML, ghi CSDL) do worker làm ở phía sau.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from ..bus import publish_events
from ..deps import get_current_agent
from ..models import Agent
from ..schemas import EVENT_TYPES, IngestRequest, IngestResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ingest", tags=["ingest"])

# Không nhận event có timestamp lệch quá xa hiện tại — chống agent lệch đồng hồ
# và chống việc cố tình nhét dữ liệu giả vào quá khứ để trốn tương quan.
MAX_CLOCK_SKEW_SECONDS = 3600


@router.post("", response_model=IngestResponse)
def ingest(payload: IngestRequest, agent: Agent = Depends(get_current_agent)) -> IngestResponse:
    now = datetime.now(timezone.utc)
    accepted = []
    reasons = []
    rejected_indices = []

    for index, event in enumerate(payload.events):
        if event.event_type not in EVENT_TYPES:
            reasons.append(f"loại event không hỗ trợ: {event.event_type}")
            rejected_indices.append(index)
            continue

        ts = event.timestamp or now
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if abs((now - ts).total_seconds()) > MAX_CLOCK_SKEW_SECONDS:
            reasons.append(f"timestamp lệch quá xa: {ts.isoformat()}")
            rejected_indices.append(index)
            continue

        accepted.append(
            {
                "timestamp": ts.isoformat(),
                # Host lấy từ bản ghi agent đã đăng ký, KHÔNG lấy từ payload:
                # một agent không được phép mạo danh máy khác.
                "host": agent.hostname,
                "platform": agent.platform,
                "event_type": event.event_type,
                "data": event.data,
                "agent_id": agent.id,
                "event_uid": str(event.event_uid) if event.event_uid else None,
            }
        )

    if accepted:
        publish_events(accepted)

    rejected = len(payload.events) - len(accepted)
    if rejected:
        logger.warning("Agent #%d: từ chối %d/%d event", agent.id, rejected, len(payload.events))

    # Chỉ trả về vài lý do đầu tiên để phản hồi không phình to khi lô lỗi hàng loạt.
    return IngestResponse(accepted=len(accepted), rejected=rejected, reasons=reasons[:5],
                          rejected_indices=rejected_indices)
