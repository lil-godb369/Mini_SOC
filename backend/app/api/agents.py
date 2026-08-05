"""Đăng ký và quản lý agent endpoint."""
from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import get_current_user, require_admin
from ..models import Agent
from ..schemas import AgentEnrollRequest, AgentEnrollResponse, AgentOut
from ..security import constant_time_equals, generate_api_key, hash_api_key

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/enroll", response_model=AgentEnrollResponse, status_code=status.HTTP_201_CREATED)
def enroll(payload: AgentEnrollRequest, db: Session = Depends(get_db)) -> AgentEnrollResponse:
    """Đăng ký một endpoint mới và cấp API key riêng cho nó.

    Dùng một token enroll chung (cấu hình qua biến môi trường) thay vì JWT admin,
    vì agent được cài tự động hàng loạt bằng script, không có người ngồi đăng
    nhập ở từng máy. Đổi lại, token enroll chỉ cấp được key mới chứ không đọc
    được dữ liệu, và nên được xoay vòng sau đợt triển khai.
    """
    if not constant_time_equals(payload.enroll_token, settings.agent_enroll_token):
        logger.warning("Đăng ký agent thất bại từ hostname=%s", payload.hostname)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token đăng ký không hợp lệ",
        )

    api_key = generate_api_key()
    agent = Agent(
        hostname=payload.hostname,
        platform=payload.platform,
        version=payload.version,
        api_key_hash=hash_api_key(api_key),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    logger.info("Đã đăng ký agent #%d (%s / %s)", agent.id, agent.hostname, agent.platform)
    # API key gốc chỉ xuất hiện đúng lần này; CSDL chỉ giữ hash.
    return AgentEnrollResponse(agent_id=agent.id, api_key=api_key)


@router.get("", response_model=List[AgentOut])
def list_agents(db: Session = Depends(get_db), _=Depends(get_current_user)) -> List[Agent]:
    return list(db.execute(select(Agent).order_by(Agent.hostname)).scalars())


# response_model=None: 204 không được phép có body, nên phải chặn FastAPI suy ra
# response model từ annotation `-> None` của hàm.
@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def deactivate_agent(
    agent_id: int, db: Session = Depends(get_db), _=Depends(require_admin)
) -> None:
    """Thu hồi quyền của một agent (vô hiệu hoá, không xoá để giữ lịch sử event)."""
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy agent")
    agent.is_active = False
    db.commit()
    logger.info("Đã vô hiệu hoá agent #%d (%s)", agent.id, agent.hostname)
