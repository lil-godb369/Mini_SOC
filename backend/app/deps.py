"""Dependency dùng chung của FastAPI: xác thực và phân quyền.

Hệ thống có HAI chủ thể gọi API, và chúng cố tình tách rời nhau:

* **Người dùng** (analyst/admin) đăng nhập bằng email + mật khẩu, nhận JWT, dùng
  cho dashboard.
* **Agent** dùng API key tĩnh, và CHỈ được phép gọi cổng ingest.

Tách như vậy để một agent bị chiếm quyền trên endpoint không thể đọc được toàn
bộ cảnh báo của cả tổ chức — nó chỉ ghi được telemetry vào đúng chỗ của mình.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import Agent, User
from .security import decode_access_token, hash_api_key

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Thiếu token xác thực",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token không hợp lệ hoặc đã hết hạn",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.execute(select(User).where(User.email == payload["sub"])).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tài khoản không tồn tại hoặc đã bị khoá",
        )
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Thao tác này yêu cầu quyền quản trị",
        )
    return user


def get_current_agent(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> Agent:
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Thiếu header X-API-Key",
        )

    # Tra cứu bằng hash tất định -> dùng được index, không phải quét cả bảng.
    key_hash = hash_api_key(x_api_key)
    agent = db.execute(
        select(Agent).where(Agent.api_key_hash == key_hash)
    ).scalar_one_or_none()

    if agent is None or not agent.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key không hợp lệ",
        )

    agent.last_seen = datetime.now(timezone.utc)
    db.commit()
    return agent
