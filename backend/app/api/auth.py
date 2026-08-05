"""Đăng nhập người dùng dashboard."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import get_current_user
from ..models import User
from ..schemas import LoginRequest, TokenResponse, UserOut
from ..security import (
    create_access_token,
    hash_password,
    needs_rehash,
    verify_password,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.execute(
        select(User).where(User.email == payload.email.lower())
    ).scalar_one_or_none()

    # Thông báo lỗi giống hệt nhau cho "sai email" và "sai mật khẩu" — không để
    # kẻ tấn công dò xem tài khoản nào có tồn tại.
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Email hoặc mật khẩu không đúng",
    )

    if user is None:
        # Vẫn băm một lần để thời gian phản hồi không tiết lộ tài khoản không tồn tại.
        hash_password(payload.password)
        raise invalid

    if not verify_password(payload.password, user.password_hash):
        logger.warning("Đăng nhập thất bại cho %s", payload.email)
        raise invalid

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tài khoản đã bị khoá",
        )

    # Nâng cấp hash trong im lặng nếu tham số Argon2 đã đổi.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
        db.commit()

    return TokenResponse(
        access_token=create_access_token(user.email, user.role),
        expires_in=settings.jwt_expire_minutes * 60,
        role=user.role,
    )


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
