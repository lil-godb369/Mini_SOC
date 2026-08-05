"""Băm mật khẩu, API key của agent, và phát/kiểm JWT.

Hai loại bí mật, hai cách băm khác nhau — có lý do:

* Mật khẩu người dùng -> **Argon2id**. Mật khẩu do người đặt nên entropy thấp và
  hay bị dùng lại, cần hàm băm chậm + tốn RAM để chống brute-force offline.
* API key của agent -> **SHA-256**. Key do hệ thống sinh ngẫu nhiên 256 bit nên
  không thể brute-force; đổi lại băm tất định giúp tra cứu bằng index O(log n)
  thay vì phải Argon2-verify lần lượt từng agent ở mỗi lần ingest (một endpoint
  gọi hàng trăm lần mỗi giây).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .config import settings

_hasher = PasswordHasher()  # tham số mặc định của argon2-cffi bám theo OWASP


# --------------------------------------------------------------------------
# Mật khẩu người dùng
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True khi hash được tạo bằng tham số cũ hơn cấu hình hiện tại."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, ValueError):
        return True


# --------------------------------------------------------------------------
# API key của agent
# --------------------------------------------------------------------------
API_KEY_PREFIX = "msoc_"


def generate_api_key() -> str:
    """Sinh API key 256-bit. Chỉ hiện đúng một lần, lúc agent đăng ký."""
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """So sánh không rò rỉ thời gian — dùng cho token enroll dùng chung."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# --------------------------------------------------------------------------
# JWT
# --------------------------------------------------------------------------
def create_access_token(subject: str, role: str = "analyst") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_expire_minutes)).timestamp()),
        "iss": "mini-soc",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Trả payload nếu token hợp lệ, None nếu hỏng/hết hạn/sai chữ ký."""
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer="mini-soc",
        )
    except jwt.PyJWTError:
        return None
