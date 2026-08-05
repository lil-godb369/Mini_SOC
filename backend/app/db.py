"""Kết nối CSDL.

Quyết định kỹ thuật: dùng SQLAlchemy ĐỒNG BỘ (không async).

Lý do: worker phát hiện và API dùng chung đúng một tầng truy cập dữ liệu. Nếu
API async còn worker sync thì sẽ phải viết hai bản model/query song song — nguồn
sinh bug và trôi lệch code. FastAPI khi thấy endpoint khai báo `def` (thay vì
`async def`) sẽ tự chạy nó trong threadpool, nên không chặn event loop. Ở quy mô
SMB (vài trăm event/giây) đây là đánh đổi đúng: đơn giản hơn nhiều, đủ nhanh.
"""
from __future__ import annotations

from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,   # tự phát hiện kết nối chết sau khi Postgres restart
    pool_size=10,
    max_overflow=20,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    """Dependency của FastAPI: mở session, đảm bảo luôn đóng."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Tạo bảng nếu chưa có.

    Hạn chế đã biết: dự án dùng `create_all` thay vì Alembic migration. Chấp nhận
    được vì schema còn mới và chưa có dữ liệu sản xuất cần bảo toàn; đã ghi vào
    mục "Hạn chế" của báo cáo. Khi lên production thật thì phải chuyển sang Alembic.
    """
    from . import models  # noqa: F401 — import để Base biết các bảng

    Base.metadata.create_all(bind=engine)
