"""Điểm khởi động API của Mini-SOC."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from . import __version__
from .api import api_router
from .bus import ensure_group, get_redis
from .config import settings
from .db import SessionLocal, init_db
from .models import User
from .security import hash_password

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


def seed_admin() -> None:
    """Tạo tài khoản quản trị đầu tiên nếu CSDL còn trống.

    Không có bước này thì không ai đăng nhập được vào hệ thống vừa cài. Chỉ chạy
    khi bảng users rỗng, nên restart nhiều lần cũng không ghi đè mật khẩu đã đổi.
    """
    with SessionLocal() as db:
        exists = db.execute(select(User.id).limit(1)).first()
        if exists:
            return
        admin = User(
            email=settings.admin_email.lower(),
            password_hash=hash_password(settings.admin_password),
            role="admin",
        )
        db.add(admin)
        db.commit()
        logger.warning(
            "Đã tạo tài khoản quản trị '%s' từ biến môi trường. ĐỔI MẬT KHẨU NGAY.",
            settings.admin_email,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Mini-SOC API v%s đang khởi động", __version__)
    init_db()
    seed_admin()
    # Tạo sẵn consumer group để worker khởi động sau vẫn nhận được event.
    ensure_group(settings.stream_events, settings.consumer_group)
    yield
    logger.info("Mini-SOC API dừng.")


app = FastAPI(
    title="Mini-SOC API",
    description=(
        "Nền tảng giám sát & phòng thủ an ninh mạng tích hợp AI cho doanh nghiệp "
        "vừa và nhỏ. Luồng: THU THẬP → PHÁT HIỆN (AI) → ĐÁNH GIÁ → CẢNH BÁO."
    ),
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

app.include_router(api_router)


@app.middleware("http")
async def dashboard_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == "/dashboard" or request.url.path.startswith("/dashboard/"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
    return response

# Bundled with the API image; no separate frontend service is required.
app.mount("/dashboard", StaticFiles(directory=Path(__file__).parent / "dashboard", html=True), name="dashboard")


@app.get("/", include_in_schema=False)
def dashboard_redirect():
    return RedirectResponse("/dashboard/")


@app.get("/health", tags=["system"])
def health() -> dict:
    """Kiểm tra sức khoẻ: dùng cho healthcheck của docker và giám sát ngoài."""
    checks = {"api": "ok"}

    try:
        with SessionLocal() as db:
            db.execute(select(1))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"error: {exc.__class__.__name__}"

    try:
        get_redis().ping()
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = f"error: {exc.__class__.__name__}"

    healthy = all(v == "ok" for v in checks.values())
    return {"status": "ok" if healthy else "degraded", "version": __version__, "checks": checks}


@app.get("/api/v1/modules", tags=["system"])
def modules() -> dict:
    """Trạng thái bật/tắt của từng lớp — dashboard hiển thị, và tiện khi demo."""
    return {
        "layer1_collection": True,
        "layer2_rule_engine": settings.enable_rule_engine,
        "layer2_ml_network": settings.enable_ml_network,
        "layer2_ransomware_behavior": settings.enable_ransomware_behavior,
        "layer3_llm_assistant": settings.enable_llm_assistant,
    }
