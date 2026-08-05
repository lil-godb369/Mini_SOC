"""Router HTTP.

Mọi module đều lộ ra API riêng (yêu cầu phi chức năng: "mọi module phải có API
để tích hợp"), gom dưới tiền tố /api/v1 và tự sinh tài liệu OpenAPI tại /docs.
"""
from fastapi import APIRouter

from . import agents, alerts, auth, events, ingest, stats

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(agents.router)
api_router.include_router(ingest.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(stats.router)

__all__ = ["api_router"]
