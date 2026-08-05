"""Cấu hình chung cho test.

Test phải chạy được mà KHÔNG cần Postgres hay Redis — nếu không thì sẽ chẳng ai
chạy chúng. Vì vậy ở đây ta trỏ CSDL sang SQLite tạm và thay Redis bằng bản giả,
trước khi bất kỳ module nào của app được import (config đọc biến môi trường ngay
lúc import).
"""
from __future__ import annotations

import os
import tempfile

# --- Phải đặt TRƯỚC khi import app ------------------------------------------
_TMP_DIR = tempfile.mkdtemp(prefix="minisoc-test-")
os.environ.setdefault("DATABASE_URL", f"sqlite+pysqlite:///{_TMP_DIR}/test.db")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6379/15")
os.environ.setdefault("JWT_SECRET", "test-secret-khong-dung-that")
os.environ.setdefault("ADMIN_EMAIL", "admin@test.local")
os.environ.setdefault("ADMIN_PASSWORD", "TestPassword#1")
os.environ.setdefault("AGENT_ENROLL_TOKEN", "test-enroll-token")

# Các cờ bật/tắt module được GÁN THẲNG (không setdefault) để bộ test hoàn toàn
# tất định. Lý do: `Settings` đọc file `.env` ở thư mục hiện tại, nên khi lập
# trình viên đã tạo `.env` cho môi trường Docker của mình thì các giá trị trong
# đó rò vào test và làm test đổi kết quả tuỳ theo máy. Đúng một lỗi như vậy đã
# xảy ra: bật ENABLE_RANSOMWARE_BEHAVIOR trong .env làm ba test đang xanh chuyển
# sang đỏ, dù mã nguồn không hề đổi.
#
# Test nào cần một bộ phát hiện cụ thể thì tự bật nó qua tham số của
# DetectionPipeline, chứ không dựa vào cấu hình bên ngoài.
os.environ["ENABLE_RULE_ENGINE"] = "true"
os.environ["ENABLE_RANSOMWARE_BEHAVIOR"] = "false"
os.environ["ENABLE_ML_NETWORK"] = "false"
os.environ["ENABLE_LLM_ASSISTANT"] = "false"

import pytest  # noqa: E402


class FakeRedis:
    """Redis giả, chỉ đủ dùng cho test: ghi lại những gì được publish."""

    def __init__(self):
        self.streams = {}

    def xadd(self, name, fields, **_kwargs):
        self.streams.setdefault(name, []).append(fields)
        return f"{len(self.streams[name])}-0"

    def ping(self):
        return True

    def pipeline(self, **_kwargs):
        return _FakePipeline(self)

    def xgroup_create(self, **_kwargs):
        return True


class _FakePipeline:
    def __init__(self, client: FakeRedis):
        self.client = client
        self.calls = []

    def xadd(self, name, fields, **kwargs):
        self.calls.append((name, fields, kwargs))
        return self

    def execute(self):
        results = [self.client.xadd(n, f, **k) for n, f, k in self.calls]
        self.calls = []
        return results


@pytest.fixture
def fake_redis(monkeypatch) -> FakeRedis:
    from app import bus

    client = FakeRedis()
    monkeypatch.setattr(bus, "_client", client)
    monkeypatch.setattr(bus, "get_redis", lambda: client)
    return client


@pytest.fixture
def client(fake_redis, monkeypatch):
    """TestClient của FastAPI với CSDL SQLite và Redis giả.

    Mỗi test bắt đầu từ CSDL trống: file SQLite dùng chung cho cả phiên, nên nếu
    không xoá sạch thì dữ liệu của test trước sẽ rò sang test sau và làm các
    khẳng định về số lượng trở nên vô nghĩa.
    """
    from fastapi.testclient import TestClient

    from app import bus, main
    from app.db import Base, engine

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    monkeypatch.setattr(main, "ensure_group", lambda *a, **k: None)
    monkeypatch.setattr(main, "get_redis", lambda: fake_redis)
    monkeypatch.setattr(bus, "get_redis", lambda: fake_redis)

    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers(client) -> dict:
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@test.local", "password": "TestPassword#1"},
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}
