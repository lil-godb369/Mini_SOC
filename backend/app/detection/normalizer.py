"""Chuẩn hoá event thô của agent về schema chung.

Nhờ bước này, phần còn lại của hệ thống được bảo đảm: mọi event luôn có đủ khoá
bắt buộc và một dict `data`, nên rule không bao giờ nổ vì thiếu trường. KHÔNG hạ
chữ thường giá trị lưu trữ (dashboard cần hiển thị bản gốc) — việc so khớp không
phân biệt hoa thường đã do `matching.py` đảm nhiệm.

Port từ PyEDR (`engine/normalizer.py`), bổ sung phân tích timestamp và các trường
dẫn xuất mà rule hay dùng (đuôi file, tên tiến trình tách từ đường dẫn).
"""
from __future__ import annotations

import ntpath
import posixpath
from datetime import datetime, timezone
from typing import Optional

REQUIRED = ("timestamp", "host", "platform", "event_type", "data")


def _parse_ts(value) -> datetime:
    """Chấp nhận datetime, epoch, hoặc chuỗi ISO-8601 (kể cả hậu tố 'Z')."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _basename(path: str) -> str:
    """Lấy tên file, xử lý được cả đường dẫn Windows lẫn POSIX."""
    return ntpath.basename(path) if "\\" in path else posixpath.basename(path)


def normalize(event: dict) -> Optional[dict]:
    """Trả về event đã hợp lệ hoá, hoặc None nếu không dùng được."""
    if not isinstance(event, dict):
        return None
    if not event.get("event_type"):
        return None

    data = event.get("data")
    if not isinstance(data, dict):
        data = {}
    event["data"] = data

    event["timestamp"] = _parse_ts(event.get("timestamp"))
    event.setdefault("host", "unknown")
    event.setdefault("platform", "unknown")

    # --- Trường dẫn xuất: tính một lần ở đây, mọi rule dùng lại ---
    # Agent trên Linux thường chỉ gửi process_path mà không gửi process_name.
    if not data.get("process_name") and data.get("process_path"):
        data["process_name"] = _basename(str(data["process_path"]))

    if data.get("file_path"):
        file_path = str(data["file_path"])
        name = _basename(file_path)
        data["file_name"] = name
        # Đuôi file dùng cho rule ransomware (.locked, .encrypted...).
        data["file_ext"] = ("." + name.rsplit(".", 1)[1].lower()) if "." in name else ""

    return event
