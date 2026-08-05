"""Hàng đợi sự kiện dựa trên Redis Streams.

Vì sao chèn hàng đợi giữa API và bộ phát hiện thay vì ghi thẳng CSDL?

* **Phản áp lực (backpressure).** Cổng ingest chỉ cần ghi vào stream rồi trả lời
  ngay, nên một cụm event dồn dập không làm agent bị timeout.
* **Tách rời.** Worker phát hiện có thể restart, nâng cấp mô hình, hay chạy nhiều
  bản song song mà API không hề hay biết — event nằm yên trong stream chờ xử lý.
* **Không mất dữ liệu.** Consumer group của Redis yêu cầu ACK từng message; nếu
  worker chết giữa chừng, message chưa ACK vẫn còn trong danh sách pending và
  được worker khác nhận lại.

Vì sao Redis Streams mà không phải Kafka: Kafka tốn hơn 1GB RAM và cần vận hành
riêng, trong khi hệ này hướng tới SMB không có đội hạ tầng. Redis Streams cho
đúng ba tính chất cần (consumer group, ACK, lưu bền) với khoảng 50MB RAM.
"""
from __future__ import annotations

import json
import logging
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

import redis

from .config import settings

logger = logging.getLogger(__name__)

_client: Optional["redis.Redis"] = None


def _json_default(obj: Any):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    return str(obj)


def get_redis() -> "redis.Redis":
    """Client Redis dùng chung (redis-py có sẵn connection pool, an toàn đa luồng)."""
    global _client
    if _client is None:
        _client = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_keepalive=True,
            health_check_interval=30,
        )
    return _client


def publish_events(events: List[dict]) -> int:
    """Đẩy các event đã hợp lệ hoá vào stream. Trả về số message đã ghi."""
    client = get_redis()
    pipe = client.pipeline(transaction=False)
    for event in events:
        pipe.xadd(
            settings.stream_events,
            {"payload": json.dumps(event, default=_json_default)},
            maxlen=settings.stream_maxlen,
            approximate=True,  # cắt xấp xỉ: rẻ hơn nhiều so với cắt chính xác
        )
    return len(pipe.execute())


def publish_alert(alert: dict) -> None:
    """Phát cảnh báo ra stream riêng (dashboard realtime + thông báo lắng nghe)."""
    client = get_redis()
    client.xadd(
        settings.stream_alerts,
        {"payload": json.dumps(alert, default=_json_default)},
        maxlen=10_000,
        approximate=True,
    )


def ensure_group(stream: str, group: str) -> None:
    """Tạo consumer group nếu chưa có (idempotent)."""
    client = get_redis()
    try:
        # mkstream=True: tạo luôn stream nếu chưa có event nào được gửi.
        client.xgroup_create(name=stream, groupname=group, id="0", mkstream=True)
        logger.info("Đã tạo consumer group '%s' trên stream '%s'", group, stream)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
        logger.debug("Consumer group '%s' đã tồn tại", group)


def read_group(
    stream: str,
    group: str,
    consumer: str,
    count: int = 100,
    block_ms: int = 2000,
) -> List[Tuple[str, Dict[str, str]]]:
    """Đọc một lô message chưa xử lý. Trả về list (message_id, fields)."""
    client = get_redis()
    response = client.xreadgroup(
        groupname=group,
        consumername=consumer,
        streams={stream: ">"},
        count=count,
        block=block_ms,
    )
    if not response:
        return []
    _stream_name, messages = response[0]
    return messages


def claim_stale(
    stream: str,
    group: str,
    consumer: str,
    min_idle_ms: int = 60_000,
    count: int = 100,
) -> List[Tuple[str, Dict[str, str]]]:
    """Nhận lại các message một worker đã chết bỏ dở (pending quá lâu chưa ACK)."""
    client = get_redis()
    try:
        _next_id, messages, _deleted = client.xautoclaim(
            name=stream,
            groupname=group,
            consumername=consumer,
            min_idle_time=min_idle_ms,
            count=count,
        )
        if messages:
            logger.warning("Nhận lại %d message bị bỏ dở", len(messages))
        return messages
    except redis.ResponseError as exc:
        logger.error("xautoclaim lỗi: %s", exc)
        return []


def ack(stream: str, group: str, message_ids: List[str]) -> None:
    if message_ids:
        get_redis().xack(stream, group, *message_ids)


def decode_payload(fields: Dict[str, str]) -> Optional[dict]:
    raw = fields.get("payload")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.error("Message hỏng, không parse được JSON: %.200s", raw)
        return None
