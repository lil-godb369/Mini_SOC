"""Worker phát hiện — trái tim của lớp 2.

Vòng lặp: đọc event từ Redis Stream → chuẩn hoá → chạy đường ống phát hiện →
ghi event và cảnh báo xuống Postgres → ACK message.

Vì sao ACK ở CUỐI, sau khi đã commit CSDL: nếu worker chết giữa chừng, message
chưa ACK vẫn nằm trong danh sách pending của consumer group và sẽ được nhận lại
(`xautoclaim`). Đánh đổi là có thể xử lý lặp một lô khi gặp sự cố — chấp nhận
được vì cảnh báo trùng dễ chịu hơn nhiều so với cảnh báo bị mất.

Chạy:  python -m app.worker
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import time
from typing import List

from sqlalchemy.orm import Session

from .bus import (
    ack,
    claim_stale,
    decode_payload,
    ensure_group,
    publish_alert,
    read_group,
)
from .config import settings
from .db import SessionLocal, init_db
from .detection import DetectionPipeline, normalize
from .detection.pipeline import AlertDraft
from .models import Alert, Event

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
)
logger = logging.getLogger("worker")

CONSUMER_NAME = f"{socket.gethostname()}-{os.getpid()}"
BATCH_SIZE = 200
BLOCK_MS = 2000
CLAIM_EVERY_SECONDS = 30

_running = True


def _stop(signum, _frame):
    global _running
    logger.info("Nhận tín hiệu %s, đang dừng có trật tự...", signum)
    _running = False


def _persist(db: Session, event: dict, drafts: List[AlertDraft]) -> List[Alert]:
    """Ghi một event và các cảnh báo của nó trong CÙNG một transaction.

    Cùng transaction để không bao giờ tồn tại cảnh báo trỏ tới event không có
    thật (hoặc ngược lại) khi worker chết đúng lúc giữa hai lệnh ghi.
    """
    row = Event(
        ts=event["timestamp"],
        host=event.get("host", "unknown"),
        platform=event.get("platform", "unknown"),
        event_type=event["event_type"],
        agent_id=event.get("agent_id"),
        data=event.get("data", {}),
    )
    db.add(row)
    db.flush()  # lấy row.id mà chưa commit

    alerts: List[Alert] = []
    for draft in drafts:
        alert = Alert(
            ts=draft.ts or row.ts,
            source=draft.source,
            rule_id=draft.rule_id,
            title=draft.title,
            severity=draft.severity,
            technique=draft.technique,
            technique_name=draft.technique_name,
            tactic=draft.tactic,
            host=draft.host or row.host,
            event_id=row.id,
            evidence=draft.evidence,
            confidence=draft.confidence,
        )
        db.add(alert)
        alerts.append(alert)

    return alerts


def _alert_payload(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "ts": alert.ts,
        "source": alert.source,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "severity": alert.severity,
        "technique": alert.technique,
        "technique_name": alert.technique_name,
        "tactic": alert.tactic,
        "host": alert.host,
        "evidence": alert.evidence,
    }


def process_batch(pipeline: DetectionPipeline, messages) -> List[str]:
    """Xử lý một lô message. Trả về danh sách id cần ACK."""
    if not messages:
        return []

    processed_ids: List[str] = []
    new_alerts: List[Alert] = []

    with SessionLocal() as db:
        for message_id, fields in messages:
            payload = decode_payload(fields)
            if payload is None:
                # Message hỏng không bao giờ tự lành — ACK để nó không kẹt
                # vĩnh viễn trong pending list.
                processed_ids.append(message_id)
                continue

            event = normalize(payload)
            if event is None:
                logger.debug("Bỏ qua event không hợp lệ: %.200s", payload)
                processed_ids.append(message_id)
                continue

            try:
                drafts = pipeline.process(event, now=time.monotonic())
                new_alerts.extend(_persist(db, event, drafts))
                processed_ids.append(message_id)
            except Exception:  # noqa: BLE001
                logger.exception("Lỗi khi xử lý message %s", message_id)
                # KHÔNG ACK: để message được nhận lại và thử lại sau.

        try:
            db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("Commit thất bại, sẽ xử lý lại cả lô")
            db.rollback()
            return []

        # Phát cảnh báo ra stream SAU khi commit — dashboard realtime và bộ gửi
        # thông báo chỉ được thấy những gì đã thực sự nằm trong CSDL.
        for alert in new_alerts:
            db.refresh(alert)
            publish_alert(_alert_payload(alert))
            logger.info(
                "CẢNH BÁO [%s] %s | host=%s | %s",
                alert.severity.upper(), alert.title, alert.host, alert.technique,
            )

    return processed_ids


def main() -> None:
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    logger.info("Worker phát hiện khởi động (consumer=%s)", CONSUMER_NAME)
    init_db()
    ensure_group(settings.stream_events, settings.consumer_group)

    pipeline = DetectionPipeline()
    if not settings.enable_rule_engine:
        logger.warning("ENABLE_RULE_ENGINE=false — rule ATT&CK đang tắt")

    last_claim = 0.0
    total = 0

    while _running:
        try:
            # Định kỳ nhận lại việc mà worker khác đã bỏ dở.
            if time.monotonic() - last_claim > CLAIM_EVERY_SECONDS:
                last_claim = time.monotonic()
                stale = claim_stale(
                    settings.stream_events, settings.consumer_group, CONSUMER_NAME
                )
                if stale:
                    ack(settings.stream_events, settings.consumer_group,
                        process_batch(pipeline, stale))

            messages = read_group(
                settings.stream_events,
                settings.consumer_group,
                CONSUMER_NAME,
                count=BATCH_SIZE,
                block_ms=BLOCK_MS,
            )
            if not messages:
                continue

            done = process_batch(pipeline, messages)
            ack(settings.stream_events, settings.consumer_group, done)

            total += len(done)
            if total % 1000 < len(done):
                logger.info("Đã xử lý %d event", total)

        except Exception:  # noqa: BLE001
            # Redis/Postgres tạm mất kết nối không được phép giết worker.
            logger.exception("Lỗi vòng lặp worker, thử lại sau 3s")
            time.sleep(3)

    logger.info("Worker đã dừng. Tổng cộng %d event.", total)


if __name__ == "__main__":
    main()
