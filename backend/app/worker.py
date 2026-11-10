"""Worker phát hiện — trái tim của lớp 2.

Vòng lặp: đọc event từ Redis Stream → chuẩn hoá → chạy đường ống phát hiện →
ghi event và cảnh báo xuống Postgres → ACK message.

Vì sao ACK ở CUỐI, sau khi đã commit CSDL: nếu worker chết giữa chừng, message
chưa ACK vẫn nằm trong danh sách pending của consumer group và sẽ được nhận lại
(`xautoclaim`). Ledger trong cùng transaction ngăn ghi event/alert trùng khi
nhận lại message hoặc khi agent mới gửi lại cùng event_uid.

Chạy:  python -m app.worker
"""
from __future__ import annotations

import logging
import copy
import hashlib
import os
import signal
import socket
import time
from datetime import datetime, timezone
from typing import List

from sqlalchemy.orm import Session
from sqlalchemy import select

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
from .detection import checkpoint
from .models import Alert, Event, ProcessedMessage, DetectionState
from .monitoring import report_worker

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
    # Only mutable detection state is copied, never the potentially large ML model.
    snapshot = copy.deepcopy((pipeline.correlator, pipeline.ransomware))
    fingerprint = checkpoint.signature(pipeline)
    states = {}

    with SessionLocal() as db:
        try:
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

                identity = (
                    f"agent:{event.get('agent_id')}:{event['event_uid']}"
                    if event.get("event_uid") and event.get("agent_id") is not None
                    else f"stream:{settings.stream_events}:{message_id}"
                )
                key = hashlib.sha256(identity.encode()).hexdigest()
                if db.get(ProcessedMessage, key) is not None:
                    processed_ids.append(message_id)
                    continue
                db.add(ProcessedMessage(key=key))
                db.flush()  # Unique PK also guards concurrent attempts.
                host = str(event.get("host", "unknown"))
                if host not in states:
                    row = db.scalar(select(DetectionState).where(DetectionState.host == host).with_for_update())
                    if row is None:
                        row = DetectionState(host=host, payload={})
                        db.add(row)
                        db.flush()
                    correlator, ransomware, watermark = checkpoint.restore(pipeline, row.payload, fingerprint)
                    states[host] = [row, correlator, ransomware, watermark]
                state = states[host]
                pipeline.correlator, pipeline.ransomware = state[1:3]
                event_time = event["timestamp"].timestamp()
                late = state[3] is not None and event_time < state[3]
                if late:
                    event["data"] = {**event.get("data", {}), "_soc_timing": {
                        "late": True, "stateful_skipped": True, "watermark": state[3]}}
                drafts = pipeline.process(event, now=event_time, stateful=not late)
                if not late:
                    state[3] = event_time
                new_alerts.extend(_persist(db, event, drafts))
                processed_ids.append(message_id)

            for row, correlator, ransomware, watermark in states.values():
                row.payload = checkpoint.dump(correlator, ransomware, watermark, fingerprint)
            db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("Batch failed; rolling back database and detection state")
            db.rollback()
            pipeline.correlator, pipeline.ransomware = snapshot
            return []

        # Phát cảnh báo ra stream SAU khi commit — dashboard realtime và bộ gửi
        # thông báo chỉ được thấy những gì đã thực sự nằm trong CSDL.
        for alert in new_alerts:
            try:
                db.refresh(alert)
                publish_alert(_alert_payload(alert))
            except Exception:
                # Dashboard reads the committed DB. Stream notifications are best effort
                # until a transactional notification outbox is implemented.
                logger.warning("Alert committed but stream notification failed (id=%s)", alert.id)
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
    last_batch_at = None

    while _running:
        try:
            try:
                report_worker(CONSUMER_NAME, pipeline, total, last_batch_at)
            except Exception:  # Observation failure must not stop event processing.
                logger.warning("Unable to publish worker observation")
            # Định kỳ nhận lại việc mà worker khác đã bỏ dở.
            if time.monotonic() - last_claim > CLAIM_EVERY_SECONDS:
                last_claim = time.monotonic()
                stale = claim_stale(
                    settings.stream_events, settings.consumer_group, CONSUMER_NAME
                )
                if stale:
                    recovered = process_batch(pipeline, stale)
                    ack(settings.stream_events, settings.consumer_group, recovered)
                    total += len(recovered)
                    if recovered:
                        last_batch_at = datetime.now(timezone.utc).isoformat()

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
            if done:
                last_batch_at = datetime.now(timezone.utc).isoformat()
            if total % 1000 < len(done):
                logger.info("Đã xử lý %d event", total)

        except Exception:  # noqa: BLE001
            # Redis/Postgres tạm mất kết nối không được phép giết worker.
            logger.exception("Lỗi vòng lặp worker, thử lại sau 3s")
            time.sleep(3)

    logger.info("Worker đã dừng. Tổng cộng %d event.", total)


if __name__ == "__main__":
    main()
