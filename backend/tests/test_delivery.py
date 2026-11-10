"""Retry after lost HTTP/ACK and transaction failure must not duplicate state."""
import json
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import worker
from app.db import SessionLocal
from app.detection import DetectionPipeline
from app.models import Event, Alert, ProcessedMessage


def counts():
    with SessionLocal() as db:
        return tuple(db.scalar(select(func.count()).select_from(model))
                     for model in (Event, Alert, ProcessedMessage))


def message(uid=None, name="powershell.exe", command="powershell -enc AAA"):
    return {"host": "PC", "platform": "windows", "event_type": "process_create",
            "agent_id": 1, "event_uid": uid,
            "data": {"ppid": 42, "process_name": name, "command_line": command}}


def test_lost_ack_replayed_stream_message_is_not_processed_twice(client, fake_redis):
    pipeline = DetectionPipeline()
    batch = [("1-0", {"payload": json.dumps(message())})]
    assert worker.process_batch(pipeline, batch) == ["1-0"]
    assert worker.process_batch(DetectionPipeline(), batch) == ["1-0"]
    assert counts() == (1, 1, 1)


def test_lost_http_response_duplicate_ingest_preserves_uid(client, fake_redis):
    key = client.post("/api/v1/agents/enroll", json={
        "enroll_token": "test-enroll-token", "hostname": "PC", "platform": "windows",
    }).json()["api_key"]
    event = message(str(uuid.uuid4()))
    for _ in range(2):
        assert client.post("/api/v1/ingest", json={"events": [event]},
                           headers={"X-API-Key": key}).status_code == 200
    stream = fake_redis.streams["minisoc:events"]
    assert worker.process_batch(DetectionPipeline(), [
        (f"{i}-0", fields) for i, fields in enumerate(stream)]) == ["0-0", "1-0"]
    assert counts() == (1, 1, 1)


def test_same_uid_is_scoped_to_agent(client, fake_redis):
    uid = str(uuid.uuid4())
    one, two = message(uid), message(uid)
    two["agent_id"] = 2
    rows = [("1-0", {"payload": json.dumps(one)}), ("2-0", {"payload": json.dumps(two)})]
    assert len(worker.process_batch(DetectionPipeline(), rows)) == 2
    assert counts() == (2, 2, 2)


def test_commit_failure_restores_detection_state_before_retry(client, fake_redis, monkeypatch):
    pipeline = DetectionPipeline(enable_ransomware=True)
    rows = [(f"{i}-0", {"payload": json.dumps(message(str(uuid.uuid4()), "tasklist.exe", "tasklist"))})
            for i in range(4)]
    original = Session.commit
    def fail(self):
        raise RuntimeError("commit unavailable")
    monkeypatch.setattr(Session, "commit", fail)
    assert worker.process_batch(pipeline, rows) == []
    assert counts() == (0, 0, 0)
    assert not pipeline.correlator._state
    assert not pipeline.correlator._cooldown
    monkeypatch.setattr(Session, "commit", original)
    assert len(worker.process_batch(pipeline, rows)) == 4
    assert counts() == (4, 1, 4)


def test_notification_failure_does_not_undo_or_duplicate_committed_alert(client, fake_redis, monkeypatch):
    def fail(*args):
        raise RuntimeError("stream offline")
    monkeypatch.setattr(worker, "publish_alert", fail)
    batch = [("1-0", {"payload": json.dumps(message(str(uuid.uuid4())))})]
    assert worker.process_batch(DetectionPipeline(), batch) == ["1-0"]
    assert worker.process_batch(DetectionPipeline(), batch) == ["1-0"]
    assert counts() == (1, 1, 1)


def test_partial_rejection_reports_exact_indices(client, fake_redis):
    key = client.post("/api/v1/agents/enroll", json={
        "enroll_token": "test-enroll-token", "hostname": "PC", "platform": "windows",
    }).json()["api_key"]
    response = client.post("/api/v1/ingest", headers={"X-API-Key": key}, json={"events": [
        message(), {"host": "PC", "event_type": "invalid", "data": {}}, message(),
    ]})
    assert response.json()["rejected_indices"] == [1]
    assert response.json()["accepted"] == 2
