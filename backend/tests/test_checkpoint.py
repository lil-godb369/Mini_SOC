"""Restart/backlog semantics through real worker transactions on temporary DB."""
import json
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sqlalchemy import select, func

from app import worker
from app.db import SessionLocal
from app.detection import DetectionPipeline
from app.models import Alert, DetectionState, Event


def send(at, index, file=False, host="PC"):
    data = ({"file_path": f"C:/lab/{index}.txt.locked", "entropy": 7.99}
            if file else {"ppid": 42, "process_name": "tasklist.exe", "command_line": "tasklist"})
    payload = {"host": host, "platform": "windows", "agent_id": 1,
               "event_uid": str(uuid4()), "timestamp": at.isoformat(),
               "event_type": "file_modify" if file else "process_create", "data": data}
    assert worker.process_batch(DetectionPipeline(enable_ransomware=file),
                                [(f"{index}-0", {"payload": json.dumps(payload)})]) == [f"{index}-0"]


def alerts(source="rule"):
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(Alert).where(Alert.source == source))


def test_partial_window_survives_new_pipeline_and_cooldown_survives_restart(client, fake_redis):
    start = datetime.now(timezone.utc) - timedelta(minutes=10)
    for i in range(4):
        send(start + timedelta(seconds=i), i)
    assert alerts() == 1
    for i in range(4, 7):
        send(start + timedelta(seconds=i), i)
    assert alerts() == 1
    with SessionLocal() as db:
        assert db.get(DetectionState, "PC").payload["rules"]


def test_slow_backlog_processed_fast_does_not_become_burst(client, fake_redis):
    start = datetime.now(timezone.utc) - timedelta(minutes=10)
    for i in range(4):
        send(start + timedelta(seconds=20*i), i)
    assert alerts() == 0


def test_late_event_is_saved_but_does_not_push_window_or_hide_single_rule(client, fake_redis):
    start = datetime.now(timezone.utc)
    for i in range(3):
        send(start + timedelta(seconds=i), i)
    send(start - timedelta(seconds=1), 9)
    assert alerts() == 0
    with SessionLocal() as db:
        rows = list(db.scalars(select(Event).order_by(Event.id)))
        assert rows[-1].data["_soc_timing"]["stateful_skipped"] is True
    payload = {"host": "PC", "timestamp": (start - timedelta(seconds=2)).isoformat(),
               "event_type": "process_create", "data": {"process_name": "powershell.exe", "command_line": "powershell -enc AAA"}}
    assert worker.process_batch(DetectionPipeline(), [("late-0", {"payload": json.dumps(payload)})])
    assert alerts() == 1
    send(start + timedelta(seconds=3), 10)
    assert alerts() == 2


def test_ransomware_distinct_files_and_cooldown_survive_restart(client, fake_redis):
    start = datetime.now(timezone.utc)
    for i in range(10):
        send(start + timedelta(seconds=i/10), i, file=True)
    assert alerts("ransomware") == 1
    send(start + timedelta(seconds=2), 11, file=True)
    assert alerts("ransomware") == 1


def test_checkpoint_rollback_does_not_advance_watermark(client, fake_redis, monkeypatch):
    start = datetime.now(timezone.utc)
    send(start, 1)
    from sqlalchemy.orm import Session
    original = Session.commit
    def unavailable(self):
        raise RuntimeError("commit failed")
    monkeypatch.setattr(Session, "commit", unavailable)
    payload = {"host": "PC", "event_type": "file_modify",
               "timestamp": (start + timedelta(seconds=20)).isoformat(), "data": {}}
    assert worker.process_batch(DetectionPipeline(), [("failed-0", {"payload": json.dumps(payload)})]) == []
    monkeypatch.setattr(Session, "commit", original)
    with SessionLocal() as db:
        assert db.get(DetectionState, "PC").payload["watermark"] == start.timestamp()
