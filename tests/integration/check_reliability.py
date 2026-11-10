"""Disposable Postgres/Redis check; never run against the project's .env DB."""
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

sys.path.insert(0, "/srv")

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from app.main import app
from app.bus import read_group, ack, claim_stale
from app.config import settings
from app.db import SessionLocal
from app.models import Alert, Event

assert settings.database_url.endswith("@postgres:5432/reliability"), "Use disposable compose only"


def run_worker(messages):
    # A new interpreter for every batch verifies persistence, not reused Python RAM.
    script = """
import json, sys
from app.worker import process_batch
from app.detection import DetectionPipeline
messages = json.load(sys.stdin)
assert len(process_batch(DetectionPipeline(), messages)) == len(messages)
"""
    completed = subprocess.run([sys.executable, "-c", script], input=json.dumps(messages),
                               text=True, capture_output=True, timeout=60, cwd="/srv")
    assert completed.returncode == 0, completed.stderr


def count(model, source=None, host=None):
    with SessionLocal() as db:
        query = select(func.count()).select_from(model)
        if source:
            query = query.where(Alert.source == source)
        if host:
            query = query.where(model.host == host)
        return db.scalar(query)


with TestClient(app) as client:
    key = client.post("/api/v1/agents/enroll", json={
        "enroll_token": settings.agent_enroll_token, "hostname": "RESTART-PC", "platform": "windows",
    }).json()["api_key"]
    headers = {"X-API-Key": key}
    assert client.post("/api/v1/agents/heartbeat", headers=headers).status_code == 200
    start = datetime.now(timezone.utc) - timedelta(minutes=10)

    def event(i, seconds=None, file=False, parent=42):
        return {"event_uid": str(uuid4()), "host": "RESTART-PC",
                "timestamp": (start + timedelta(seconds=i if seconds is None else seconds)).isoformat(),
                "event_type": "file_modify" if file else "process_create",
                "data": {"file_path": f"C:/sandbox/{i}.locked", "entropy": 7.99} if file else {
                    "ppid": parent, "process_name": "tasklist.exe", "command_line": "tasklist"}}

    def ingest(events):
        response = client.post("/api/v1/ingest", headers=headers, json={"events": events})
        assert response.status_code == 200 and response.json()["accepted"] == len(events)

    def drain():
        messages = read_group(settings.stream_events, settings.consumer_group, "active", block_ms=50)
        run_worker(messages)
        ack(settings.stream_events, settings.consumer_group, [m[0] for m in messages])

    ingest([event(i) for i in range(3)])
    pending = read_group(settings.stream_events, settings.consumer_group, "dead", block_ms=50)
    run_worker(pending)  # Committed, then worker exits before ACK.
    assert count(Event) == 3 and count(Alert) == 0
    replayed = claim_stale(settings.stream_events, settings.consumer_group, "replacement", min_idle_ms=0)
    assert len(replayed) == 3
    run_worker(replayed)
    ack(settings.stream_events, settings.consumer_group, [m[0] for m in replayed])
    assert count(Event) == 3 and count(Alert) == 0
    fourth = event(3)
    ingest([fourth])
    drain()
    assert count(Event) == 4 and count(Alert) == 1
    ingest([fourth, event(4)])  # Lost HTTP response retry + cooldown across process restart.
    drain()
    assert count(Event) == 5 and count(Alert) == 1
    ingest([event(10+i, seconds=10+i/10, file=True) for i in range(9)])
    drain()
    assert count(Alert, source="ransomware") == 0
    ingest([event(19, seconds=11, file=True)])
    drain()
    assert count(Alert, source="ransomware") == 1
    # Events spaced 20 seconds apart must not become a burst when drained at once.
    before = count(Alert)
    ingest([event(30+i, seconds=40+i*20, parent=99) for i in range(4)])
    drain()
    assert count(Alert) == before
    login = client.post("/api/v1/auth/login", json={
        "email": settings.admin_email, "password": settings.admin_password,
    }).json()["access_token"]
    observations = client.get("/api/v1/stats/worker", headers={"Authorization": "Bearer " + login})
    assert observations.status_code == 200 and observations.json()["queue"]["pending"] == 0

    contracts = [
        ("powershell.exe", "powershell -enc AAA", "T1059.001"),
        ("reg.exe", r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Demo /d calc.exe", "T1547.001"),
        ("schtasks.exe", "schtasks /create /tn Demo /tr calc.exe /sc onlogon", "T1053.005"),
        ("crontab", "crontab /tmp/demo.cron", "T1053.003"),
        ("procdump.exe", "procdump -ma lsass.exe output.dmp", "T1003"),
        ("powershell.exe", "powershell -NoProfile -File backup.ps1", None),
        ("crontab", "crontab -l", None),
        ("reg.exe", "reg add /?", None),
    ]
    user_headers = {"Authorization": "Bearer " + login}
    for name, command, technique in contracts:
        previous = count(Alert)
        ingest([{"host": "RESTART-PC", "event_uid": str(uuid4()),
                 "timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "process_create",
                 "data": {"process_name": name, "command_line": command}}])
        drain()
        assert count(Alert) == previous + (1 if technique else 0), name
        if technique:
            evidence = client.get("/api/v1/alerts?limit=1", headers=user_headers).json()["items"][0]
            assert evidence["technique"] == technique and evidence["evidence"]["command_line"] == command

print("PASS: real Postgres/Redis, restart/retry/checkpoint/backlog, detection positive/negative contracts")
