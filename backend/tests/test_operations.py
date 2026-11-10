"""Operational behavior, isolated from the running lab services."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.detection.correlator import Correlator
from app.detection.rules_loader import load_rules


def test_heartbeat_updates_idle_agent_but_creates_no_event(client, fake_redis, auth_headers):
    from app.db import SessionLocal
    from app.models import Agent

    enrollment = client.post("/api/v1/agents/enroll", json={
        "enroll_token": "test-enroll-token", "hostname": "IDLE-PC", "platform": "windows",
    }).json()
    with SessionLocal() as db:
        agent = db.get(Agent, enrollment["agent_id"])
        agent.last_seen = datetime.now(timezone.utc) - timedelta(minutes=10)
        db.commit()
    assert client.get("/api/v1/stats/overview", headers=auth_headers).json()["agents_online"] == 0
    response = client.post("/api/v1/agents/heartbeat", headers={"X-API-Key": enrollment["api_key"]})
    assert response.status_code == 200
    assert response.json()["last_seen"] is not None
    assert "api_key" not in response.json()
    assert "api_key_hash" not in response.json()
    assert client.get("/api/v1/stats/overview", headers=auth_headers).json()["agents_online"] == 1
    assert client.get("/api/v1/events", headers=auth_headers).json() == []
    assert not fake_redis.streams
    client.delete(f"/api/v1/agents/{enrollment['agent_id']}", headers=auth_headers)
    assert client.post("/api/v1/agents/heartbeat", headers={"X-API-Key": enrollment["api_key"]}).status_code == 401
    assert client.post("/api/v1/agents/heartbeat").status_code == 401


def test_discovery_does_not_mix_hosts_or_missing_parent():
    correlator = Correlator(load_rules())
    def event(host, ppid):
        return {"host": host, "event_type": "process_create",
                "data": {"ppid": ppid, "process_name": "tasklist.exe"}}
    for i in range(3):
        assert not correlator.evaluate(event("A", 42), now=i)
    assert not correlator.evaluate(event("B", 42), now=3)
    assert len(correlator.evaluate(event("A", 42), now=4)) == 1
    for i in range(6):
        assert not correlator.evaluate(event("C", None), now=i)


def test_worker_status_requires_user(client):
    assert client.get("/api/v1/stats/worker").status_code == 401


def test_worker_observations_report_actual_loaded_detectors(client, auth_headers, monkeypatch):
    from app import monitoring

    class RedisObservations:
        def __init__(self):
            self.values = {}
        def set(self, key, value, ex):
            assert ex == 90
            self.values[key] = value
        def scan_iter(self, **kwargs):
            return iter(self.values)
        def get(self, key):
            return self.values.get(key)
        def xlen(self, stream):
            return 100
        def exists(self, stream):
            return True
        def xinfo_groups(self, stream):
            return [{"name": "detection", "pending": 2, "lag": 7}]

    redis = RedisObservations()
    monkeypatch.setattr(monitoring, "get_redis", lambda: redis)
    assert client.get("/api/v1/stats/worker", headers=auth_headers).json()["status"] == "unknown"
    pipeline = SimpleNamespace(enable_rules=True, ransomware=object(), ml_network=None)
    monitoring.report_worker("worker-test", pipeline, 12, None)
    body = client.get("/api/v1/stats/worker", headers=auth_headers).json()
    assert body["status"] == "observed"
    assert body["workers"][0]["detectors"] == {"rules": True, "ransomware": True, "ml_network": False}
    assert body["queue"] == {"length": 100, "pending": 2, "lag": 7}
    redis.values.clear()  # Simulate expired heartbeat, not a healthy idle worker.
    assert client.get("/api/v1/stats/worker", headers=auth_headers).json()["status"] == "unknown"

    def unavailable():
        raise RuntimeError("private infrastructure details")
    monkeypatch.setattr(monitoring, "get_redis", unavailable)
    response = client.get("/api/v1/stats/worker", headers=auth_headers)
    assert response.status_code == 503
    assert "private" not in response.text
