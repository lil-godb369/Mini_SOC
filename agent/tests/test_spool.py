"""Durable retry tests use temporary SQLite files and fake HTTP only."""
from types import SimpleNamespace
from pathlib import Path
import subprocess
import sys

from mini_soc_agent.sender import EventSender
from mini_soc_agent.spool import DiskSpool


def event():
    return {"host": "PC", "event_type": "file_modify", "data": {"file_path": "demo.txt"}}


def test_committed_events_survive_reopening_and_identity_does_not_change(tmp_path):
    path = str(tmp_path / "queue.sqlite3")
    spool = DiskSpool(path)
    assert spool.append("key-a", event())
    first = spool.batch("key-a", 100)
    reopened = DiskSpool(path)
    assert reopened.batch("key-a", 100) == first
    assert first[0][1]["event_uid"]
    assert reopened.batch("key-b", 100) == []


def test_capacity_drops_new_event_and_persists_counter(tmp_path):
    path = str(tmp_path / "queue.sqlite3")
    spool = DiskSpool(path, max_events=1)
    assert spool.append("scope", event())
    assert not spool.append("scope", event())
    assert DiskSpool(path).stats("scope")["dropped_full"] == 1
    assert spool.stats("scope")["stored"] == 1


def test_payload_byte_limit_and_quarantine_count_towards_capacity(tmp_path):
    spool = DiskSpool(str(tmp_path / "queue.sqlite3"), max_bytes=1)
    assert not spool.append("scope", event())
    spool.max_bytes = 10_000
    spool.max_events = 1
    assert spool.append("scope", event())
    rows = spool.batch("scope", 100)
    spool.complete(rows, [0])
    assert spool.batch("scope", 100) == []
    assert spool.stats("scope")["quarantined"] == 1
    assert not spool.append("scope", event())


def test_network_failure_and_restart_replay_same_id_then_ack(tmp_path, monkeypatch):
    import requests
    state = str(tmp_path / "agent.json")
    sender = EventSender("http://test", state)
    sender.api_key = "test-key"
    assert sender.send(event())
    uid = sender.spool.batch(sender.scope, 100)[0][1]["event_uid"]

    def offline(*args, **kwargs):
        raise requests.ConnectionError()

    monkeypatch.setattr(sender._session, "post", offline)
    sender._stop.set()  # One failed send, then bounded shutdown with data retained.
    sender._run()
    assert sender.spool.stats(sender.scope)["pending"] == 1
    restarted = EventSender("http://test", state)
    restarted.api_key = "test-key"
    seen = []

    def success(url, **kwargs):
        seen.extend(kwargs["json"]["events"])
        return SimpleNamespace(status_code=200, json=lambda: {"accepted": 1, "rejected": 0})

    monkeypatch.setattr(restarted._session, "post", success)
    restarted._stop.set()
    restarted._run()
    assert seen[0]["event_uid"] == uid
    assert restarted.spool.stats(restarted.scope)["stored"] == 0
    assert not restarted.storage_failed.is_set()


def test_partial_ack_quarantines_reject_and_deletes_only_accepted(tmp_path, monkeypatch):
    sender = EventSender("http://test", str(tmp_path / "agent.json"))
    sender.api_key = "test-key"
    sender.send(event())
    sender.send(event())
    monkeypatch.setattr(sender._session, "post", lambda *a, **k: SimpleNamespace(
        status_code=200, json=lambda: {"accepted": 1, "rejected": 1, "rejected_indices": [1]}))
    sender._stop.set()
    sender._run()
    stats = sender.spool.stats(sender.scope)
    assert stats["stored"] == stats["quarantined"] == 1
    assert stats["pending"] == 0


def test_invalid_ack_preserves_batch(tmp_path, monkeypatch):
    sender = EventSender("http://test", str(tmp_path / "agent.json"))
    sender.api_key = "test-key"
    sender.send(event())
    # Old API with partial rejects but no indices cannot safely acknowledge rows.
    monkeypatch.setattr(sender._session, "post", lambda *a, **k: SimpleNamespace(
        status_code=200, json=lambda: {"accepted": 0, "rejected": 1}))
    sender._stop.set()
    sender._run()
    assert sender.spool.stats(sender.scope)["pending"] == 1


def test_revoked_key_retains_rows_and_new_key_does_not_replay_them(tmp_path, monkeypatch):
    sender = EventSender("http://test", str(tmp_path / "agent.json"))
    sender.api_key = "old-key"
    sender.send(event())
    old_scope = sender.scope
    monkeypatch.setattr(sender._session, "post", lambda *a, **k: SimpleNamespace(status_code=401))
    sender._run()
    assert sender.auth_failed.is_set()
    assert sender.spool.stats(old_scope)["pending"] == 1
    sender.api_key = "new-key"
    assert sender.spool.batch(sender.scope, 100) == []


def test_disk_failure_sets_fatal_flag_without_network_request(tmp_path, monkeypatch):
    sender = EventSender("http://test", str(tmp_path / "agent.json"))
    def unavailable(*args):
        raise OSError("disk full")
    monkeypatch.setattr(sender.spool, "append", unavailable)
    assert not sender.send(event())
    assert sender.storage_failed.is_set()


def test_process_termination_after_append_keeps_committed_event(tmp_path):
    path = str(tmp_path / "queue.sqlite3")
    script = """
import os, sys
from mini_soc_agent.spool import DiskSpool
spool = DiskSpool(sys.argv[1])
assert spool.append('scope', {'host': 'PC', 'event_type': 'file_modify', 'data': {}})
os._exit(23)
"""
    result = subprocess.run([sys.executable, "-c", script, path],
                            cwd=str(Path(__file__).resolve().parents[1]),
                            capture_output=True, timeout=15)
    assert result.returncode == 23, result.stderr.decode(errors="replace")
    assert DiskSpool(path).stats("scope")["pending"] == 1


def test_spool_status_does_not_send_network_or_expose_key(tmp_path, monkeypatch, capsys):
    from mini_soc_agent.agent import main
    import requests
    sender = EventSender("http://test", str(tmp_path / "agent.json"))
    sender.api_key, sender.agent_id = "private-test-key", 1
    sender.save_state()
    sender.send(event())
    def forbidden(*args, **kwargs):
        raise AssertionError("status must not call network")
    monkeypatch.setattr(requests.Session, "post", forbidden)
    assert main(["--server", "http://test", "--state-file", sender.state_path, "--spool-status"]) == 0
    output = capsys.readouterr().out
    assert '"pending": 1' in output
    assert sender.api_key not in output
