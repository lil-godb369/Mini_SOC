"""Lifecycle regressions: idle heartbeat, revoked keys and explicit reenrollment."""
import json
from types import SimpleNamespace

import pytest

from mini_soc_agent.agent import main
from mini_soc_agent.sender import EventSender


def test_idle_sender_checks_key_without_telemetry(tmp_path, monkeypatch):
    sender = EventSender("http://test", str(tmp_path / "agent.json"))
    sender.api_key = "test-key"
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(status_code=401)

    monkeypatch.setattr(sender._session, "post", post)
    sender._run()
    assert sender.auth_failed.is_set()
    assert len(calls) == 1
    assert calls[0][0].endswith("/agents/heartbeat")
    assert calls[0][1]["headers"] == {"X-API-Key": "test-key"}


def test_ingest_revocation_is_terminal_not_auto_enrollment(tmp_path, monkeypatch):
    sender = EventSender("http://test", str(tmp_path / "agent.json"))
    monkeypatch.setattr(sender._session, "post", lambda *a, **k: SimpleNamespace(status_code=401))
    assert sender._post([{"event_type": "file_modify"}]) is False
    assert sender.auth_failed.is_set()


def test_network_outage_is_retryable_and_does_not_log_key(tmp_path, monkeypatch, caplog):
    import requests

    sender = EventSender("http://test", str(tmp_path / "agent.json"))
    sender.api_key = "test-secret-not-for-logs"

    def unavailable(*args, **kwargs):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(sender._session, "post", unavailable)
    assert sender._heartbeat() is False
    assert not sender.auth_failed.is_set()
    assert sender.api_key not in caplog.text


def test_state_is_bound_to_server_and_legacy_state_still_loads(tmp_path):
    state = tmp_path / "agent.json"
    sender = EventSender("http://one", str(state))
    sender.api_key, sender.agent_id = "test-key", 7
    sender.save_state()
    with pytest.raises(RuntimeError, match="mismatch"):
        EventSender("http://two", str(state)).load_state()
    state.write_text(json.dumps({"api_key": "legacy-key", "agent_id": 1}), encoding="utf-8")
    assert EventSender("http://one", str(state)).load_state()


def test_reenroll_requires_token_without_touching_state(tmp_path):
    state = tmp_path / "agent.json"
    state.write_text("preserve", encoding="utf-8")
    assert main(["--reenroll", "--enroll-token", "", "--state-file", str(state)]) == 2
    assert state.read_text(encoding="utf-8") == "preserve"


def test_explicit_reenroll_does_not_reuse_saved_key(tmp_path, monkeypatch):
    state = tmp_path / "agent.json"
    state.write_text("preserve", encoding="utf-8")

    def must_not_load(self):
        pytest.fail("--reenroll must bypass saved state")

    def unavailable(self, *args):
        raise RuntimeError("offline")

    monkeypatch.setattr(EventSender, "load_state", must_not_load)
    monkeypatch.setattr(EventSender, "enroll", unavailable)
    assert main(["--reenroll", "--enroll-token", "test", "--state-file", str(state)]) == 3
    assert state.read_text(encoding="utf-8") == "preserve"


def test_failed_state_replace_preserves_existing_key(tmp_path, monkeypatch):
    from mini_soc_agent import sender as module

    state = tmp_path / "agent.json"
    state.write_text("old-state", encoding="utf-8")
    sender = EventSender("http://test", str(state))
    sender.api_key = "new-test-key"

    def fail(*args):
        raise OSError("disk unavailable")

    monkeypatch.setattr(module.os, "replace", fail)
    with pytest.raises(OSError):
        sender.save_state()
    assert state.read_text(encoding="utf-8") == "old-state"
    assert list(tmp_path.iterdir()) == [state]
