"""Test đầu-cuối cho mốc của Tuần 1.

Kiểm chứng đúng luồng mà đồ án hứa hẹn:

    agent gửi telemetry  ->  hàng đợi  ->  worker phát hiện  ->  CSDL  ->  API

Chạy được mà không cần Postgres hay Redis thật, nhờ SQLite và Redis giả. Cái
được kiểm ở đây là ĐƯỜNG DÂY, chứ không phải từng mảnh rời rạc — vì lỗi tích hợp
mới là loại lỗi làm hỏng buổi demo, chứ không phải lỗi trong một hàm đơn lẻ.
"""
from __future__ import annotations

import json

import pytest

from app import worker
from app.detection import DetectionPipeline


@pytest.fixture
def agent_key(client) -> str:
    resp = client.post("/api/v1/agents/enroll", json={
        "enroll_token": "test-enroll-token",
        "hostname": "MAY-NAN-NHAN",
        "platform": "windows",
        "version": "0.1.0",
    })
    assert resp.status_code == 201
    return resp.json()["api_key"]


def drain_queue(fake_redis, pipeline) -> list:
    """Lấy mọi event trong stream giả rồi chạy qua đúng hàm mà worker dùng."""
    queued = fake_redis.streams.get("minisoc:events", [])
    messages = [(f"{i}-0", fields) for i, fields in enumerate(queued)]
    fake_redis.streams["minisoc:events"] = []
    return worker.process_batch(pipeline, messages)


def send(client, api_key: str, events: list):
    resp = client.post("/api/v1/ingest", json={"events": events},
                       headers={"X-API-Key": api_key})
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Kịch bản 1 — PowerShell che giấu (T1059.001), rule một-event
# ---------------------------------------------------------------------------
def test_powershell_che_giau_sinh_canh_bao_high(client, fake_redis, auth_headers, agent_key):
    pipeline = DetectionPipeline()

    send(client, agent_key, [{
        "host": "MAY-NAN-NHAN",
        "platform": "windows",
        "event_type": "process_create",
        "data": {
            "pid": 4321, "ppid": 1000,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
            "user": "MAY-NAN-NHAN\\alice",
        },
    }])

    acked = drain_queue(fake_redis, pipeline)
    assert len(acked) == 1  # message đã được xử lý và ACK

    body = client.get("/api/v1/alerts", headers=auth_headers).json()
    assert body["total"] == 1

    alert = body["items"][0]
    assert alert["technique"] == "T1059.001"
    assert alert["severity"] == "high"
    assert alert["host"] == "MAY-NAN-NHAN"
    assert alert["source"] == "rule"
    assert alert["status"] == "new"
    # Bằng chứng phải đi được tới tận API, nếu không thì lớp 3 chẳng có gì để tóm tắt.
    assert "-enc" in alert["evidence"]["command_line"]

    # Event thô cũng phải được lưu để phục vụ điều tra.
    events = client.get("/api/v1/events", headers=auth_headers).json()
    assert len(events) == 1
    assert events[0]["event_type"] == "process_create"

    # Và cảnh báo phải được phát ra stream cho dashboard realtime.
    published = fake_redis.streams.get("minisoc:alerts", [])
    assert len(published) == 1
    assert json.loads(published[0]["payload"])["technique"] == "T1059.001"


# ---------------------------------------------------------------------------
# Kịch bản 2 — cụm do thám (T1057), rule ngưỡng qua nhiều event
# ---------------------------------------------------------------------------
def test_cum_do_tham_sinh_dung_mot_canh_bao(client, fake_redis, auth_headers, agent_key):
    pipeline = DetectionPipeline()

    recon = ["whoami.exe", "hostname.exe", "ipconfig.exe", "tasklist.exe", "systeminfo.exe"]
    send(client, agent_key, [
        {
            "host": "MAY-NAN-NHAN",
            "platform": "windows",
            "event_type": "process_create",
            "data": {"pid": 5000 + i, "ppid": 4321, "process_name": name,
                     "command_line": name},
        }
        for i, name in enumerate(recon)
    ])

    drain_queue(fake_redis, pipeline)

    body = client.get("/api/v1/alerts?technique=T1057", headers=auth_headers).json()
    # 5 lệnh do thám vượt ngưỡng 4, nhưng cooldown phải chặn cảnh báo thứ hai.
    assert body["total"] == 1

    alert = body["items"][0]
    assert alert["severity"] == "medium"
    assert alert["evidence"]["matched_events"] >= 4
    assert alert["evidence"]["group_value"] == "4321"  # gom theo tiến trình cha


# ---------------------------------------------------------------------------
# Kịch bản 3 — ransomware (T1486), cụm sửa file
# ---------------------------------------------------------------------------
def test_cum_sua_file_sinh_canh_bao_medium(client, fake_redis, auth_headers, agent_key):
    pipeline = DetectionPipeline()

    send(client, agent_key, [
        {
            "host": "MAY-NAN-NHAN",
            "platform": "windows",
            "event_type": "file_modify",
            "data": {"file_path": f"C:\\sandbox\\tai_lieu_{i:02d}.txt.locked",
                     "entropy": 7.97, "file_size": 4096},
        }
        for i in range(15)
    ])

    drain_queue(fake_redis, pipeline)

    body = client.get("/api/v1/alerts?severity=medium", headers=auth_headers).json()
    assert body["total"] == 1
    assert body["items"][0]["technique"] == "T1486"

    # Trường dẫn xuất do normalizer tính phải có mặt — lớp 2 của Tuần 2 cần chúng.
    events = client.get("/api/v1/events?event_type=file_modify", headers=auth_headers).json()
    assert events[0]["data"]["file_ext"] == ".locked"
    assert events[0]["data"]["entropy"] == 7.97


# ---------------------------------------------------------------------------
# Hoạt động bình thường không được sinh cảnh báo
# ---------------------------------------------------------------------------
def test_hoat_dong_binh_thuong_khong_sinh_canh_bao(client, fake_redis, auth_headers, agent_key):
    pipeline = DetectionPipeline()

    send(client, agent_key, [
        {"host": "MAY-NAN-NHAN", "platform": "windows", "event_type": "process_create",
         "data": {"pid": 100 + i, "ppid": 1, "process_name": name, "command_line": name}}
        for i, name in enumerate(["notepad.exe", "chrome.exe", "explorer.exe", "code.exe"])
    ])

    drain_queue(fake_redis, pipeline)

    body = client.get("/api/v1/alerts", headers=auth_headers).json()
    assert body["total"] == 0

    # Nhưng telemetry vẫn phải được lưu lại đầy đủ.
    assert len(client.get("/api/v1/events", headers=auth_headers).json()) == 4


# ---------------------------------------------------------------------------
# Độ bền của worker
# ---------------------------------------------------------------------------
def test_message_hong_duoc_ack_de_khong_ket_hang_doi(fake_redis):
    """Message không parse được sẽ không bao giờ tự lành — phải ACK, không retry."""
    pipeline = DetectionPipeline()
    acked = worker.process_batch(pipeline, [("1-0", {"payload": "{khong-phai-json"})])
    assert acked == ["1-0"]


def test_event_thieu_truong_bat_buoc_bi_bo_qua(fake_redis):
    pipeline = DetectionPipeline()
    acked = worker.process_batch(
        pipeline, [("1-0", {"payload": json.dumps({"host": "X", "data": {}})})]
    )
    assert acked == ["1-0"]  # thiếu event_type -> bỏ, nhưng vẫn ACK


def test_thong_ke_phan_anh_dung_so_lieu(client, fake_redis, auth_headers, agent_key):
    pipeline = DetectionPipeline()

    send(client, agent_key, [{
        "host": "MAY-NAN-NHAN", "platform": "windows", "event_type": "process_create",
        "data": {"process_name": "procdump.exe",
                 "command_line": "procdump.exe -ma lsass.exe out.dmp"},
    }])
    drain_queue(fake_redis, pipeline)

    stats = client.get("/api/v1/stats/overview", headers=auth_headers).json()
    assert stats["total_events"] == 1
    assert stats["total_alerts"] == 1
    assert stats["open_alerts"] == 1

    by_sev = {row["severity"]: row["count"] for row in stats["alerts_by_severity"]}
    assert by_sev["critical"] == 1

    assert stats["top_techniques"][0]["technique"] == "T1003"
