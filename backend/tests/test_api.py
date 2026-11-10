"""Test API: xác thực, đăng ký agent, thu thập telemetry.

Đây cũng là nơi kiểm chứng các yêu cầu phi chức năng về bảo mật — không chỉ
"đường đi thuận lợi có chạy không", mà cả "đường đi xấu có bị chặn không".
"""
from __future__ import annotations

import json


# ---------------------------------------------------------------------------
# Sức khoẻ hệ thống
# ---------------------------------------------------------------------------
def test_health_tra_ve_trang_thai_tung_thanh_phan(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["checks"]["api"] == "ok"
    assert body["checks"]["database"] == "ok"


def test_endpoint_modules_liet_ke_cac_lop(client):
    body = client.get("/api/v1/modules").json()
    assert body["layer1_collection"] is True
    assert "layer2_rule_engine" in body


# ---------------------------------------------------------------------------
# Xác thực
# ---------------------------------------------------------------------------
class TestAuth:
    def test_dang_nhap_dung_tra_ve_token(self, client):
        resp = client.post("/api/v1/auth/login",
                           json={"email": "admin@test.local", "password": "TestPassword#1"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"]
        assert body["role"] == "admin"

    def test_sai_mat_khau_bi_tu_choi(self, client):
        resp = client.post("/api/v1/auth/login",
                           json={"email": "admin@test.local", "password": "sai-mat-khau"})
        assert resp.status_code == 401

    def test_thong_bao_loi_khong_lo_tai_khoan_co_ton_tai_hay_khong(self, client):
        sai_mat_khau = client.post("/api/v1/auth/login",
                                   json={"email": "admin@test.local", "password": "x"})
        khong_ton_tai = client.post("/api/v1/auth/login",
                                    json={"email": "ai_do@test.local", "password": "x"})
        # Cùng mã lỗi VÀ cùng nội dung -> không dò được danh sách tài khoản.
        assert sai_mat_khau.status_code == khong_ton_tai.status_code == 401
        assert sai_mat_khau.json()["detail"] == khong_ton_tai.json()["detail"]

    def test_khong_co_token_thi_khong_doc_duoc_canh_bao(self, client):
        assert client.get("/api/v1/alerts").status_code == 401

    def test_token_gia_bi_tu_choi(self, client):
        resp = client.get("/api/v1/alerts",
                          headers={"Authorization": "Bearer khong.phai.jwt"})
        assert resp.status_code == 401

    def test_me_tra_ve_nguoi_dung_hien_tai(self, client, auth_headers):
        body = client.get("/api/v1/auth/me", headers=auth_headers).json()
        assert body["email"] == "admin@test.local"
        assert body["role"] == "admin"
        # Không bao giờ để lộ hash mật khẩu ra API.
        assert "password_hash" not in body


# ---------------------------------------------------------------------------
# Đăng ký agent
# ---------------------------------------------------------------------------
class TestAgentEnrollment:
    def test_dang_ky_thanh_cong_tra_ve_api_key(self, client):
        resp = client.post("/api/v1/agents/enroll", json={
            "enroll_token": "test-enroll-token",
            "hostname": "MAY-THU-NGHIEM",
            "platform": "windows",
            "version": "0.1.0",
        })
        assert resp.status_code == 201
        body = resp.json()
        assert body["api_key"].startswith("msoc_")
        assert body["agent_id"] > 0

    def test_sai_token_enroll_bi_tu_choi(self, client):
        resp = client.post("/api/v1/agents/enroll", json={
            "enroll_token": "token-sai",
            "hostname": "MAY-GIA-MAO",
            "platform": "linux",
        })
        assert resp.status_code == 401

    def test_platform_khong_hop_le_bi_tu_choi(self, client):
        resp = client.post("/api/v1/agents/enroll", json={
            "enroll_token": "test-enroll-token",
            "hostname": "MAY-LA",
            "platform": "solaris",
        })
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Thu thập telemetry
# ---------------------------------------------------------------------------
class TestIngest:
    def _enroll(self, client, hostname="MAY-INGEST") -> str:
        resp = client.post("/api/v1/agents/enroll", json={
            "enroll_token": "test-enroll-token",
            "hostname": hostname,
            "platform": "windows",
        })
        return resp.json()["api_key"]

    def test_khong_co_api_key_thi_bi_chan(self, client):
        resp = client.post("/api/v1/ingest", json={"events": [
            {"host": "X", "event_type": "process_create", "data": {}}
        ]})
        assert resp.status_code == 401

    def test_api_key_sai_bi_chan(self, client):
        resp = client.post(
            "/api/v1/ingest",
            json={"events": [{"host": "X", "event_type": "process_create", "data": {}}]},
            headers={"X-API-Key": "msoc_key_bia_dat"},
        )
        assert resp.status_code == 401

    def test_gui_event_hop_le_thi_vao_hang_doi(self, client, fake_redis):
        api_key = self._enroll(client)
        resp = client.post(
            "/api/v1/ingest",
            json={"events": [{
                "host": "MAY-INGEST",
                "platform": "windows",
                "event_type": "process_create",
                "data": {"process_name": "powershell.exe", "command_line": "powershell -enc AAA"},
            }]},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 200
        assert resp.json() == {"accepted": 1, "rejected": 0, "reasons": [], "rejected_indices": []}

        # Event phải nằm trong stream, không nằm thẳng trong CSDL.
        queued = fake_redis.streams["minisoc:events"]
        assert len(queued) == 1
        payload = json.loads(queued[0]["payload"])
        assert payload["data"]["command_line"] == "powershell -enc AAA"

    def test_loai_event_khong_ho_tro_bi_tu_choi(self, client):
        api_key = self._enroll(client, "MAY-LOAI-LA")
        resp = client.post(
            "/api/v1/ingest",
            json={"events": [{"host": "X", "event_type": "khong_ton_tai", "data": {}}]},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 200
        assert resp.json()["accepted"] == 0
        assert resp.json()["rejected"] == 1

    def test_agent_khong_the_mao_danh_may_khac(self, client, fake_redis):
        """Agent gửi host giả, server phải ghi đè bằng hostname đã đăng ký."""
        api_key = self._enroll(client, "MAY-THAT")
        client.post(
            "/api/v1/ingest",
            json={"events": [{
                "host": "MAY-GIAM-DOC",       # cố tình khai man
                "event_type": "process_create",
                "data": {},
            }]},
            headers={"X-API-Key": api_key},
        )
        payload = json.loads(fake_redis.streams["minisoc:events"][-1]["payload"])
        assert payload["host"] == "MAY-THAT"

    def test_lo_rong_bi_tu_choi_o_tang_kiem_tra(self, client):
        api_key = self._enroll(client, "MAY-LO-RONG")
        resp = client.post("/api/v1/ingest", json={"events": []},
                           headers={"X-API-Key": api_key})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Đọc cảnh báo
# ---------------------------------------------------------------------------
class TestAlerts:
    def test_danh_sach_rong_luc_moi_cai(self, client, auth_headers):
        body = client.get("/api/v1/alerts", headers=auth_headers).json()
        assert body["total"] == 0
        assert body["items"] == []

    def test_loc_theo_muc_do_khong_hop_le_bi_tu_choi(self, client, auth_headers):
        resp = client.get("/api/v1/alerts?severity=tham_hoa", headers=auth_headers)
        assert resp.status_code == 422

    def test_canh_bao_khong_ton_tai_tra_404(self, client, auth_headers):
        assert client.get("/api/v1/alerts/999999", headers=auth_headers).status_code == 404

    def test_thong_ke_tong_quan_co_du_truong(self, client, auth_headers):
        body = client.get("/api/v1/stats/overview", headers=auth_headers).json()
        assert body["total_alerts"] == 0
        assert len(body["alerts_by_severity"]) == 4
        assert isinstance(body["timeline"], list)
