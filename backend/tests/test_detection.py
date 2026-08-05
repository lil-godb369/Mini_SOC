"""Unit test cho lõi phát hiện (lớp 2).

Toàn bộ test ở đây chạy trên dict thuần — không CSDL, không Redis, không mạng.
Đó là lý do `pipeline.py` được thiết kế không chạm CSDL: phần quan trọng nhất
của đồ án phải kiểm chứng được trong vài mili giây.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.detection import normalize
from app.detection.correlator import Correlator
from app.detection.matching import eval_condition, matches
from app.detection.pipeline import DetectionPipeline
from app.detection.rules_loader import RuleEngine, load_rules


# ---------------------------------------------------------------------------
# Tiện ích
# ---------------------------------------------------------------------------
def make_event(event_type: str, **data) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": "TEST-PC",
        "platform": "windows",
        "event_type": event_type,
        "data": data,
    }


# ---------------------------------------------------------------------------
# matching.py
# ---------------------------------------------------------------------------
class TestMatching:
    def test_contains_any_khong_phan_biet_hoa_thuong(self):
        event = make_event("process_create", command_line="POWERSHELL.EXE -EncodedCommand ABC")
        cond = {"field": "data.command_line", "op": "contains_any", "values": ["-encodedcommand"]}
        assert eval_condition(event, cond) is True

    def test_truong_thieu_khong_gay_loi(self):
        event = make_event("process_create")
        cond = {"field": "data.command_line", "op": "contains_any", "values": ["x"]}
        assert eval_condition(event, cond) is False

    def test_duong_dan_long_nhau_khong_ton_tai(self):
        event = make_event("process_create")
        cond = {"field": "data.khong.co.that", "op": "exists"}
        assert eval_condition(event, cond) is False

    def test_op_in_yeu_cau_khop_chinh_xac(self):
        event = make_event("process_create", process_name="whoami.exe")
        assert eval_condition(event, {"field": "data.process_name", "op": "in",
                                      "values": ["whoami.exe", "id"]}) is True
        # "whoami" khong bang "whoami.exe" -> phai la False
        assert eval_condition(event, {"field": "data.process_name", "op": "in",
                                      "values": ["whoami"]}) is False

    def test_so_sanh_so(self):
        event = make_event("file_modify", entropy=7.95)
        assert eval_condition(event, {"field": "data.entropy", "op": "gt", "values": [7.5]}) is True
        assert eval_condition(event, {"field": "data.entropy", "op": "lt", "values": [7.5]}) is False

    def test_so_sanh_so_voi_gia_tri_khong_phai_so(self):
        event = make_event("file_modify", entropy="rat cao")
        assert eval_condition(event, {"field": "data.entropy", "op": "gt", "values": [7.5]}) is False

    def test_logic_all_va_any(self):
        event = make_event("process_create", command_line="powershell -nop", process_name="powershell.exe")
        conditions = [
            {"field": "data.command_line", "op": "contains_any", "values": ["-nop"]},
            {"field": "data.command_line", "op": "contains_any", "values": ["khong-co"]},
        ]
        assert matches(event, {"logic": "any", "conditions": conditions}) is True
        assert matches(event, {"logic": "all", "conditions": conditions}) is False

    def test_danh_sach_dieu_kien_rong_khop_moi_thu(self):
        assert matches(make_event("file_modify"), {"conditions": []}) is True

    def test_op_khong_hop_le_bao_loi(self):
        with pytest.raises(ValueError):
            eval_condition(make_event("process_create"),
                           {"field": "data.x", "op": "op_bia_dat", "values": []})


# ---------------------------------------------------------------------------
# normalizer.py
# ---------------------------------------------------------------------------
class TestNormalizer:
    def test_event_thieu_event_type_bi_loai(self):
        assert normalize({"host": "a", "data": {}}) is None

    def test_data_khong_phai_dict_duoc_thay_bang_dict_rong(self):
        event = normalize({"event_type": "process_create", "data": "hong"})
        assert event["data"] == {}

    def test_tu_suy_ra_ten_tien_trinh_tu_duong_dan_windows(self):
        event = normalize(make_event("process_create",
                                     process_path=r"C:\Windows\System32\cmd.exe"))
        assert event["data"]["process_name"] == "cmd.exe"

    def test_tu_suy_ra_ten_tien_trinh_tu_duong_dan_linux(self):
        event = normalize(make_event("process_create", process_path="/usr/bin/whoami"))
        assert event["data"]["process_name"] == "whoami"

    def test_trich_duoi_file(self):
        event = normalize(make_event("file_modify", file_path=r"C:\sandbox\bao_cao.docx.LOCKED"))
        assert event["data"]["file_ext"] == ".locked"
        assert event["data"]["file_name"] == "bao_cao.docx.LOCKED"

    def test_file_khong_co_duoi(self):
        event = normalize(make_event("file_modify", file_path="/etc/passwd"))
        assert event["data"]["file_ext"] == ""

    def test_timestamp_hong_duoc_thay_bang_thoi_diem_hien_tai(self):
        event = normalize({"event_type": "process_create", "timestamp": "khong-phai-ngay",
                           "host": "a", "data": {}})
        assert isinstance(event["timestamp"], datetime)

    def test_timestamp_hau_to_z_duoc_hieu_la_utc(self):
        event = normalize({"event_type": "process_create",
                           "timestamp": "2026-08-05T10:00:00Z", "host": "a", "data": {}})
        assert event["timestamp"].tzinfo is not None
        assert event["timestamp"].year == 2026


# ---------------------------------------------------------------------------
# Nạp rule
# ---------------------------------------------------------------------------
class TestRuleLoading:
    def test_nap_du_nam_rule_attack(self):
        rules = load_rules()
        assert len(rules) == 5
        techniques = {r.technique for r in rules}
        assert techniques == {"T1059.001", "T1547.001", "T1057", "T1003", "T1486"}

    def test_moi_rule_deu_co_anh_xa_attack(self):
        for rule in load_rules():
            assert rule.technique, f"{rule.id} thiếu technique"
            assert rule.tactic, f"{rule.id} thiếu tactic"
            assert rule.severity in {"low", "medium", "high", "critical"}


# ---------------------------------------------------------------------------
# Rule một-event
# ---------------------------------------------------------------------------
class TestSingleEventRules:
    @pytest.fixture
    def engine(self):
        return RuleEngine(load_rules())

    def test_powershell_ma_hoa_kich_hoat_t1059(self, engine):
        event = make_event("process_create", process_name="powershell.exe",
                           command_line="powershell.exe -nop -w hidden -enc SQBFAFgA")
        hits = engine.evaluate(event)
        assert "T1059.001" in {h.technique for h in hits}

    def test_powershell_binh_thuong_khong_kich_hoat(self, engine):
        event = make_event("process_create", process_name="powershell.exe",
                           command_line="powershell.exe Get-Date")
        assert engine.evaluate(event) == []

    def test_ghi_run_key_kich_hoat_t1547(self, engine):
        event = make_event(
            "process_create", process_name="reg.exe",
            command_line=r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v X /d calc.exe /f",
        )
        assert "T1547.001" in {h.technique for h in engine.evaluate(event)}

    def test_scheduled_task_kich_hoat_t1547(self, engine):
        event = make_event("process_create", process_name="schtasks.exe",
                           command_line="schtasks /create /tn Backdoor /tr calc.exe /sc onlogon")
        assert "T1547.001" in {h.technique for h in engine.evaluate(event)}

    def test_cron_linux_kich_hoat_t1547(self, engine):
        event = make_event("process_create", process_name="bash",
                           command_line="bash -c 'crontab -l'")
        assert "T1547.001" in {h.technique for h in engine.evaluate(event)}

    def test_dump_lsass_kich_hoat_t1003_critical(self, engine):
        event = make_event("process_create", process_name="procdump.exe",
                           command_line="procdump.exe -ma lsass.exe out.dmp")
        hits = engine.evaluate(event)
        assert "T1003" in {h.technique for h in hits}
        assert any(h.severity == "critical" for h in hits)

    def test_doc_shadow_linux_kich_hoat_t1003(self, engine):
        event = make_event("process_create", process_name="cat",
                           command_line="cat /etc/shadow")
        assert "T1003" in {h.technique for h in engine.evaluate(event)}

    def test_rule_process_create_khong_ap_vao_file_modify(self, engine):
        event = make_event("file_modify", file_path="C:\\tmp\\lsass.txt")
        assert engine.evaluate(event) == []


# ---------------------------------------------------------------------------
# Correlator — đây là nơi đồng hồ tiêm vào phát huy tác dụng
# ---------------------------------------------------------------------------
class TestCorrelator:
    @pytest.fixture
    def correlator(self):
        return Correlator(load_rules())

    def _recon(self, ppid: int = 1000, name: str = "whoami.exe") -> dict:
        return make_event("process_create", process_name=name, ppid=ppid)

    def test_duoi_nguong_thi_khong_canh_bao(self, correlator):
        for i in range(3):  # rule cần 4
            assert correlator.evaluate(self._recon(), now=float(i)) == []

    def test_dat_nguong_thi_canh_bao(self, correlator):
        hits = []
        for i in range(4):
            hits.extend(correlator.evaluate(self._recon(), now=float(i)))
        assert len(hits) == 1
        assert hits[0].rule.technique == "T1057"
        assert hits[0].count == 4

    def test_event_ngoai_cua_so_khong_cong_don(self, correlator):
        # 4 event nhưng trải trên 60s, trong khi cửa sổ chỉ 15s -> không được kích hoạt.
        hits = []
        for i in range(4):
            hits.extend(correlator.evaluate(self._recon(), now=float(i * 20)))
        assert hits == []

    def test_tien_trinh_cha_khac_nhau_dem_rieng(self, correlator):
        # 3 event từ ppid 1000 + 3 từ ppid 2000: không nhóm nào đủ 4.
        hits = []
        for i in range(3):
            hits.extend(correlator.evaluate(self._recon(ppid=1000), now=float(i)))
            hits.extend(correlator.evaluate(self._recon(ppid=2000), now=float(i)))
        assert hits == []

    def test_cooldown_chan_canh_bao_lap(self, correlator):
        hits = []
        for i in range(10):  # vượt xa ngưỡng 4
            hits.extend(correlator.evaluate(self._recon(), now=float(i)))
        # Chỉ được đúng một cảnh báo trong cửa sổ 15s, không phải 7 cái.
        assert len(hits) == 1

    def test_cum_ransomware_kich_hoat_t1486(self, correlator):
        hits = []
        for i in range(12):  # ngưỡng là 12 file trong 5s
            event = make_event("file_modify", file_path=f"C:\\sandbox\\f{i}.txt.locked")
            hits.extend(correlator.evaluate(event, now=i * 0.1))
        assert len(hits) == 1
        assert hits[0].rule.technique == "T1486"

    def test_sua_file_thua_thot_khong_kich_hoat(self, correlator):
        hits = []
        for i in range(12):  # 12 file nhưng cách nhau 1s -> vượt cửa sổ 5s
            event = make_event("file_modify", file_path=f"C:\\docs\\f{i}.txt")
            hits.extend(correlator.evaluate(event, now=float(i)))
        assert hits == []


# ---------------------------------------------------------------------------
# Đường ống hoàn chỉnh
# ---------------------------------------------------------------------------
class TestPipeline:
    @pytest.fixture
    def pipeline(self):
        return DetectionPipeline()

    def test_sinh_ban_nhap_canh_bao_du_thong_tin(self, pipeline):
        event = normalize(make_event(
            "process_create", process_name="powershell.exe",
            command_line="powershell -nop -enc AAA", pid=1234, ppid=1000, user="TEST-PC\\alice",
        ))
        drafts = pipeline.process(event, now=1.0)
        assert len(drafts) == 1

        draft = drafts[0]
        assert draft.source == "rule"
        assert draft.severity == "high"
        assert draft.technique == "T1059.001"
        assert draft.host == "TEST-PC"
        # Bằng chứng phải đủ để người phân tích hiểu chuyện gì đã xảy ra.
        assert draft.evidence["command_line"] == "powershell -nop -enc AAA"
        assert draft.evidence["pid"] == 1234
        assert draft.evidence["user"] == "TEST-PC\\alice"

    def test_event_lanh_khong_sinh_canh_bao(self, pipeline):
        event = normalize(make_event("process_create", process_name="notepad.exe",
                                     command_line="notepad.exe ghi_chu.txt"))
        assert pipeline.process(event, now=1.0) == []

    def test_mot_event_co_the_kich_hoat_nhieu_rule(self, pipeline):
        # Dòng lệnh này vừa khớp PowerShell đáng ngờ (-nop) vừa khớp persistence (schtasks /create).
        event = normalize(make_event(
            "process_create", process_name="powershell.exe",
            command_line="powershell -nop -c \"schtasks /create /tn X /tr calc.exe\"",
        ))
        techniques = {d.technique for d in pipeline.process(event, now=1.0)}
        assert {"T1059.001", "T1547.001"} <= techniques

    def test_bang_chung_cua_rule_nguong_co_so_lieu_cua_so(self, pipeline):
        drafts = []
        for i in range(12):
            event = normalize(make_event("file_modify", file_path=f"C:\\sandbox\\f{i}.locked"))
            drafts.extend(pipeline.process(event, now=i * 0.1))

        assert len(drafts) == 1
        evidence = drafts[0].evidence
        assert evidence["matched_events"] == 12
        assert evidence["window_seconds"] == 5
        assert evidence["group_by"] == "host"
