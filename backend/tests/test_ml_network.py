"""Unit test cho suy luận mô hình ML mạng (lớp 2).

Trọng tâm của bộ test này là các lỗi TRIỂN KHAI học máy — loại lỗi mà mô hình
vẫn chạy, vẫn trả về một con số trông hợp lý, nhưng con số đó vô nghĩa. Chúng
không làm chương trình sập nên rất khó phát hiện nếu không kiểm tra có chủ đích:

* đặc trưng bị xếp sai thứ tự so với lúc huấn luyện
* dữ liệu vào thiếu đặc trưng, bị âm thầm điền 0
* giá trị inf/NaN từ phép chia cho thời lượng luồng bằng 0
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

pytest.importorskip("sklearn", reason="cần scikit-learn để chạy test suy luận")
pytest.importorskip("joblib")

import joblib  # noqa: E402
import numpy as np  # noqa: E402

from app.detection.ml_network import NetworkMLDetector  # noqa: E402

# Tên đặc trưng cố ý giữ nguyên khoảng trắng thừa như trong CIC-IDS2017.
FEATURES = [
    " Flow Duration",
    " Total Fwd Packets",
    " Total Backward Packets",
    "Flow Bytes/s",
    " Flow Packets/s",
    " Fwd Packet Length Mean",
    " Bwd Packet Length Mean",
    " ACK Flag Count",
]


@pytest.fixture(scope="module")
def model_dir(tmp_path_factory):
    """Huấn luyện một mô hình tí hon và lưu đúng định dạng mà ml/train.py sinh ra."""
    from sklearn.ensemble import RandomForestClassifier

    rng = np.random.default_rng(0)
    n = 400
    # Lớp 0 (lành tính): giá trị nhỏ. Lớp 1 (tấn công): giá trị lớn ở cột đầu.
    benign = rng.normal(loc=10.0, scale=2.0, size=(n, len(FEATURES)))
    attack = rng.normal(loc=100.0, scale=2.0, size=(n, len(FEATURES)))
    X = np.vstack([benign, attack])
    y = np.array([0] * n + [1] * n)

    model = RandomForestClassifier(n_estimators=30, random_state=0).fit(X, y)

    directory = tmp_path_factory.mktemp("artifacts")
    joblib.dump(
        {
            "model": model,
            "feature_names": FEATURES,
            "metadata": {"task": "binary", "split": "day"},
        },
        directory / "random_forest.joblib",
    )
    return directory


@pytest.fixture
def detector(model_dir):
    return NetworkMLDetector(model_dir=model_dir, model_name="random_forest",
                             alert_threshold=0.80)


def flow_event(features: dict, host="MAY-VAN-PHONG", remote_ip="203.0.113.9") -> dict:
    return {
        "timestamp": datetime.now(timezone.utc),
        "host": host,
        "platform": "windows",
        "event_type": "network_flow",
        "data": {
            "remote_ip": remote_ip,
            "remote_port": 443,
            "protocol": "tcp",
            "flow_features": features,
        },
    }


def values(magnitude: float) -> dict:
    return {name: magnitude for name in FEATURES}


# ---------------------------------------------------------------------------
# Nạp mô hình
# ---------------------------------------------------------------------------
class TestNapMoHinh:
    def test_thieu_file_mo_hinh_bao_loi_ro_rang(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="ml/train.py|ENABLE_ML_NETWORK"):
            NetworkMLDetector(model_dir=tmp_path, model_name="khong_ton_tai")

    def test_nap_duoc_ten_dac_trung_va_sieu_du_lieu(self, detector):
        assert detector.feature_names == FEATURES
        assert detector.metadata["split"] == "day"


# ---------------------------------------------------------------------------
# Dựng vector đặc trưng — nơi lỗi im lặng hay xảy ra nhất
# ---------------------------------------------------------------------------
class TestDungVectorDacTrung:
    def test_vector_dung_thu_tu_huan_luyen_du_dict_dao_lon(self, detector):
        """Dict trong Python giữ thứ tự chèn — nếu code tin vào đó thì sẽ sai."""
        dao_nguoc = {name: float(i) for i, name in enumerate(reversed(FEATURES))}
        vector = detector.build_vector(dao_nguoc)

        # ' Flow Duration' là đặc trưng ĐẦU lúc huấn luyện, nhưng CUỐI trong dict.
        assert vector is not None
        assert vector[0] == float(len(FEATURES) - 1)
        assert vector[-1] == 0.0

    def test_khop_ten_bo_qua_khoang_trang_hoa_thuong_gach_duoi(self, detector):
        """Bộ trích xuất luồng đặt tên `flow_duration`, dataset dùng ' Flow Duration'."""
        features = {
            "flow_duration": 42.0,
            "total_fwd_packets": 7.0,
            "TOTAL_BACKWARD_PACKETS": 3.0,
            "flow_bytes_s": 100.0,
            "FlowPacketsS": 5.0,
            "fwd packet length mean": 60.0,
            "bwd_packet_length_mean": 80.0,
            "ack flag count": 1.0,
        }
        vector = detector.build_vector(features)
        assert vector is not None
        assert vector[0] == 42.0     # Flow Duration
        assert vector[1] == 7.0      # Total Fwd Packets
        assert vector[7] == 1.0      # ACK Flag Count

    def test_thieu_qua_nhieu_dac_trung_thi_TU_CHOI_cham_diem(self, detector):
        """Thà không chấm điểm còn hơn điền 0 rồi cho ra dự đoán rác."""
        assert detector.build_vector({" Flow Duration": 100.0}) is None

    def test_thieu_it_dac_trung_van_cham_diem_duoc(self, detector):
        features = values(100.0)
        features.pop(" ACK Flag Count")   # 7/8 = 87.5% > ngưỡng 80%
        assert detector.build_vector(features) is not None

    def test_vo_cuc_va_nan_duoc_thay_bang_khong(self, detector):
        """inf sinh ra thật khi Flow Bytes/s chia cho thời lượng luồng bằng 0."""
        features = values(100.0)
        features["Flow Bytes/s"] = float("inf")
        features[" Flow Packets/s"] = float("nan")

        vector = detector.build_vector(features)
        assert vector is not None
        assert all(np.isfinite(vector)), "vector còn giá trị vô cực -> sklearn sẽ nổ"

    def test_gia_tri_khong_phai_so_bi_bo_qua(self, detector):
        features = values(100.0)
        features[" Flow Duration"] = "rat lau"
        vector = detector.build_vector(features)
        # Còn 7/8 đặc trưng hợp lệ -> vẫn đủ ngưỡng, và ô hỏng về 0.
        assert vector is not None
        assert vector[0] == 0.0


# ---------------------------------------------------------------------------
# Chấm điểm
# ---------------------------------------------------------------------------
class TestChamDiem:
    def test_luu_luong_tan_cong_sinh_canh_bao(self, detector):
        drafts = detector.score(flow_event(values(100.0)))
        assert len(drafts) == 1

        alert = drafts[0]
        assert alert.source == "ml_network"
        assert alert.technique == "T1071"
        assert alert.confidence >= 0.80
        assert alert.evidence["remote_ip"] == "203.0.113.9"
        # Cảnh báo phải nói rõ mô hình được huấn luyện thế nào — người đọc cần
        # biết con số này đáng tin tới đâu, không chỉ thấy "0.94".
        assert alert.evidence["trained_split"] == "day"

    def test_luu_luong_lanh_tinh_khong_sinh_canh_bao(self, detector):
        assert detector.score(flow_event(values(10.0))) == []

    def test_bo_qua_event_khong_phai_network_flow(self, detector):
        event = flow_event(values(100.0))
        event["event_type"] = "process_create"
        assert detector.score(event) == []

    def test_thieu_flow_features_khong_gay_loi(self, detector):
        event = flow_event(values(100.0))
        event["data"].pop("flow_features")
        assert detector.score(event) == []

    def test_nguong_cao_hon_thi_it_canh_bao_hon(self, model_dir):
        nhay = NetworkMLDetector(model_dir=model_dir, alert_threshold=0.50)
        chat = NetworkMLDetector(model_dir=model_dir, alert_threshold=0.999)
        # Điểm giữa hai cụm: mô hình phân vân, xác suất nằm lưng chừng.
        event = flow_event(values(60.0))
        assert len(nhay.score(event)) >= len(chat.score(event))

    def test_muc_do_nghiem_trong_tang_theo_xac_suat(self, detector):
        drafts = detector.score(flow_event(values(100.0)))
        assert drafts[0].severity in ("medium", "high", "critical")


# ---------------------------------------------------------------------------
# Tích hợp với đường ống
# ---------------------------------------------------------------------------
def test_pipeline_van_chay_khi_chua_co_mo_hinh(monkeypatch, tmp_path):
    """Chưa huấn luyện mô hình thì lớp ML tự tắt, các lớp khác KHÔNG được sập."""
    from app.config import settings
    from app.detection import DetectionPipeline

    monkeypatch.setattr(settings, "ml_model_dir", str(tmp_path))

    pipeline = DetectionPipeline(enable_ml_network=True, enable_ransomware=False)
    assert pipeline.ml_network is None   # đã tắt trong im lặng, không ném lỗi

    # Rule engine vẫn phải hoạt động bình thường.
    from app.detection import normalize

    event = normalize({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": "X", "platform": "windows", "event_type": "process_create",
        "data": {"process_name": "powershell.exe", "command_line": "powershell -enc AAA"},
    })
    assert len(pipeline.process(event, now=1.0)) == 1


def test_pipeline_cam_duoc_mo_hinh_va_sinh_canh_bao(monkeypatch, model_dir):
    from app.config import settings
    from app.detection import DetectionPipeline

    monkeypatch.setattr(settings, "ml_model_dir", str(model_dir))
    monkeypatch.setattr(settings, "ml_model_name", "random_forest")

    pipeline = DetectionPipeline(enable_ml_network=True, enable_ransomware=False)
    assert pipeline.ml_network is not None

    drafts = pipeline.process(flow_event(values(100.0)), now=1.0)
    assert [d.source for d in drafts] == ["ml_network"]
    # Pipeline phải điền host cho những bộ phát hiện bỏ trống trường này.
    assert drafts[0].host == "MAY-VAN-PHONG"
