"""Suy luận mô hình ML trên luồng mạng — lớp 2.

Nạp mô hình đã huấn luyện ở `ml/train.py` và chấm điểm các event `network_flow`
theo thời gian gần thực.

Ba điều module này làm rất nghiêm ngặt, vì đây là chỗ mà lỗi triển khai học máy
thường IM LẶNG — mô hình vẫn chạy, vẫn trả về số, nhưng số đó vô nghĩa:

1. **Thứ tự đặc trưng.** Vector đưa vào mô hình phải xếp đúng thứ tự lúc huấn
   luyện. Ta không tin vào thứ tự khoá của dict gửi lên, mà dựng lại vector theo
   đúng `feature_names` lưu kèm mô hình.
2. **Đặc trưng thiếu.** Nếu bộ trích xuất luồng gửi thiếu quá nhiều đặc trưng,
   module TỪ CHỐI chấm điểm thay vì điền 0 rồi cho ra một dự đoán rác.
3. **Giá trị vô cực và NaN.** `Flow Bytes/s` chia cho thời lượng luồng; luồng
   dài 0 sinh ra `inf`, và scikit-learn sẽ ném lỗi giữa lúc đang chạy thật.
"""
from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

from .draft import AlertDraft

logger = logging.getLogger(__name__)

# Thư mục chứa artifact sinh ra bởi ml/train.py.
DEFAULT_MODEL_DIR = Path(__file__).resolve().parents[3] / "ml" / "artifacts"
DEFAULT_MODEL_NAME = "random_forest"

# Dưới tỉ lệ này thì từ chối chấm điểm — dữ liệu vào quá thiếu để tin được.
MIN_FEATURE_COVERAGE = 0.80

# Chỉ báo động khi xác suất vượt ngưỡng. Đặt cao vì ở một SMB không có người
# trực SOC, cảnh báo giả tốn kém hơn nhiều so với một lần bỏ sót — cái bỏ sót
# vẫn còn rule engine và lớp hành vi làm lưới đỡ.
DEFAULT_ALERT_THRESHOLD = 0.80

SEVERITY_BY_PROBABILITY = [(0.98, "critical"), (0.92, "high"), (0.80, "medium")]


def _normalise_key(name: str) -> str:
    """Khoá so khớp không phân biệt hoa thường, khoảng trắng, gạch dưới.

    Tên đặc trưng của CIC-IDS2017 có khoảng trắng thừa (`' Flow Duration'`), còn
    bộ trích xuất luồng lại hay đặt tên kiểu `flow_duration`. Chuẩn hoá cả hai
    phía về một dạng để chúng gặp nhau, thay vì bắt agent phải khớp từng ký tự.
    """
    return "".join(ch for ch in name.lower() if ch.isalnum())


class NetworkMLDetector:
    def __init__(
        self,
        model_dir: Optional[Path] = None,
        model_name: Optional[str] = None,
        alert_threshold: Optional[float] = None,
    ):
        import joblib  # import tại chỗ: backend chạy được kể cả khi chưa cài sklearn

        from ..config import settings

        if model_dir is not None:
            directory = Path(model_dir)
        elif settings.ml_model_dir:
            # Trong Docker, ml/artifacts được mount vào và trỏ bằng ML_MODEL_DIR.
            directory = Path(settings.ml_model_dir)
        else:
            directory = DEFAULT_MODEL_DIR

        model_name = model_name or settings.ml_model_name
        alert_threshold = (
            settings.ml_alert_threshold if alert_threshold is None else alert_threshold
        )
        path = directory / f"{model_name}.joblib"
        if not path.exists():
            raise FileNotFoundError(
                f"Không tìm thấy mô hình tại {path}. "
                "Chạy `python ml/train.py` để huấn luyện, hoặc đặt ENABLE_ML_NETWORK=false."
            )

        bundle = joblib.load(path)
        self.model = bundle["model"]
        self.feature_names: List[str] = bundle["feature_names"]
        self.metadata: Dict[str, Any] = bundle.get("metadata", {})
        self.alert_threshold = alert_threshold
        self.model_name = model_name

        # Bảng tra từ tên đã chuẩn hoá -> vị trí trong vector đặc trưng.
        self._index_by_key = {
            _normalise_key(name): i for i, name in enumerate(self.feature_names)
        }

        logger.info(
            "Đã nạp mô hình ML mạng '%s': %d đặc trưng, huấn luyện kiểu %s, chia theo %s",
            model_name, len(self.feature_names),
            self.metadata.get("task", "?"), self.metadata.get("split", "?"),
        )

    # -----------------------------------------------------------------
    def build_vector(self, features: Dict[str, Any]) -> Optional[List[float]]:
        """Dựng vector đặc trưng đúng thứ tự huấn luyện.

        Trả về None nếu thiếu quá nhiều đặc trưng — thà không chấm điểm còn hơn
        chấm ra một con số không có căn cứ.
        """
        incoming = {_normalise_key(k): v for k, v in features.items()}

        vector = [0.0] * len(self.feature_names)
        found = 0
        for key, index in self._index_by_key.items():
            if key not in incoming:
                continue
            try:
                value = float(incoming[key])
            except (TypeError, ValueError):
                continue
            # inf/NaN xuất hiện thật khi thời lượng luồng bằng 0.
            if math.isnan(value) or math.isinf(value):
                value = 0.0
            vector[index] = value
            found += 1

        coverage = found / len(self.feature_names) if self.feature_names else 0.0
        if coverage < MIN_FEATURE_COVERAGE:
            logger.debug(
                "Bỏ qua chấm điểm: chỉ có %d/%d đặc trưng (%.0f%%)",
                found, len(self.feature_names), coverage * 100,
            )
            return None
        return vector

    @staticmethod
    def _severity_for(probability: float) -> str:
        for threshold, severity in SEVERITY_BY_PROBABILITY:
            if probability >= threshold:
                return severity
        return "low"

    def score(self, event: dict) -> List[AlertDraft]:
        """Chấm điểm một event network_flow. Trả về danh sách rỗng nếu không đáng báo."""
        if event.get("event_type") != "network_flow":
            return []

        data = event.get("data", {}) or {}
        features = data.get("flow_features")
        if not isinstance(features, dict) or not features:
            return []

        vector = self.build_vector(features)
        if vector is None:
            return []

        try:
            if hasattr(self.model, "predict_proba"):
                probability = float(self.model.predict_proba([vector])[0][1])
            else:
                # IsolationForest: -1 là bất thường, +1 là bình thường.
                probability = 1.0 if self.model.predict([vector])[0] == -1 else 0.0
        except Exception as exc:  # noqa: BLE001 — mô hình lỗi không được giết worker
            logger.error("Chấm điểm thất bại: %s", exc)
            return []

        if probability < self.alert_threshold:
            return []

        severity = self._severity_for(probability)
        remote_ip = data.get("remote_ip", "")
        remote_port = data.get("remote_port", "")

        evidence = {
            "model": self.model_name,
            "probability": round(probability, 4),
            "threshold": self.alert_threshold,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "protocol": data.get("protocol", ""),
            # Ghi lại cách mô hình được huấn luyện: người đọc cảnh báo cần biết
            # con số này đáng tin tới đâu, chứ không chỉ thấy "0.94".
            "trained_task": self.metadata.get("task"),
            "trained_split": self.metadata.get("split"),
            "feature_count": len(self.feature_names),
        }

        return [
            AlertDraft(
                source="ml_network",
                rule_id=f"ML-{self.model_name}",
                title=(
                    f"Luồng mạng bất thường (xác suất {probability:.1%}) "
                    f"tới {remote_ip}:{remote_port}"
                    if remote_ip else
                    f"Luồng mạng bất thường (xác suất {probability:.1%})"
                ),
                severity=severity,
                technique="T1071",
                technique_name="Application Layer Protocol",
                tactic="Command and Control",
                host=str(event.get("host", "")),
                evidence=evidence,
                confidence=round(probability, 4),
            )
        ]
