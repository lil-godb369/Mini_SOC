"""Ghép rule engine + correlator thành một đường ống phát hiện duy nhất.

Điểm quan trọng về thiết kế: lớp này KHÔNG chạm vào CSDL. Nó nhận vào một event
đã chuẩn hoá và trả ra danh sách "bản nháp cảnh báo". Nhờ vậy toàn bộ logic phát
hiện — phần lõi của đồ án — có thể unit test bằng dict thuần, không cần Postgres,
không cần Redis. Việc ghi xuống CSDL là chuyện của worker.

Các lớp phát hiện của Tuần 2 (mô hình ML mạng, phân tích hành vi ransomware) sẽ
cắm vào đúng đây và trả về cùng kiểu `AlertDraft`.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from .correlator import Correlator
from .draft import AlertDraft
from .ransomware import RansomwareDetector
from .rules_loader import Rule, RuleEngine, load_rules

logger = logging.getLogger(__name__)


def _evidence_from_event(event: dict) -> Dict[str, Any]:
    """Trích các trường có ích cho người phân tích (và cho lớp 3 tóm tắt)."""
    data = event.get("data", {}) or {}
    keys = (
        "pid", "ppid", "process_name", "process_path", "command_line", "user",
        "file_path", "file_name", "file_ext",
        "remote_ip", "remote_port", "registry_key", "registry_value",
    )
    return {k: data[k] for k in keys if data.get(k) not in (None, "")}


class DetectionPipeline:
    """Điều phối mọi bộ phát hiện của lớp 2.

    Từng bộ bật/tắt độc lập được (yêu cầu phi chức năng của đồ án). Mặc định lấy
    theo biến môi trường, nhưng test truyền thẳng tham số để khỏi phụ thuộc cấu
    hình bên ngoài.
    """

    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        enable_rules: Optional[bool] = None,
        enable_ransomware: Optional[bool] = None,
        enable_ml_network: Optional[bool] = None,
    ):
        from ..config import settings

        self.enable_rules = settings.enable_rule_engine if enable_rules is None else enable_rules
        self.enable_ransomware = (
            settings.enable_ransomware_behavior if enable_ransomware is None else enable_ransomware
        )
        want_ml = settings.enable_ml_network if enable_ml_network is None else enable_ml_network

        self.rules = rules if rules is not None else load_rules()
        self.rule_engine = RuleEngine(self.rules)
        self.correlator = Correlator(self.rules)
        self.ransomware = RansomwareDetector() if self.enable_ransomware else None

        # Nạp mô hình ML tách riêng: thiếu file mô hình (chưa huấn luyện) không
        # được phép làm chết worker — các bộ phát hiện còn lại vẫn phải chạy.
        self.ml_network = None
        if want_ml:
            from .ml_network import NetworkMLDetector

            try:
                self.ml_network = NetworkMLDetector()
            except Exception as exc:  # noqa: BLE001
                logger.error("Không nạp được mô hình ML mạng, tạm tắt lớp này: %s", exc)

        logger.info(
            "Đường ống phát hiện: %d rule đơn, %d rule ngưỡng, ransomware=%s, ml_mang=%s",
            len(self.rule_engine.single_rules),
            len(self.correlator.threshold_rules),
            "bật" if self.ransomware else "tắt",
            "bật" if self.ml_network else "tắt",
        )

    def process(self, event: dict, now: float, stateful: bool = True) -> List[AlertDraft]:
        """Chạy một event qua mọi bộ phát hiện đang bật.

        Worker supplies event-time epoch seconds. Late events may still run
        single-event rules and ML, with stateful detectors explicitly disabled.
        """
        drafts: List[AlertDraft] = []
        host = str(event.get("host", ""))
        ts = event.get("timestamp")
        base_evidence = _evidence_from_event(event)

        # --- Rule một-event ---
        for rule in (self.rule_engine.evaluate(event) if self.enable_rules else []):
            drafts.append(
                AlertDraft(
                    source="rule",
                    rule_id=rule.id,
                    title=rule.name,
                    severity=rule.severity,
                    technique=rule.technique,
                    technique_name=rule.technique_name,
                    tactic=rule.tactic,
                    host=host,
                    evidence=dict(base_evidence),
                    ts=ts if isinstance(ts, datetime) else None,
                )
            )

        # --- Rule ngưỡng / hành vi ---
        for hit in (self.correlator.evaluate(event, now=now) if self.enable_rules and stateful else []):
            evidence = dict(base_evidence)
            evidence.update(hit.as_evidence())
            drafts.append(
                AlertDraft(
                    source="rule",
                    rule_id=hit.rule.id,
                    title=f"{hit.rule.name} ({hit.count} event / {hit.window:g}s)",
                    severity=hit.rule.severity,
                    technique=hit.rule.technique,
                    technique_name=hit.rule.technique_name,
                    tactic=hit.rule.tactic,
                    host=host,
                    evidence=evidence,
                    ts=ts if isinstance(ts, datetime) else None,
                )
            )

        # --- Phân tích hành vi ransomware (entropy + tốc độ + đuôi + độ lan) ---
        if self.ransomware is not None and stateful:
            drafts.extend(self.ransomware.observe(event, now=now))

        # --- Mô hình ML trên luồng mạng ---
        if self.ml_network is not None:
            drafts.extend(self.ml_network.score(event))

        # Điền nốt những trường mà từng bộ phát hiện có thể bỏ trống.
        for draft in drafts:
            if not draft.host:
                draft.host = host
            if draft.ts is None and isinstance(ts, datetime):
                draft.ts = ts

        return drafts
