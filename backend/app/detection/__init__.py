"""Lớp 2 — phát hiện.

Mọi bộ phát hiện chia sẻ chung một đầu ra (`AlertDraft`):

    rules_loader + correlator  — rule ATT&CK viết bằng YAML (Tuần 1)
    ransomware                 — phân tích hành vi entropy/tốc độ ghi (Tuần 2)
    ml_network                 — mô hình ML trên luồng mạng, CIC-IDS2017 (Tuần 2)
"""
from .draft import AlertDraft
from .normalizer import normalize
from .pipeline import DetectionPipeline
from .ransomware import RansomwareDetector
from .rules_loader import Rule, RuleEngine, load_rules

__all__ = [
    "AlertDraft",
    "normalize",
    "DetectionPipeline",
    "RansomwareDetector",
    "Rule",
    "RuleEngine",
    "load_rules",
]
