"""Kiểu dữ liệu cảnh báo dùng chung cho mọi bộ phát hiện.

Tách riêng khỏi `pipeline.py` để tránh phụ thuộc vòng: `pipeline` cần import các
bộ phát hiện, còn các bộ phát hiện cần import kiểu cảnh báo. Cả hai cùng phụ
thuộc vào module này thì vòng bị phá.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class AlertDraft:
    """Cảnh báo trước khi được ghi xuống CSDL.

    Mọi lớp phát hiện — rule ATT&CK, mô hình ML mạng, phân tích hành vi
    ransomware, honeypot, bộ quét lỗ hổng, phát hiện phishing — đều trả về đúng
    kiểu này. Nhờ vậy worker chỉ có một đường ghi, và dashboard chỉ có một dạng
    cảnh báo phải hiểu.
    """

    source: str                    # rule | ml_network | ransomware | honeypot | ...
    rule_id: str
    title: str
    severity: str                  # low | medium | high | critical
    technique: str = ""            # mã kỹ thuật MITRE ATT&CK
    technique_name: str = ""
    tactic: str = ""
    host: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: Optional[float] = None   # điểm của mô hình; rule để None
    ts: Optional[datetime] = None
