"""Phát hiện hành vi có trạng thái: "N event khớp trong X giây".

Dùng cho kỹ thuật chỉ đáng ngờ khi xuất hiện thành CỤM — ví dụ một loạt lệnh do
thám (T1057) hay mã hoá file hàng loạt (T1486). Event được gom theo trường
`group_by` (PID cha, tên tiến trình, host...) và mỗi cặp (rule, nhóm) giữ một
cửa sổ trượt riêng.

Port từ PyEDR (`engine/correlator.py`) với hai thay đổi:

1. Đồng hồ được TIÊM VÀO qua tham số `now` thay vì gọi `time.monotonic()` bên
   trong. Nhờ vậy unit test kiểm được ranh giới cửa sổ mà không phải `sleep`, và
   khi phát lại pcap/log cũ vẫn tương quan đúng theo thời gian của dữ liệu.
2. Giới hạn kích thước state để không rò rỉ bộ nhớ: một máy bị tấn công có thể
   sinh ra rất nhiều giá trị nhóm (mỗi PID một nhóm), nhóm im lặng lâu bị dọn.
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple

from . import matching
from .matching import get_field
from .rules_loader import Rule

logger = logging.getLogger(__name__)

# Số nhóm tối đa giữ trong bộ nhớ trước khi dọn các nhóm đã hết hạn.
MAX_TRACKED_GROUPS = 50_000


class CorrelationHit:
    """Một lần kích hoạt rule ngưỡng."""

    def __init__(self, rule: Rule, count: int, group_value: str, window: float):
        self.rule = rule
        self.count = count
        self.group_value = group_value
        self.window = window

    def as_evidence(self) -> dict:
        return {
            "matched_events": self.count,
            "window_seconds": self.window,
            "group_by": self.rule.detection.get("group_by", "host"),
            "group_value": self.group_value,
        }


class Correlator:
    def __init__(self, rules: List[Rule]):
        self.threshold_rules = [r for r in rules if r.type == "threshold"]
        # Host is always part of the identity: PIDs are local to each machine.
        self._state: Dict[Tuple[str, str, str], Deque[float]] = defaultdict(deque)
        # Chống cảnh báo lặp lại ở mỗi event khi cửa sổ đang "nóng".
        self._cooldown: Dict[Tuple[str, str, str], float] = {}

    def evaluate(self, event: dict, now: float) -> List[CorrelationHit]:
        """`now` must not decrease within a host; worker supplies event-time seconds."""
        hits: List[CorrelationHit] = []
        etype = event.get("event_type")

        for rule in self.threshold_rules:
            if rule.event_type and rule.event_type != etype:
                continue
            if not matching.matches(event, rule.detection):
                continue

            det = rule.detection
            window = float(det.get("window_seconds", 10))
            count = int(det.get("count", 5))
            group_field = det.get("group_by", "host")
            raw_group = get_field(event, group_field)
            host = event.get("host")
            if raw_group is None or raw_group == "" or not host:
                continue
            group_val = str(raw_group)

            key = (rule.id, str(host), group_val)
            bucket = self._state[key]
            bucket.append(now)
            while bucket and now - bucket[0] > window:
                bucket.popleft()

            if len(bucket) >= count and matching.matches(event, det.get("trigger") or {}):
                last_alert = self._cooldown.get(key, float("-inf"))
                if now - last_alert >= window:  # mỗi cửa sổ chỉ một cảnh báo
                    self._cooldown[key] = now
                    hits.append(CorrelationHit(rule, len(bucket), group_val, window))

        if len(self._state) > MAX_TRACKED_GROUPS:
            self._evict(now)
        return hits

    def _evict(self, now: float) -> None:
        """Dọn các nhóm đã rỗng hoặc quá hạn cửa sổ dài nhất."""
        max_window = max(
            (float(r.detection.get("window_seconds", 10)) for r in self.threshold_rules),
            default=10.0,
        )
        stale = [k for k, b in self._state.items() if not b or now - b[-1] > max_window]
        for key in stale:
            self._state.pop(key, None)
            self._cooldown.pop(key, None)
        logger.debug("Correlator dọn %d nhóm hết hạn", len(stale))
