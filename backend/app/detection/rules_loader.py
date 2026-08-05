"""Nạp rule YAML và đánh giá các phát hiện không trạng thái (một event).

Rule dạng ngưỡng/hành vi được chuyển cho Correlator xử lý.
Port từ PyEDR (`engine/rule_engine.py`), thêm kiểm tra tính hợp lệ khi nạp: một
rule sai cú pháp phải bị phát hiện lúc khởi động chứ không phải lúc đang demo.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

import yaml

from . import matching

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
RULES_DIR = Path(__file__).parent / "rules"


class Rule:
    def __init__(self, raw: dict, source: str):
        self.source = source
        self.id: str = raw["id"]
        self.name: str = raw.get("name", self.id)
        self.technique: str = raw.get("technique", "")
        self.technique_name: str = raw.get("technique_name", "")
        self.tactic: str = raw.get("tactic", "")
        self.severity: str = raw.get("severity", "medium")
        self.event_type: str = raw.get("event_type", "")
        self.enabled: bool = raw.get("enabled", True)
        self.description: str = raw.get("description", "")
        self.detection: dict = raw.get("detection", {}) or {}
        self.type: str = self.detection.get("type", "single")

    def __repr__(self) -> str:
        return f"<Rule {self.id} ({self.type})>"


def _validate(raw: dict, source: str) -> None:
    if not raw.get("id"):
        raise ValueError(f"{source}: thiếu trường 'id'")
    sev = raw.get("severity", "medium")
    if sev not in VALID_SEVERITIES:
        raise ValueError(f"{source}: severity '{sev}' không hợp lệ")

    detection = raw.get("detection") or {}
    rtype = detection.get("type", "single")
    if rtype not in ("single", "threshold"):
        raise ValueError(f"{source}: detection.type '{rtype}' không hợp lệ")
    if rtype == "threshold":
        if not detection.get("count"):
            raise ValueError(f"{source}: rule threshold cần 'count'")
        if not detection.get("window_seconds"):
            raise ValueError(f"{source}: rule threshold cần 'window_seconds'")

    # Biên dịch thử regex ngay bây giờ để lỗi cú pháp lộ ra lúc khởi động.
    for cond in detection.get("conditions") or []:
        if cond.get("op") == "regex":
            for pattern in cond.get("values") or []:
                matching._compiled(str(pattern))


def load_rules(rules_dir: Optional[Path] = None) -> List[Rule]:
    """Nạp mọi rule *.yml. Rule hỏng bị bỏ qua và ghi log, không làm chết app."""
    directory = Path(rules_dir) if rules_dir else RULES_DIR
    rules: List[Rule] = []
    seen_ids = set()

    for path in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
            if not raw:
                continue
            _validate(raw, path.name)
            if raw["id"] in seen_ids:
                logger.warning("Bỏ qua rule trùng id: %s (%s)", raw["id"], path.name)
                continue
            rule = Rule(raw, source=path.name)
            if not rule.enabled:
                logger.info("Rule %s đang tắt (enabled: false)", rule.id)
                continue
            seen_ids.add(rule.id)
            rules.append(rule)
        except Exception as exc:  # noqa: BLE001 — một rule hỏng không được giết engine
            logger.error("Không nạp được rule %s: %s", path.name, exc)

    logger.info("Đã nạp %d rule từ %s", len(rules), directory)
    return rules


class RuleEngine:
    """Đánh giá rule một-event và trả về các rule khớp."""

    def __init__(self, rules: List[Rule]):
        self.single_rules = [r for r in rules if r.type == "single"]
        # Gom rule theo event_type để không phải duyệt toàn bộ ở mỗi event.
        self._by_type: dict = {}
        for rule in self.single_rules:
            self._by_type.setdefault(rule.event_type or "*", []).append(rule)

    def evaluate(self, event: dict) -> List[Rule]:
        etype = event.get("event_type", "")
        candidates = self._by_type.get(etype, []) + self._by_type.get("*", [])
        return [r for r in candidates if matching.matches(event, r.detection)]
