"""Đánh giá điều kiện, dùng chung cho rule engine và correlator.

Port từ PyEDR (`engine/matching.py`), giữ nguyên ngữ nghĩa để 5 rule ATT&CK cũ
chạy được không cần sửa; bổ sung các toán tử `gt`/`lt`/`startswith`/`endswith`
cho các rule mới của lớp 4-6.

Một `detection.conditions` là danh sách dict:

    - field: data.command_line     # đường dẫn có dấu chấm vào trong event
      op: contains_any             # toán tử
      values: ["-enc", "iex"]      # toán hạng (op `exists` không cần)

`logic` (any|all) ghép các điều kiện. Danh sách rỗng khớp mọi event — dùng cho
rule hành vi vốn chỉ ĐẾM số event của một loại.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

# Cache regex đã biên dịch: rule engine chạy trên mọi event, biên dịch lại mỗi
# lần là lãng phí đáng kể khi lưu lượng cao.
_regex_cache: Dict[str, "re.Pattern[str]"] = {}


def _compiled(pattern: str) -> "re.Pattern[str]":
    rx = _regex_cache.get(pattern)
    if rx is None:
        rx = re.compile(pattern, re.IGNORECASE)
        _regex_cache[pattern] = rx
    return rx


def get_field(event: dict, path: str) -> Any:
    """Giải đường dẫn dạng 'data.command_line' trên event."""
    cur: Any = event
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _as_str(value: Any) -> str:
    return "" if value is None else str(value)


def _as_float(value: Any):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def eval_condition(event: dict, cond: dict) -> bool:
    field_val = get_field(event, cond.get("field", ""))
    op = cond.get("op", "contains_any")
    values: List[Any] = cond.get("values", []) or []

    if op == "exists":
        return field_val is not None
    if op == "not_exists":
        return field_val is None

    text = _as_str(field_val).lower()

    if op == "contains_any":
        return any(_as_str(v).lower() in text for v in values)
    if op == "contains_all":
        return all(_as_str(v).lower() in text for v in values)
    if op == "in":
        return text in {_as_str(v).lower() for v in values}
    if op == "not_in":
        return text not in {_as_str(v).lower() for v in values}
    if op == "equals":
        return any(text == _as_str(v).lower() for v in values)
    if op == "startswith":
        return any(text.startswith(_as_str(v).lower()) for v in values)
    if op == "endswith":
        return any(text.endswith(_as_str(v).lower()) for v in values)
    if op == "regex":
        raw = _as_str(field_val)
        return any(_compiled(_as_str(v)).search(raw) for v in values)

    # So sánh số — cho các rule ngưỡng của lớp 2 (entropy, tốc độ ghi...).
    if op in ("gt", "gte", "lt", "lte"):
        left = _as_float(field_val)
        if left is None or not values:
            return False
        right = _as_float(values[0])
        if right is None:
            return False
        if op == "gt":
            return left > right
        if op == "gte":
            return left >= right
        if op == "lt":
            return left < right
        return left <= right

    raise ValueError(f"Toán tử điều kiện không hợp lệ: {op!r}")


def matches(event: dict, detection: dict) -> bool:
    """True nếu event thoả điều kiện phát hiện của rule."""
    conditions = detection.get("conditions") or []
    if not conditions:
        return True  # rule hành vi: khớp mọi event thuộc loại này

    logic = (detection.get("logic") or "any").lower()
    if logic == "all":
        return all(eval_condition(event, c) for c in conditions)
    return any(eval_condition(event, c) for c in conditions)
