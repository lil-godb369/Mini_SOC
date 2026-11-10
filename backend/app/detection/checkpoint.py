"""Versioned JSON checkpoints. Never unpickle state from the database."""
from __future__ import annotations

import hashlib
import json
from collections import deque

from .correlator import Correlator
from .ransomware import RansomwareDetector, _FileWrite

VERSION = 1  # Bump when detector state/semantics change incompatibly.


def signature(pipeline) -> str:
    config = {
        "version": VERSION,
        "rules_enabled": pipeline.enable_rules,
        "rules": [vars(rule) for rule in pipeline.rules],
        "ransomware": None if pipeline.ransomware is None else {
            "window": pipeline.ransomware.window_seconds,
            "min_files": pipeline.ransomware.min_files,
            "threshold": pipeline.ransomware.alert_threshold,
        },
    }
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def restore(pipeline, payload: dict, expected_signature: str):
    correlator = Correlator(pipeline.rules)
    previous = pipeline.ransomware
    ransomware = None if previous is None else RansomwareDetector(
        previous.window_seconds, previous.min_files, previous.alert_threshold)
    # Preserve watermark even across configuration changes to avoid accepting older
    # events into a new window. Reset only incompatible detector internals.
    watermark = payload.get("watermark")
    if payload.get("signature") != expected_signature:
        return correlator, ransomware, watermark
    for row in payload.get("rules", []):
        key = tuple(row["key"])
        correlator._state[key] = deque(row["times"])
        if row["cooldown"] is not None:
            correlator._cooldown[key] = row["cooldown"]
    if ransomware is not None:
        for row in payload.get("ransomware", []):
            ransomware._windows[row["key"]] = deque(_FileWrite(**write) for write in row["writes"])
            if row["cooldown"] is not None:
                ransomware._cooldown[row["key"]] = row["cooldown"]
    return correlator, ransomware, watermark


def dump(correlator, ransomware, watermark: float, fingerprint: str) -> dict:
    # Prune by event time, not wall clock: a paused worker can resume a backlog.
    windows = {rule.id: float(rule.detection["window_seconds"]) for rule in correlator.threshold_rules}
    rules = []
    for key, bucket in correlator._state.items():
        window = windows.get(key[0], 0)
        times = [at for at in bucket if watermark - at <= window]
        cooldown = correlator._cooldown.get(key)
        if times or (cooldown is not None and watermark - cooldown <= window):
            rules.append({"key": list(key), "times": times, "cooldown": cooldown})
    ransom = []
    if ransomware is not None:
        for key, bucket in ransomware._windows.items():
            writes = [{name: getattr(write, name) for name in
                       ("at", "entropy", "ext", "directory", "path", "old_path")}
                      for write in bucket if watermark - write.at <= ransomware.window_seconds]
            cooldown = ransomware._cooldown.get(key)
            if writes or (cooldown is not None and watermark - cooldown <= ransomware.window_seconds):
                ransom.append({"key": key, "writes": writes, "cooldown": cooldown})
    return {"signature": fingerprint, "watermark": watermark, "rules": rules, "ransomware": ransom}
