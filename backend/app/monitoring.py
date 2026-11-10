"""Expiring worker observations, separate from API dependency health."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .bus import get_redis
from .config import settings

WORKER_TTL_SECONDS = 90


def worker_prefix() -> str:
    return f"{settings.stream_events}:workers:"


def report_worker(consumer: str, pipeline, acknowledged: int, last_batch_at) -> None:
    payload = {
        "consumer": consumer,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "acknowledged_messages": acknowledged,
        "last_batch_at": last_batch_at,
        "detectors": {
            "rules": pipeline.enable_rules,
            "ransomware": pipeline.ransomware is not None,
            "ml_network": pipeline.ml_network is not None,
        },
    }
    get_redis().set(worker_prefix() + consumer, json.dumps(payload), ex=WORKER_TTL_SECONDS)


def worker_overview() -> dict:
    client = get_redis()
    workers = []
    # TTL removes observations after a crash; no heartbeat means unknown, not healthy.
    for key in client.scan_iter(match=worker_prefix() + "*", count=100):
        raw = client.get(key)
        if raw:
            workers.append(json.loads(raw))
    queue = {"length": client.xlen(settings.stream_events), "pending": None, "lag": None}
    # Redis 7 exposes consumer-group lag, which is different from stream length.
    if client.exists(settings.stream_events):
        for group in client.xinfo_groups(settings.stream_events):
            if group["name"] == settings.consumer_group:
                queue.update(pending=group["pending"], lag=group.get("lag"))
                break
    return {
        "status": "observed" if workers else "unknown",
        "heartbeat_ttl_seconds": WORKER_TTL_SECONDS,
        "workers": sorted(workers, key=lambda item: item["consumer"]),
        "queue": queue,
    }
