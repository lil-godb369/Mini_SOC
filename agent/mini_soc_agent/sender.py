"""Gửi event lên Mini-SOC: đăng ký, gom lô, thử lại.

Thiết kế: bộ thu thập KHÔNG bao giờ gọi mạng trực tiếp. Chúng chỉ đẩy event vào
một hàng đợi SQLite bền trên đĩa, còn một luồng nền lo việc gửi. Nhờ vậy khi server sập
hay mạng chập chờn, việc giám sát tiến trình/file trên máy vẫn chạy bình thường
thay vì bị chặn ở lời gọi HTTP.
"""
from __future__ import annotations

import json
import logging
import os
import hashlib
import threading
import time
import tempfile
from typing import Optional

import requests

from .spool import DiskSpool

logger = logging.getLogger("agent.sender")

# Disk capacity is bounded; when full, preserve old rows and count new drops.
MAX_QUEUE = 20_000
BATCH_SIZE = 100
FLUSH_INTERVAL = 2.0
MAX_BACKOFF = 60.0
HEARTBEAT_INTERVAL = 60.0


def default_state_path() -> str:
    """Nơi lưu API key sau khi đăng ký."""
    base = os.environ.get("PROGRAMDATA") or os.path.expanduser("~")
    return os.path.join(base, ".mini-soc", "agent.json")


class EventSender:
    def __init__(
        self,
        server_url: str,
        state_path: Optional[str] = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ):
        self.server_url = server_url.rstrip("/")
        self.state_path = state_path or default_state_path()
        self.verify_tls = verify_tls
        self.timeout = timeout

        self.api_key: Optional[str] = None
        self.agent_id: Optional[int] = None

        self._spool: Optional[DiskSpool] = None
        self._spool_lock = threading.Lock()
        self._wake = threading.Event()
        self.storage_failed = threading.Event()
        self._rejected_indices = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._session = requests.Session()
        self._dropped = 0
        self.auth_failed = threading.Event()
        self._last_heartbeat = float("-inf")

    # -- Trạng thái lưu trên đĩa -------------------------------------------
    def load_state(self) -> bool:
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            if not isinstance(state, dict):
                return False
            if state.get("server_url") and state["server_url"] != self.server_url:
                logger.error("State belongs to another server; use a separate --state-file")
                raise RuntimeError("Agent state server mismatch")
            self.api_key = state.get("api_key")
            self.agent_id = state.get("agent_id")
            return bool(self.api_key)
        except (OSError, ValueError):
            return False

    def save_state(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.state_path))
        os.makedirs(directory, exist_ok=True)
        # Replace only a complete file: interrupted writes must preserve the old key.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory,
                                             prefix=".agent-", delete=False) as fh:
                temporary = fh.name
                json.dump({"api_key": self.api_key, "agent_id": self.agent_id,
                           "server_url": self.server_url}, fh)
                fh.flush()
                os.fsync(fh.fileno())
            # Windows ACL hardening is a separate deployment task.
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.state_path)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    # -- Đăng ký -----------------------------------------------------------
    def enroll(self, enroll_token: str, hostname: str, platform: str, version: str) -> None:
        """Đổi token enroll dùng chung lấy API key riêng của máy này."""
        resp = self._session.post(
            f"{self.server_url}/api/v1/agents/enroll",
            json={
                "enroll_token": enroll_token,
                "hostname": hostname,
                "platform": platform,
                "version": version,
            },
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        if resp.status_code != 201:
            raise RuntimeError(f"Đăng ký thất bại (HTTP {resp.status_code})")

        body = resp.json()
        self.api_key = body["api_key"]
        self.agent_id = body["agent_id"]
        self.save_state()
        logger.info("Đăng ký thành công, agent_id=%s", self.agent_id)

    # -- Vòng đời ----------------------------------------------------------
    @property
    def spool(self) -> DiskSpool:
        with self._spool_lock:
            if self._spool is None:
                self._spool = DiskSpool(self.state_path + ".spool.sqlite3")
            return self._spool

    @property
    def scope(self) -> str:
        # Never replay another server/key's queued telemetry after reenrollment.
        return hashlib.sha256((self.server_url + "\n" + str(self.api_key)).encode()).hexdigest()

    def start(self) -> None:
        if not self.api_key:
            raise RuntimeError("Chưa có API key — cần đăng ký trước")
        self.spool  # Fail before collectors start if local storage is unavailable.
        self._thread = threading.Thread(target=self._run, name="sender", daemon=True)
        self._thread.start()

    def stop(self, drain_timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=drain_timeout)
        if self._spool is not None:
            try:
                logger.info("Spool status: %s", self.spool.stats(self.scope))
            except Exception:
                self.storage_failed.set()
                logger.error("Cannot read spool status during shutdown")

    def send(self, event: dict) -> bool:
        """Commit locally before returning; network I/O stays on the sender thread."""
        try:
            accepted = self.spool.append(self.scope, event)
            if not accepted:
                self._dropped += 1
                if self._dropped % 1000 == 1:
                    logger.warning("Spool limit reached; dropped event count=%d", self._dropped)
            self._wake.set()
            return accepted
        except Exception:
            self.storage_failed.set()
            logger.error("Cannot persist telemetry; agent stopping")
            return False

    # -- Luồng nền ---------------------------------------------------------
    def _heartbeat(self) -> bool:
        try:
            resp = self._session.post(
                f"{self.server_url}/api/v1/agents/heartbeat",
                headers={"X-API-Key": self.api_key},
                timeout=self.timeout, verify=self.verify_tls,
            )
        except requests.RequestException:
            logger.warning("Heartbeat failed: server unreachable")
            return False
        if resp.status_code == 401:
            self._reject_key()
        return resp.status_code == 200

    def _reject_key(self) -> None:
        self.auth_failed.set()
        logger.error("API key rejected; agent stopping. Check revocation or use "
                     "--reenroll with an enrollment token after a database reset.")

    def _run(self) -> None:
        try:
            self._run_loop()
        except Exception:
            self.storage_failed.set()
            logger.error("Sender failed; unsent committed events remain on disk")

    def _run_loop(self) -> None:
        backoff = 1.0
        while True:
            if self.auth_failed.is_set() or self.storage_failed.is_set():
                return
            if not self._stop.is_set() and time.monotonic() - self._last_heartbeat >= HEARTBEAT_INTERVAL:
                self._last_heartbeat = time.monotonic()
                self._heartbeat()
                if self.auth_failed.is_set():
                    return
            self._wake.clear()
            rows = self.spool.batch(self.scope, BATCH_SIZE)
            if not rows:
                if self._stop.is_set():
                    return
                self._wake.wait(FLUSH_INTERVAL)
                continue
            if self._post([event for _, event in rows]):
                self.spool.complete(rows, self._rejected_indices)
                backoff = 1.0
            else:
                # Lùi dần theo cấp số nhân, giữ nguyên lô để gửi lại.
                if self.auth_failed.is_set() or self._stop.wait(backoff):
                    return
                backoff = min(backoff * 2, MAX_BACKOFF)

    def _post(self, batch: list) -> bool:
        try:
            resp = self._session.post(
                f"{self.server_url}/api/v1/ingest",
                json={"events": batch[:500]},
                headers={"X-API-Key": self.api_key},
                timeout=self.timeout,
                verify=self.verify_tls,
            )
        except requests.RequestException:
            logger.warning("Cannot send telemetry: connection failed")
            return False

        if resp.status_code == 200:
            try:
                body = resp.json()
                rejected = body.get("rejected")
                indices = body.get("rejected_indices", [])
                if (type(rejected) is not int or type(body.get("accepted")) is not int
                    or rejected < 0 or body["accepted"] < 0
                    or body["accepted"] + rejected != len(batch)
                    or not isinstance(indices, list)
                    or any(type(i) is not int or i < 0 or i >= len(batch) for i in indices)
                    or len(set(indices)) != rejected or len(indices) != rejected):
                    raise ValueError("Invalid acknowledgement")
            except (ValueError, AttributeError, TypeError):
                logger.warning("Invalid ingest acknowledgement; preserving spool batch")
                return False
            self._rejected_indices = indices
            if rejected:
                logger.warning("Server rejected %d events; quarantining locally", rejected)
            return True

        if resp.status_code == 401:
            self._reject_key()
            return False

        logger.warning("Ingest returned HTTP %d; preserving spool batch", resp.status_code)
        return False
