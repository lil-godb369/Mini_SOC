"""Gửi event lên Mini-SOC: đăng ký, gom lô, thử lại.

Thiết kế: bộ thu thập KHÔNG bao giờ gọi mạng trực tiếp. Chúng chỉ đẩy event vào
một hàng đợi trong bộ nhớ, còn một luồng nền lo việc gửi. Nhờ vậy khi server sập
hay mạng chập chờn, việc giám sát tiến trình/file trên máy vẫn chạy bình thường
thay vì bị chặn ở lời gọi HTTP.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from typing import Optional

import requests

logger = logging.getLogger("agent.sender")

# Hàng đợi có giới hạn: nếu server chết lâu, thà bỏ event cũ còn hơn để agent
# ngốn hết RAM của máy đang được bảo vệ.
MAX_QUEUE = 20_000
BATCH_SIZE = 100
FLUSH_INTERVAL = 2.0
MAX_BACKOFF = 60.0


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

        self._queue: "queue.Queue[dict]" = queue.Queue(maxsize=MAX_QUEUE)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._session = requests.Session()
        self._dropped = 0

    # -- Trạng thái lưu trên đĩa -------------------------------------------
    def load_state(self) -> bool:
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            self.api_key = state.get("api_key")
            self.agent_id = state.get("agent_id")
            return bool(self.api_key)
        except (OSError, ValueError):
            return False

    def save_state(self) -> None:
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump({"api_key": self.api_key, "agent_id": self.agent_id}, fh)
        # API key là bí mật: siết quyền về chỉ chủ sở hữu (không tác dụng trên Windows).
        try:
            os.chmod(self.state_path, 0o600)
        except OSError:
            pass

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
            raise RuntimeError(f"Đăng ký thất bại ({resp.status_code}): {resp.text[:200]}")

        body = resp.json()
        self.api_key = body["api_key"]
        self.agent_id = body["agent_id"]
        self.save_state()
        logger.info("Đăng ký thành công, agent_id=%s", self.agent_id)

    # -- Vòng đời ----------------------------------------------------------
    def start(self) -> None:
        if not self.api_key:
            raise RuntimeError("Chưa có API key — cần đăng ký trước")
        self._thread = threading.Thread(target=self._run, name="sender", daemon=True)
        self._thread.start()

    def stop(self, drain_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=drain_timeout)
        if self._dropped:
            logger.warning("Đã bỏ %d event do hàng đợi đầy", self._dropped)

    def send(self, event: dict) -> None:
        """Không chặn. Hàng đợi đầy thì bỏ event và đếm lại để báo cáo."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._dropped += 1
            if self._dropped % 1000 == 1:
                logger.warning("Hàng đợi đầy, đang bỏ event (tổng %d)", self._dropped)

    # -- Luồng nền ---------------------------------------------------------
    def _run(self) -> None:
        backoff = 1.0
        batch: list = []
        last_flush = time.monotonic()

        while not self._stop.is_set() or not self._queue.empty() or batch:
            try:
                timeout = max(0.1, FLUSH_INTERVAL - (time.monotonic() - last_flush))
                batch.append(self._queue.get(timeout=timeout))
            except queue.Empty:
                pass

            due = (
                len(batch) >= BATCH_SIZE
                or (batch and time.monotonic() - last_flush >= FLUSH_INTERVAL)
                or (batch and self._stop.is_set())
            )
            if not due:
                continue

            if self._post(batch):
                batch = []
                backoff = 1.0
                last_flush = time.monotonic()
            else:
                # Lùi dần theo cấp số nhân, giữ nguyên lô để gửi lại.
                time.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
                last_flush = time.monotonic()
                # Lô quá lớn thì cắt bớt phần cũ nhất, tránh phình vô hạn.
                if len(batch) > BATCH_SIZE * 5:
                    dropped = len(batch) - BATCH_SIZE * 5
                    self._dropped += dropped
                    batch = batch[-BATCH_SIZE * 5:]

    def _post(self, batch: list) -> bool:
        try:
            resp = self._session.post(
                f"{self.server_url}/api/v1/ingest",
                json={"events": batch[:500]},
                headers={"X-API-Key": self.api_key},
                timeout=self.timeout,
                verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            logger.warning("Không gửi được: %s", exc)
            return False

        if resp.status_code == 200:
            body = resp.json()
            if body.get("rejected"):
                logger.warning("Server từ chối %d event: %s", body["rejected"], body.get("reasons"))
            return True

        if resp.status_code == 401:
            logger.error("API key bị từ chối — cần đăng ký lại agent")
            return False

        logger.warning("Server trả về %d: %.200s", resp.status_code, resp.text)
        return False
