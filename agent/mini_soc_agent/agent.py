"""Điểm khởi động của agent.

    # Lần đầu: đăng ký rồi chạy
    python -m mini_soc_agent.agent --server http://127.0.0.1:8000 \
        --enroll-token <TOKEN> --watch-dir ./sandbox

    # Các lần sau: API key đã lưu, chỉ cần
    python -m mini_soc_agent.agent --server http://127.0.0.1:8000 --watch-dir ./sandbox
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from typing import List

from . import __version__
from .collectors import (
    HOSTNAME,
    PLATFORM,
    FileCollector,
    NetworkCollector,
    ProcessCollector,
)
from .sender import EventSender, default_state_path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [agent] %(message)s",
)
logger = logging.getLogger("agent")

_shutdown = threading.Event()


def _handle_signal(signum, _frame):
    logger.info("Nhận tín hiệu %s, đang dừng...", signum)
    _shutdown.set()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mini-soc-agent",
        description="Agent thu thập telemetry của Mini-SOC (lớp 1)",
    )
    parser.add_argument("--server", default=os.environ.get("MINISOC_SERVER", "http://127.0.0.1:8000"),
                        help="URL của Mini-SOC API")
    parser.add_argument("--enroll-token", default=os.environ.get("MINISOC_ENROLL_TOKEN"),
                        help="Token đăng ký (chỉ cần ở lần chạy đầu tiên)")
    parser.add_argument("--state-file", default=default_state_path(),
                        help="Nơi lưu API key sau khi đăng ký")
    parser.add_argument("--watch-dir", default=None,
                        help="Thư mục cần giám sát thay đổi file (demo T1486)")
    parser.add_argument("--poll-interval", type=float, default=0.5,
                        help="Chu kỳ quét tiến trình, tính bằng giây")
    parser.add_argument("--no-network", action="store_true",
                        help="Tắt giám sát kết nối mạng")
    parser.add_argument("--no-entropy", action="store_true",
                        help="Không tính entropy khi có thay đổi file")
    parser.add_argument("--insecure", action="store_true",
                        help="Bỏ qua kiểm tra chứng chỉ TLS (chỉ dùng trong lab)")
    return parser


def main(argv: List[str] = None) -> int:
    args = build_parser().parse_args(argv)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info("Mini-SOC agent v%s | host=%s | platform=%s", __version__, HOSTNAME, PLATFORM)

    sender = EventSender(
        server_url=args.server,
        state_path=args.state_file,
        verify_tls=not args.insecure,
    )

    # Đăng ký một lần duy nhất; những lần chạy sau dùng lại API key đã lưu.
    if not sender.load_state():
        if not args.enroll_token:
            logger.error(
                "Chưa đăng ký và không có --enroll-token. "
                "Lấy token trong .env (AGENT_ENROLL_TOKEN) rồi chạy lại."
            )
            return 2
        try:
            sender.enroll(args.enroll_token, HOSTNAME, PLATFORM, __version__)
        except Exception as exc:  # noqa: BLE001
            logger.error("Đăng ký thất bại: %s", exc)
            return 3
    else:
        logger.info("Dùng lại API key đã lưu (agent_id=%s)", sender.agent_id)

    sender.start()

    threads: List[threading.Thread] = []
    stoppables: List[object] = []

    process_collector = ProcessCollector(sender.send, poll_interval=args.poll_interval)
    stoppables.append(process_collector)
    threads.append(threading.Thread(target=process_collector.run, name="process", daemon=True))

    if not args.no_network:
        network_collector = NetworkCollector(sender.send)
        stoppables.append(network_collector)
        threads.append(threading.Thread(target=network_collector.run, name="network", daemon=True))

    file_collector = None
    if args.watch_dir:
        file_collector = FileCollector(
            sender.send, args.watch_dir, compute_entropy=not args.no_entropy
        )
        file_collector.start()

    for thread in threads:
        thread.start()

    logger.info("Agent đang chạy. Nhấn Ctrl+C để dừng.")
    try:
        while not _shutdown.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    logger.info("Đang dừng các bộ thu thập...")
    for item in stoppables:
        item.stop()
    if file_collector:
        file_collector.stop()
    # Dừng sender sau cùng để những event vừa thu vẫn kịp gửi đi.
    sender.stop()
    logger.info("Agent đã dừng.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
