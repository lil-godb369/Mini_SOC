"""Bộ thu thập telemetry.

Bản tham chiếu này dùng API ở tầng người dùng (psutil, watchdog) nên chạy được
mọi nơi mà không cần biên dịch. Hạn chế đã biết, ghi rõ trong báo cáo:

* Thăm dò tiến trình theo chu kỳ có thể BỎ SÓT tiến trình sống ngắn hơn chu kỳ.
  Agent mức kernel (ETW trên Windows, eBPF trên Linux) không bị vấn đề này.
* watchdog báo đường dẫn file bị thay đổi nhưng KHÔNG cho biết tiến trình nào
  gây ra, nên rule ransomware phải gom theo host thay vì theo PID.

Bù lại hạn chế thứ hai, bộ thu thập file tính sẵn **entropy Shannon** của nội
dung vừa ghi. Dữ liệu đã mã hoá có entropy sát 8.0, còn văn bản/tài liệu thường
dưới 6.5 — đây là tín hiệu chính mà lớp 2 dùng để phân biệt ransomware thật với
việc người dùng chỉ đang giải nén một file zip.
"""
from __future__ import annotations

import logging
import math
import os
import socket
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Callable, Optional

import psutil

logger = logging.getLogger("agent.collectors")

HOSTNAME = socket.gethostname()
PLATFORM = "windows" if psutil.WINDOWS else ("linux" if psutil.LINUX else "macos")

# Chỉ đọc phần đầu file để tính entropy: đủ đại diện, và không làm treo agent
# khi ransomware đụng vào một file vài GB.
ENTROPY_SAMPLE_BYTES = 65_536


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def base_event(event_type: str, data: dict) -> dict:
    return {
        "timestamp": now_iso(),
        "host": HOSTNAME,
        "platform": PLATFORM,
        "event_type": event_type,
        "data": data,
    }


def shannon_entropy(payload: bytes) -> float:
    """Entropy Shannon theo byte, thang 0.0 - 8.0."""
    if not payload:
        return 0.0
    counts = Counter(payload)
    total = len(payload)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _read_head_windows(path: str, size: int) -> Optional[bytes]:
    """Đọc phần đầu file trên Windows mà KHÔNG chặn thao tác của tiến trình khác.

    Đây là bản vá cho một lỗi thật, phát hiện khi chạy demo: `open()` của Python
    trên Windows mở file mà không có cờ FILE_SHARE_DELETE, nên trong lúc agent
    đọc file để tính entropy, mọi lệnh đổi tên hay xoá file đó của tiến trình
    khác đều thất bại với `WinError 32`.

    Hậu quả nếu không vá: agent làm hỏng chính hoạt động bình thường của máy mà
    nó đang bảo vệ. Một EDR gây ra điều đó sẽ bị gỡ bỏ ngay, và đúng ra là vậy.

    Cách vá: gọi thẳng CreateFileW với đủ cả ba cờ chia sẻ, để tiến trình khác
    vẫn ghi/đổi tên/xoá được file trong khi ta đang đọc.
    """
    import ctypes
    import msvcrt
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE

    handle = create_file(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE or not handle:
        return None

    fd = None
    try:
        # open_osfhandle nhận quyền sở hữu handle: đóng fd là đóng luôn handle.
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        return os.read(fd, size)
    except OSError:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        else:
            ctypes.windll.kernel32.CloseHandle(handle)


def file_entropy(path: str) -> Optional[float]:
    """Entropy Shannon của phần đầu file, hoặc None nếu không đọc được.

    Không đọc được là chuyện BÌNH THƯỜNG (file vừa bị xoá, đang bị khoá độc
    quyền, không đủ quyền). Khi đó bộ phát hiện ransomware chỉ đơn giản là mất
    một tín hiệu cho file đó — nó không được phép báo lỗi hay chặn ai cả.
    """
    try:
        if os.name == "nt":
            chunk = _read_head_windows(path, ENTROPY_SAMPLE_BYTES)
            if chunk is None:
                return None
        else:
            # Trên Linux/macOS, mở file để đọc không hề chặn rename hay unlink.
            with open(path, "rb") as fh:
                chunk = fh.read(ENTROPY_SAMPLE_BYTES)
        return round(shannon_entropy(chunk), 3)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Tiến trình
# ---------------------------------------------------------------------------
class ProcessCollector:
    """Phát hiện tiến trình mới bằng cách so sánh tập PID qua từng chu kỳ."""

    FIELDS = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]

    def __init__(self, emit: Callable[[dict], None], poll_interval: float = 0.5):
        self.emit = emit
        self.poll_interval = poll_interval
        self._seen = set(psutil.pids())
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        logger.info("Đang theo dõi tiến trình mới (chu kỳ %.1fs)", self.poll_interval)
        while not self._stop:
            current = set(psutil.pids())
            for pid in current - self._seen:
                try:
                    info = psutil.Process(pid).as_dict(attrs=self.FIELDS)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Tiến trình đã chết trước khi kịp đọc, hoặc thuộc user khác.
                    continue
                self.emit(self._to_event(info))
            # Chỉ giữ PID còn sống: PID được hệ điều hành tái sử dụng, nếu giữ
            # mãi thì lần quay vòng sau sẽ bỏ sót tiến trình mới trùng PID cũ.
            self._seen = current
            time.sleep(self.poll_interval)

    @staticmethod
    def _to_event(info: dict) -> dict:
        cmdline = info.get("cmdline") or []
        return base_event(
            "process_create",
            {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "process_name": info.get("name"),
                "process_path": info.get("exe"),
                "command_line": " ".join(cmdline),
                "user": info.get("username"),
            },
        )


# ---------------------------------------------------------------------------
# File
# ---------------------------------------------------------------------------
class FileCollector:
    """Theo dõi một cây thư mục và phát event khi file bị tạo/sửa/đổi tên."""

    def __init__(
        self,
        emit: Callable[[dict], None],
        watch_dir: str,
        compute_entropy: bool = True,
    ):
        self.emit = emit
        self.watch_dir = watch_dir
        self.compute_entropy = compute_entropy
        self._observer = None

    def start(self) -> bool:
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            logger.warning("Chưa cài watchdog — tắt giám sát file")
            return False

        os.makedirs(self.watch_dir, exist_ok=True)
        collector = self

        class _Handler(FileSystemEventHandler):
            def _emit(self, path: str, event_type: str, old_path: str = None) -> None:
                data = {"file_path": path}
                if old_path:
                    # Đổi tên KHÔNG tạo ra file mới. Gửi kèm đường dẫn cũ để lớp
                    # 2 biết hai đường dẫn này là cùng một file, thay vì đếm
                    # thành hai. Với ransomware — vốn đổi đuôi hàng loạt — nhầm
                    # lẫn này làm hỏng mọi tín hiệu dạng tỉ lệ.
                    data["old_file_path"] = old_path
                try:
                    data["file_size"] = os.path.getsize(path)
                except OSError:
                    pass
                if collector.compute_entropy:
                    entropy = file_entropy(path)
                    if entropy is not None:
                        data["entropy"] = entropy
                collector.emit(base_event(event_type, data))

            def on_created(self, event):
                if not event.is_directory:
                    self._emit(event.src_path, "file_create")

            def on_modified(self, event):
                if not event.is_directory:
                    self._emit(event.src_path, "file_modify")

            def on_moved(self, event):
                # Ransomware đổi đuôi file -> watchdog báo đây là "moved".
                if not event.is_directory:
                    self._emit(event.dest_path, "file_modify", old_path=event.src_path)

        self._observer = Observer()
        self._observer.schedule(_Handler(), self.watch_dir, recursive=True)
        self._observer.start()
        logger.info("Đang giám sát thư mục: %s", os.path.abspath(self.watch_dir))
        return True

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)


# ---------------------------------------------------------------------------
# Kết nối mạng
# ---------------------------------------------------------------------------
class NetworkCollector:
    """Phát event khi có kết nối TCP ra ngoài mới được thiết lập.

    Đây là nguồn cho kỹ thuật T1071 (giao thức tầng ứng dụng) và là bước đệm
    tới đặc trưng luồng đầy đủ mà mô hình ML của lớp 2 sẽ dùng.
    """

    PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "::1", "fe80:")

    def __init__(self, emit: Callable[[dict], None], poll_interval: float = 2.0):
        self.emit = emit
        self.poll_interval = poll_interval
        self._seen = set()
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def _is_external(self, ip: str) -> bool:
        if ip.startswith(self.PRIVATE_PREFIXES):
            return False
        # Dải 172.16.0.0/12 phải kiểm tra riêng vì không cắt được bằng tiền tố chuỗi.
        if ip.startswith("172."):
            try:
                return not (16 <= int(ip.split(".")[1]) <= 31)
            except (IndexError, ValueError):
                return True
        return True

    def run(self) -> None:
        logger.info("Đang theo dõi kết nối mạng ra ngoài")
        while not self._stop:
            try:
                connections = psutil.net_connections(kind="tcp")
            except (psutil.AccessDenied, PermissionError):
                logger.warning("Không đủ quyền đọc bảng kết nối — tắt giám sát mạng")
                return

            current = set()
            for conn in connections:
                if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                    continue
                if not self._is_external(conn.raddr.ip):
                    continue

                key = (conn.pid, conn.raddr.ip, conn.raddr.port)
                current.add(key)
                if key in self._seen:
                    continue

                name = None
                if conn.pid:
                    try:
                        name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                self.emit(
                    base_event(
                        "network_connect",
                        {
                            "pid": conn.pid,
                            "process_name": name,
                            "remote_ip": conn.raddr.ip,
                            "remote_port": conn.raddr.port,
                            "local_port": conn.laddr.port if conn.laddr else None,
                            "protocol": "tcp",
                        },
                    )
                )

            self._seen = current
            time.sleep(self.poll_interval)
