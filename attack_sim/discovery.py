"""Mô phỏng T1057 / T1082 — Do thám hệ thống, kèm T1059.001 PowerShell.

Chạy một cụm lệnh trinh sát vô hại từ cùng một tiến trình cha, để rule tương
quan "cụm do thám" của engine kích hoạt. Toàn bộ là lệnh CHỈ ĐỌC, không đụng
vào bất cứ thứ gì trên máy.

    python discovery.py
"""
from __future__ import annotations

import platform
import subprocess
import sys
import time

WINDOWS_COMMANDS = [
    ["whoami"],
    ["hostname"],
    ["ipconfig", "/all"],
    ["net", "user"],
    ["systeminfo"],
    ["tasklist"],
]

LINUX_COMMANDS = [
    ["whoami"],
    ["hostname"],
    ["id"],
    ["uname", "-a"],
    ["ps", "aux"],
    ["netstat", "-tunlp"],
]

# base64 của chuỗi 'hi' ở dạng UTF-16LE mà PowerShell -enc yêu cầu.
ENCODED_POWERSHELL = ["powershell", "-nop", "-w", "hidden", "-enc", "aABpAA=="]


def run_burst(commands) -> int:
    """Phóng các lệnh do thám ĐỒNG THỜI, rồi mới chờ tất cả kết thúc.

    Bản đầu chạy tuần tự và chờ từng lệnh xong mới sang lệnh kế. Khi chạy demo
    thật, agent chỉ bắt được 2 trên 6 tiến trình: `whoami`, `hostname`,
    `ipconfig`, `net` sống dưới 100ms, nên chúng lọt qua khe giữa hai lần quét
    của bộ thu thập (chu kỳ 0.25-0.5 giây). Rule cần 4 tiến trình mới kích hoạt,
    nên cụm do thám không bao giờ bị phát hiện.

    Phóng đồng thời khiến cả 6 tiến trình cùng tồn tại trong một khoảnh khắc,
    nên một lần quét bắt được nhiều tiến trình cùng lúc. Đây cũng SÁT THỰC TẾ
    hơn: mã do thám của kẻ tấn công thường phóng song song để rút ngắn thời gian
    hiện diện, chứ không xếp hàng đợi từng lệnh.

    Lưu ý: cách này giảm nhẹ chứ KHÔNG xoá bỏ hạn chế gốc của việc thăm dò theo
    chu kỳ. Chỉ agent mức kernel (ETW trên Windows, eBPF trên Linux) mới bảo đảm
    không bỏ sót tiến trình sống ngắn.
    """
    processes = []
    for cmd in commands:
        try:
            processes.append(
                (cmd, subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL))
            )
        except (FileNotFoundError, OSError):
            print(f"[sim]   bỏ qua (không có sẵn): {' '.join(cmd)}")
        time.sleep(0.05)   # so le một chút để tránh dồn cục ở tầng lập lịch

    executed = 0
    for cmd, proc in processes:
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        print(f"[sim]   đã chạy: {' '.join(cmd)}")
        executed += 1

    return executed


def main() -> int:
    is_windows = platform.system() == "Windows"
    print("[sim] T1057/T1082 Do thám — chạy một cụm lệnh trinh sát")

    executed = run_burst(WINDOWS_COMMANDS if is_windows else LINUX_COMMANDS)

    if is_windows:
        try:
            subprocess.run(ENCODED_POWERSHELL, capture_output=True, timeout=20)
            print("[sim]   đã chạy: PowerShell mã hoá (T1059.001)")
            executed += 1
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    print(f"[sim] xong, {executed} lệnh đã chạy.")
    print("[sim] Mong đợi: cảnh báo Discovery (medium), có thể kèm PowerShell (high).")

    if executed < 4:
        print("[sim] CẢNH BÁO: dưới 4 lệnh chạy được — rule ngưỡng có thể không kích hoạt.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
