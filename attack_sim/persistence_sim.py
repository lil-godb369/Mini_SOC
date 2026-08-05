"""Mô phỏng T1547.001 — Duy trì truy cập qua tự khởi động (mặc định CHẠY KHÔ).

Mặc định, kịch bản chỉ IN RA lệnh tạo mục tự khởi động. Điều đó vẫn đủ để rule
kích hoạt, vì agent nhìn thấy tiến trình `reg.exe` được sinh ra với dòng lệnh
khớp mẫu — mà không thay đổi Run key hay crontab của bạn.

    python persistence_sim.py               # an toàn, chỉ in
    python persistence_sim.py --for-real     # ghi thật (có kèm lệnh gỡ)
"""
from __future__ import annotations

import argparse
import platform
import subprocess
import sys

VALUE_NAME = "MiniSOC_Demo"
RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"


def windows_commands():
    create = ["reg", "add", RUN_KEY, "/v", VALUE_NAME, "/t", "REG_SZ", "/d", "calc.exe", "/f"]
    undo = ["reg", "delete", RUN_KEY, "/v", VALUE_NAME, "/f"]
    return create, undo


def linux_commands():
    create = ["bash", "-c", f"echo '# {VALUE_NAME} demo' >> ~/.bashrc"]
    undo = ["bash", "-c", f"sed -i '/# {VALUE_NAME} demo/d' ~/.bashrc"]
    return create, undo


def main() -> int:
    parser = argparse.ArgumentParser(description="Mô phỏng duy trì truy cập T1547.001")
    parser.add_argument("--for-real", action="store_true",
                        help="thật sự tạo mục tự khởi động (có thể hoàn tác)")
    args = parser.parse_args()

    is_windows = platform.system() == "Windows"
    create, undo = windows_commands() if is_windows else linux_commands()

    print("[sim] T1547.001 Duy trì truy cập qua tự khởi động")
    print(f"[sim] lệnh: {' '.join(create)}")

    if args.for_real:
        result = subprocess.run(create, capture_output=True)
        if result.returncode == 0:
            print("[sim] ĐÃ TẠO mục tự khởi động.")
            print(f"[sim] gỡ bằng: {' '.join(undo)}")
        else:
            print(f"[sim] tạo thất bại: {result.stderr.decode(errors='replace')[:200]}")
            return 1
    else:
        # Ngay cả lần chạy khô cũng sinh ra reg.exe với dòng lệnh khớp rule
        # (nhờ `reg add /?`), nên phát hiện vẫn kích hoạt mà không đổi gì cả.
        if is_windows:
            subprocess.run(["reg", "add", "/?"], capture_output=True)
        else:
            subprocess.run(["bash", "-c", "echo 'crontab -l  # demo, khong ghi gi'"],
                           capture_output=True)
        print("[sim] CHẠY KHÔ — không có gì bị thay đổi. Dùng --for-real để ghi thật.")

    print("[sim] Mong đợi: cảnh báo Persistence (high).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
