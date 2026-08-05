"""Mô phỏng T1486 — Mã hoá dữ liệu để gây thiệt hại (CHỈ TRONG SANDBOX).

Kịch bản KHÔNG BAO GIỜ đụng tới thứ gì ngoài thư mục sandbox. Nó:
  1. tạo thư mục sandbox và đổ vào đó vài file giả (nếu đang trống),
  2. "mã hoá" từng file bằng XOR đảo ngược được rồi đổi đuôi thành .locked,
  3. hoàn tác toàn bộ với --restore.

Cụm sửa đổi file dồn dập chính là thứ làm rule T1486 của engine kích hoạt (agent
phải được chạy với --watch-dir trỏ vào đúng thư mục sandbox này).

    python ransomware_sim.py                 # mã hoá sandbox
    python ransomware_sim.py --restore       # hoàn tác
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import time

# Repo root = thư mục cha của attack_sim/. Neo sandbox vào đây để chạy từ bất kỳ
# thư mục nào cũng ra cùng một chỗ.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SANDBOX = os.path.join(REPO_ROOT, "sandbox")

LOCKED_EXT = ".locked"

# Hạt giống cố định -> dòng khoá tái tạo được -> luôn khôi phục được file.
KEY_SEED = 20260805
KEYSTREAM_SIZE = 65_536

# --- Vì sao dùng DÒNG KHOÁ chứ không phải XOR với một byte hằng số ---
#
# Bản đầu tiên của kịch bản này XOR mọi byte với hằng số 0x5A. Khi chạy demo
# thật, các file "đã mã hoá" đo được entropy chỉ 4.05 — y hệt văn bản gốc. Lý
# do: XOR với một hằng số chỉ là phép HOÁN VỊ bảng byte, nó không thêm chút bất
# định nào, nên entropy không hề thay đổi.
#
# Hậu quả: bộ phát hiện hành vi (vốn dựa chủ yếu vào entropy) im lặng — và nó
# im lặng ĐÚNG, vì dữ liệu đó thật sự không trông giống dữ liệu đã mã hoá. Nói
# cách khác, kịch bản mô phỏng đã không tái tạo được chính tính chất mà nó cần
# kiểm chứng, và như vậy nó không chứng minh được điều gì.
#
# Dòng khoá giả ngẫu nhiên cho ra entropy ~8.0, đúng như AES của ransomware
# thật, mà vẫn đảo ngược được hoàn toàn (XOR là phép nghịch đảo của chính nó
# khi dùng lại cùng dòng khoá).
# Bộ sinh phải được tạo MỘT LẦN, bên ngoài vòng lặp. Nếu viết
# `random.Random(KEY_SEED).getrandbits(8)` ngay trong biểu thức lặp thì mỗi vòng
# lại dựng một bộ sinh mới với cùng hạt giống, và trả về đúng một byte lặp lại
# 65536 lần — tức là quay về đúng XOR hằng số mà ta đang muốn loại bỏ.
_rng = random.Random(KEY_SEED)
_KEYSTREAM = bytes(_rng.getrandbits(8) for _ in range(KEYSTREAM_SIZE))


def xor_bytes(data: bytes) -> bytes:
    """XOR với dòng khoá tuần hoàn. Gọi hai lần thì ra lại dữ liệu gốc."""
    keystream = _KEYSTREAM
    size = len(keystream)
    return bytes(byte ^ keystream[i % size] for i, byte in enumerate(data))


def assert_safe(sandbox: str) -> None:
    """Chốt chặn an toàn: sandbox BẮT BUỘC nằm trong repo.

    Đây không phải sự cẩn thận thừa. Một lỗi gõ nhầm đường dẫn (`--sandbox C:\\`)
    sẽ biến kịch bản demo thành sự cố thật. Vì kịch bản này tồn tại để ghi đè
    file hàng loạt, nó phải tự chứng minh mình không thể thoát khỏi sandbox.
    """
    resolved = os.path.abspath(sandbox)
    root = os.path.abspath(REPO_ROOT)

    refusal = SystemExit(
        f"TỪ CHỐI: sandbox {resolved!r} nằm ngoài repo {root!r}. "
        "Kịch bản này chỉ được phép ghi trong thư mục dự án."
    )
    try:
        inside = os.path.commonpath([resolved, root]) == root
    except ValueError:
        # Trên Windows, commonpath ném ValueError khi hai đường dẫn ở khác ổ đĩa
        # (ví dụ C:\ và D:\). Khác ổ đĩa thì chắc chắn nằm ngoài repo -> từ chối.
        raise refusal
    if not inside:
        raise refusal
    if resolved == root:
        raise SystemExit("TỪ CHỐI: sandbox không được là chính thư mục gốc của repo.")


def ensure_dummy_files(sandbox: str, n: int = 20) -> None:
    os.makedirs(sandbox, exist_ok=True)
    existing = [f for f in os.listdir(sandbox) if not f.endswith(LOCKED_EXT)]
    if existing:
        return
    print(f"[sim] tạo {n} file giả trong {sandbox}")
    for i in range(n):
        path = os.path.join(sandbox, f"tai_lieu_{i:02d}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            # ~4KB mỗi file, cỡ một tài liệu văn phòng thật. Cỡ file quan trọng:
            # entropy đo trên mẫu quá nhỏ luôn thấp hơn giá trị thật (350 byte
            # ngẫu nhiên chỉ đạt ~7.3/8.0), nên file quá bé sẽ làm phép đo entropy
            # mất độ tin cậy ngay cả khi dữ liệu đã thật sự được mã hoá.
            fh.write(f"Tai lieu kinh doanh quan trong #{i}\n" * 120)


def encrypt(sandbox: str, delay: float) -> int:
    ensure_dummy_files(sandbox)
    targets = [
        f for f in os.listdir(sandbox)
        if not f.endswith(LOCKED_EXT) and os.path.isfile(os.path.join(sandbox, f))
    ]
    print(f"[sim] T1486 — đang mã hoá {len(targets)} file trong sandbox...")

    for name in targets:
        path = os.path.join(sandbox, name)
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path, "wb") as fh:
            fh.write(xor_bytes(data))
        os.rename(path, path + LOCKED_EXT)
        # Đủ nhanh để thành một "cụm" theo rule, nhưng vẫn quan sát được khi demo.
        time.sleep(delay)

    print(f"[sim] xong, {len(targets)} file. Mong đợi cảnh báo ransomware T1486 (critical).")
    return len(targets)


def restore(sandbox: str) -> int:
    if not os.path.isdir(sandbox):
        print(f"[sim] không có sandbox tại {sandbox}, không cần hoàn tác.")
        return 0

    locked = [f for f in os.listdir(sandbox) if f.endswith(LOCKED_EXT)]
    print(f"[sim] đang khôi phục {len(locked)} file...")
    for name in locked:
        path = os.path.join(sandbox, name)
        with open(path, "rb") as fh:
            data = fh.read()
        original = path[: -len(LOCKED_EXT)]
        with open(original, "wb") as fh:
            fh.write(xor_bytes(data))  # XOR là phép nghịch đảo của chính nó
        os.remove(path)
    print("[sim] khôi phục hoàn tất.")
    return len(locked)


def main() -> int:
    parser = argparse.ArgumentParser(description="Mô phỏng ransomware T1486 (an toàn)")
    parser.add_argument("--restore", action="store_true", help="hoàn tác việc mã hoá")
    parser.add_argument("--sandbox", default=DEFAULT_SANDBOX,
                        help="thư mục sandbox (bắt buộc nằm trong repo)")
    parser.add_argument("--delay", type=float, default=0.05,
                        help="giãn cách giữa các file, tính bằng giây")
    args = parser.parse_args()

    assert_safe(args.sandbox)

    if args.restore:
        restore(args.sandbox)
    else:
        count = encrypt(args.sandbox, args.delay)
        if count < 12:
            print("[sim] CẢNH BÁO: dưới 12 file — rule T1486 (ngưỡng 12) có thể không kích hoạt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
