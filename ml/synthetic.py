"""Sinh bộ dữ liệu tổng hợp có HÌNH DẠNG giống CIC-IDS2017.

Mục đích: đường ống tiền xử lý + huấn luyện phải chạy và kiểm thử được NGAY, kể
cả khi chưa tải xong bộ dữ liệu thật 2.8 GB. Nhờ vậy lỗi trong code lộ ra ngay
bây giờ, chứ không phải sau nửa ngày chờ tải về.

Dữ liệu sinh ra cố tình mang đủ những chỗ BẨN của bộ thật, vì đó chính là những
chỗ code làm sạch phải xử lý:

* tên cột có khoảng trắng thừa ở đầu (`' Flow Duration'`)
* cột trùng tên `Fwd Header Length` / `Fwd Header Length.1`
* giá trị `inf` trong `Flow Bytes/s` khi thời lượng luồng bằng 0
* nhãn hỏng encoding: `'Web Attack \\x96 Brute Force'` (byte 0x96 của latin-1)
* các cột hằng số toàn 0
* mất cân bằng lớp nghiêm trọng, kèm vài lớp cực hiếm

⚠️ Số liệu chạy trên dữ liệu tổng hợp KHÔNG được đưa vào báo cáo như kết quả
thực nghiệm. Nó chỉ dùng để kiểm thử đường ống. Kết quả thật phải chạy trên
CIC-IDS2017 gốc.

    python synthetic.py --out data/raw_synthetic --rows-per-day 20000
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Tên cột giữ nguyên khoảng trắng thừa như trong CSV gốc.
FEATURE_COLUMNS = [
    " Destination Port", " Flow Duration", " Total Fwd Packets",
    " Total Backward Packets", "Total Length of Fwd Packets",
    " Total Length of Bwd Packets", " Fwd Packet Length Max",
    " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std",
    "Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean",
    " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s",
    " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max", " Flow IAT Min",
    "Fwd IAT Total", " Fwd IAT Mean", " Fwd Header Length", " Bwd Header Length",
    "Fwd Packets/s", " Bwd Packets/s", " Min Packet Length", " Max Packet Length",
    " Packet Length Mean", " Packet Length Std", "FIN Flag Count",
    " SYN Flag Count", " PSH Flag Count", " ACK Flag Count", " Average Packet Size",
]

# Cột hằng số — trong bộ thật cũng toàn 0 ở mọi dòng.
CONSTANT_COLUMNS = [" Bwd PSH Flags", " Fwd URG Flags", " Bwd URG Flags", " CWE Flag Count"]

# Ánh xạ tệp -> (ngày, các nhãn tấn công, tỉ lệ tấn công).
# Bám sát bố cục thật của CIC-IDS2017.
DAY_PLAN: Dict[str, Tuple[str, List[str], float]] = {
    "Monday-WorkingHours.pcap_ISCX.csv": ("monday", [], 0.0),
    "Tuesday-WorkingHours.pcap_ISCX.csv": ("tuesday", ["FTP-Patator", "SSH-Patator"], 0.08),
    "Wednesday-workingHours.pcap_ISCX.csv": (
        "wednesday",
        ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "Heartbleed"],
        0.36,
    ),
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": (
        "thursday",
        # Nhãn hỏng encoding y như bộ thật: 0x96 là gạch ngang trong latin-1.
        ["Web Attack \x96 Brute Force", "Web Attack \x96 XSS", "Web Attack \x96 Sql Injection"],
        0.015,
    ),
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": (
        "thursday", ["Infiltration"], 0.0005,
    ),
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": ("friday", ["Bot"], 0.01),
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": ("friday", ["PortScan"], 0.55),
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": ("friday", ["DDoS"], 0.56),
}

# Lớp cực hiếm — trong bộ thật Heartbleed chỉ có 11 dòng trên toàn bộ 2.8 triệu.
RARE_LABELS = {"Heartbleed": 11, "Infiltration": 36}

BENIGN_PORTS = [80, 443, 53, 22, 445, 3389, 8080, 993, 587]


def _benign(rng: np.random.Generator, n: int) -> Dict[str, np.ndarray]:
    """Lưu lượng nền: phiên vừa phải, hai chiều cân đối."""
    duration = rng.lognormal(mean=11.0, sigma=2.2, size=n)
    fwd_pkts = rng.lognormal(mean=1.6, sigma=1.0, size=n).round() + 1
    bwd_pkts = rng.lognormal(mean=1.5, sigma=1.0, size=n).round() + 1
    fwd_len = fwd_pkts * rng.uniform(60, 900, n)
    bwd_len = bwd_pkts * rng.uniform(60, 1300, n)
    return {
        " Destination Port": rng.choice(BENIGN_PORTS, n),
        " Flow Duration": duration,
        " Total Fwd Packets": fwd_pkts,
        " Total Backward Packets": bwd_pkts,
        "Total Length of Fwd Packets": fwd_len,
        " Total Length of Bwd Packets": bwd_len,
        " SYN Flag Count": rng.integers(0, 2, n),
        " PSH Flag Count": rng.integers(0, 3, n),
        " ACK Flag Count": rng.integers(1, 5, n),
        "FIN Flag Count": rng.integers(0, 2, n),
    }


def _attack(rng: np.random.Generator, n: int, kind: str) -> Dict[str, np.ndarray]:
    """Mỗi họ tấn công có một chữ ký thống kê riêng — đó là thứ mô hình phải học."""
    if "PortScan" in kind:
        # Rất nhiều luồng cực ngắn, gần như không có chiều về.
        duration = rng.exponential(scale=120, size=n)
        fwd_pkts = np.ones(n) + rng.integers(0, 2, n)
        bwd_pkts = rng.integers(0, 2, n)
        port = rng.integers(1, 65535, n)
    elif "DDoS" in kind or "Hulk" in kind or "GoldenEye" in kind:
        # Rất nhiều gói đi, phiên ngắn, tỉ lệ đi/về lệch hẳn.
        duration = rng.lognormal(mean=9.0, sigma=1.2, size=n)
        fwd_pkts = rng.lognormal(mean=3.4, sigma=0.8, size=n).round() + 5
        bwd_pkts = rng.lognormal(mean=1.0, sigma=0.8, size=n).round()
        port = np.full(n, 80)
    elif "slowloris" in kind or "Slowhttptest" in kind:
        # Đặc trưng ngược lại: phiên kéo rất dài, cực ít gói.
        duration = rng.lognormal(mean=15.5, sigma=1.0, size=n)
        fwd_pkts = rng.integers(2, 12, n)
        bwd_pkts = rng.integers(1, 6, n)
        port = np.full(n, 80)
    elif "Patator" in kind:
        # Dò mật khẩu: nhiều phiên ngắn giống hệt nhau tới cùng một cổng.
        duration = rng.lognormal(mean=12.5, sigma=0.6, size=n)
        fwd_pkts = rng.integers(8, 26, n)
        bwd_pkts = rng.integers(8, 26, n)
        port = np.full(n, 21 if "FTP" in kind else 22)
    elif "Web Attack" in kind:
        duration = rng.lognormal(mean=12.0, sigma=1.5, size=n)
        fwd_pkts = rng.integers(4, 40, n)
        bwd_pkts = rng.integers(3, 30, n)
        port = np.full(n, 80)
    else:  # Bot, Infiltration, Heartbleed
        duration = rng.lognormal(mean=13.0, sigma=2.0, size=n)
        fwd_pkts = rng.integers(2, 60, n)
        bwd_pkts = rng.integers(2, 60, n)
        port = rng.choice([80, 443, 8080], n)

    fwd_pkts = np.maximum(fwd_pkts, 1)
    bwd_pkts = np.maximum(bwd_pkts, 0)
    return {
        " Destination Port": port,
        " Flow Duration": duration,
        " Total Fwd Packets": fwd_pkts,
        " Total Backward Packets": bwd_pkts,
        "Total Length of Fwd Packets": fwd_pkts * rng.uniform(40, 400, n),
        " Total Length of Bwd Packets": bwd_pkts * rng.uniform(0, 300, n),
        " SYN Flag Count": rng.integers(0, 3, n),
        " PSH Flag Count": rng.integers(0, 2, n),
        " ACK Flag Count": rng.integers(0, 3, n),
        "FIN Flag Count": rng.integers(0, 2, n),
    }


def _derive(base: Dict[str, np.ndarray], rng: np.random.Generator, n: int) -> pd.DataFrame:
    """Tính các đặc trưng phái sinh từ những đại lượng cơ bản."""
    duration = base[" Flow Duration"]
    fwd_pkts = base[" Total Fwd Packets"]
    bwd_pkts = base[" Total Backward Packets"]
    fwd_len = base["Total Length of Fwd Packets"]
    bwd_len = base[" Total Length of Bwd Packets"]

    total_pkts = fwd_pkts + bwd_pkts
    total_len = fwd_len + bwd_len

    # Ép khoảng 0.5% số luồng có thời lượng bằng 0. Trong bộ thật, đây là các
    # luồng chỉ gồm một gói duy nhất, được ghi nhận với Flow Duration = 0 — và
    # chính chúng sinh ra inf ở các cột tính theo giây. Không tái tạo chỗ này
    # thì test "đã loại hết inf chưa" trở nên vô nghĩa.
    zero_duration = rng.random(n) < 0.005
    duration = duration.copy()
    duration[zero_duration] = 0.0

    # Chia cho 0 một cách CÓ CHỦ Ý: chính đây là nguồn sinh ra inf trong bộ thật.
    with np.errstate(divide="ignore", invalid="ignore"):
        flow_bytes_s = total_len / (duration / 1e6)
        flow_pkts_s = total_pkts / (duration / 1e6)
        fwd_pkts_s = fwd_pkts / (duration / 1e6)
        bwd_pkts_s = bwd_pkts / (duration / 1e6)

    fwd_mean = np.where(fwd_pkts > 0, fwd_len / np.maximum(fwd_pkts, 1), 0)
    bwd_mean = np.where(bwd_pkts > 0, bwd_len / np.maximum(bwd_pkts, 1), 0)
    pkt_mean = np.where(total_pkts > 0, total_len / np.maximum(total_pkts, 1), 0)
    iat_mean = duration / np.maximum(total_pkts, 1)

    frame = pd.DataFrame({
        " Destination Port": base[" Destination Port"].astype(np.int64),
        " Flow Duration": duration.astype(np.int64),
        " Total Fwd Packets": fwd_pkts.astype(np.int64),
        " Total Backward Packets": bwd_pkts.astype(np.int64),
        "Total Length of Fwd Packets": fwd_len,
        " Total Length of Bwd Packets": bwd_len,
        " Fwd Packet Length Max": fwd_mean * rng.uniform(1.0, 2.5, n),
        " Fwd Packet Length Min": fwd_mean * rng.uniform(0.1, 0.9, n),
        " Fwd Packet Length Mean": fwd_mean,
        " Fwd Packet Length Std": fwd_mean * rng.uniform(0.0, 0.6, n),
        "Bwd Packet Length Max": bwd_mean * rng.uniform(1.0, 2.5, n),
        " Bwd Packet Length Min": bwd_mean * rng.uniform(0.1, 0.9, n),
        " Bwd Packet Length Mean": bwd_mean,
        " Bwd Packet Length Std": bwd_mean * rng.uniform(0.0, 0.6, n),
        "Flow Bytes/s": flow_bytes_s,
        " Flow Packets/s": flow_pkts_s,
        " Flow IAT Mean": iat_mean,
        " Flow IAT Std": iat_mean * rng.uniform(0.0, 1.5, n),
        " Flow IAT Max": iat_mean * rng.uniform(1.0, 6.0, n),
        " Flow IAT Min": iat_mean * rng.uniform(0.0, 0.5, n),
        "Fwd IAT Total": duration * rng.uniform(0.4, 1.0, n),
        " Fwd IAT Mean": iat_mean * rng.uniform(0.6, 1.6, n),
        " Fwd Header Length": fwd_pkts * 32,
        " Bwd Header Length": bwd_pkts * 32,
        "Fwd Packets/s": fwd_pkts_s,
        " Bwd Packets/s": bwd_pkts_s,
        " Min Packet Length": np.minimum(fwd_mean, bwd_mean) * rng.uniform(0.1, 0.9, n),
        " Max Packet Length": np.maximum(fwd_mean, bwd_mean) * rng.uniform(1.0, 2.0, n),
        " Packet Length Mean": pkt_mean,
        " Packet Length Std": pkt_mean * rng.uniform(0.0, 0.8, n),
        "FIN Flag Count": base["FIN Flag Count"],
        " SYN Flag Count": base[" SYN Flag Count"],
        " PSH Flag Count": base[" PSH Flag Count"],
        " ACK Flag Count": base[" ACK Flag Count"],
        " Average Packet Size": pkt_mean * rng.uniform(0.9, 1.1, n),
    })

    # Cột trùng tên, đúng như pandas đặt khi đọc CSV gốc.
    frame[" Fwd Header Length.1"] = frame[" Fwd Header Length"]
    for column in CONSTANT_COLUMNS:
        frame[column] = 0

    return frame


def generate_day(
    rng: np.random.Generator, rows: int, attacks: List[str], attack_ratio: float
) -> pd.DataFrame:
    """Sinh dữ liệu một ngày, trộn lưu lượng lành tính với các họ tấn công."""
    n_attack_total = int(rows * attack_ratio)
    n_benign = rows - n_attack_total

    parts: List[pd.DataFrame] = []
    labels: List[np.ndarray] = []

    if n_benign > 0:
        frame = _derive(_benign(rng, n_benign), rng, n_benign)
        parts.append(frame)
        labels.append(np.full(n_benign, "BENIGN"))

    if attacks and n_attack_total > 0:
        # Lớp cực hiếm lấy đúng số lượng cố định; phần còn lại chia đều.
        rare = [a for a in attacks if a in RARE_LABELS]
        common = [a for a in attacks if a not in RARE_LABELS]

        for label in rare:
            n = min(RARE_LABELS[label], n_attack_total)
            if n <= 0:
                continue
            parts.append(_derive(_attack(rng, n, label), rng, n))
            labels.append(np.full(n, label))
            n_attack_total -= n

        if common and n_attack_total > 0:
            per_class = max(1, n_attack_total // len(common))
            for label in common:
                n = min(per_class, n_attack_total)
                if n <= 0:
                    break
                parts.append(_derive(_attack(rng, n, label), rng, n))
                labels.append(np.full(n, label))
                n_attack_total -= n

    day = pd.concat(parts, ignore_index=True)
    day[" Label"] = np.concatenate(labels)

    # Xáo trộn để tấn công không nằm gọn ở cuối tệp.
    return day.sample(frac=1.0, random_state=int(rng.integers(0, 2**31))).reset_index(drop=True)


def generate(out_dir: Path, rows_per_day: int = 20_000, seed: int = 42) -> List[Path]:
    rng = np.random.default_rng(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    for filename, (day, attacks, ratio) in DAY_PLAN.items():
        frame = generate_day(rng, rows_per_day, attacks, ratio)
        path = out_dir / filename
        # latin-1 để tái tạo đúng lỗi encoding của nhãn 'Web Attack'.
        frame.to_csv(path, index=False, encoding="latin-1")
        counts = frame[" Label"].value_counts().to_dict()
        logger.info("%-52s %6d dong  (%s)  %s", filename, len(frame), day, counts)
        written.append(path)

    return written


def main() -> int:
    parser = argparse.ArgumentParser(description="Sinh dữ liệu tổng hợp giống CIC-IDS2017")
    parser.add_argument("--out", type=Path, default=Path("data/raw_synthetic"))
    parser.add_argument("--rows-per-day", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
    paths = generate(args.out, args.rows_per_day, args.seed)

    print(f"\nDa sinh {len(paths)} tep vao {args.out}")
    print("LUU Y: day la du lieu TONG HOP, chi dung de kiem thu duong ong.")
    print("       Ket qua thuc nghiem trong bao cao PHAI chay tren CIC-IDS2017 that.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
