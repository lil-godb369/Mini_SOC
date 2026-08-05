"""Tiền xử lý CIC-IDS2017 — lớp 2.

Bộ dữ liệu này nổi tiếng là "sạch" trên giấy nhưng bẩn khi mở ra. Module này xử
lý từng vấn đề một cách tường minh, vì mỗi lỗi bỏ sót đều bơm điểm số ảo cho mô
hình — và hội đồng chấm sẽ hỏi đúng vào đó:

1. **Tên cột có khoảng trắng thừa** — `' Flow Duration'` chứ không phải
   `'Flow Duration'`. Không strip thì mọi lệnh chọn cột đều trượt.
2. **Cột trùng tên** — `Fwd Header Length` xuất hiện hai lần, pandas tự đổi
   thành `Fwd Header Length.1`. Giữ cả hai là nhân đôi trọng số của một đặc trưng.
3. **Giá trị vô cực** — `Flow Bytes/s` và `Flow Packets/s` chia cho thời lượng
   luồng; luồng dài 0 micro-giây tạo ra `inf`. scikit-learn ném lỗi khi gặp inf.
4. **Nhãn hỏng encoding** — `'Web Attack \x96 Brute Force'` (0x96 là dấu gạch
   ngang trong latin-1). Đọc bằng UTF-8 sẽ nổ hoặc tạo ra nhãn rác.
5. **Cột hằng số** — hàng chục cột toàn số 0 ở mọi dòng. Chúng không mang thông
   tin, chỉ làm chậm việc huấn luyện và làm nhiễu biểu đồ độ quan trọng đặc trưng.
6. **Rò rỉ qua cổng đích** — xem chú thích ở `DEFAULT_DROP_COLUMNS` bên dưới.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

LABEL_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"

# Ánh xạ tệp CSV -> ngày thu thập. Đây là nền tảng cho việc chia tập theo ngày:
# huấn luyện trên thứ Hai-Tư, kiểm thử trên thứ Năm-Sáu.
FILE_TO_DAY: Dict[str, str] = {
    "Monday-WorkingHours": "monday",
    "Tuesday-WorkingHours": "tuesday",
    "Wednesday-workingHours": "wednesday",
    "Thursday-WorkingHours-Morning-WebAttacks": "thursday",
    "Thursday-WorkingHours-Afternoon-Infilteration": "thursday",
    "Friday-WorkingHours-Morning": "friday",
    "Friday-WorkingHours-Afternoon-PortScan": "friday",
    "Friday-WorkingHours-Afternoon-DDos": "friday",
}

TRAIN_DAYS = ("monday", "tuesday", "wednesday")
TEST_DAYS = ("thursday", "friday")

# Cột bị loại theo mặc định.
#
# `Destination Port` là cái bẫy lớn nhất của bộ dữ liệu này. Nó tương quan gần
# như hoàn hảo với nhãn: lưu lượng PortScan trong CIC-IDS2017 nhắm vào một dải
# cổng cố định, nên mô hình chỉ cần học "cổng 21 = FTP-Patator" là đạt F1 ~0.99
# mà KHÔNG học được gì về hành vi tấn công. Đưa mô hình đó ra mạng thật thì nó
# sập ngay. Ta bỏ cột này để buộc mô hình học đặc trưng thống kê của luồng — kết
# quả sẽ thấp hơn con số thường thấy trong các bài báo, nhưng là con số thật.
DEFAULT_DROP_COLUMNS = ["Destination Port"]

# Cột định danh, nếu có trong biến thể CSE-CIC-IDS2018 thì cũng phải bỏ.
IDENTIFIER_COLUMNS = [
    "Flow ID", "Source IP", "Src IP", "Destination IP", "Dst IP",
    "Source Port", "Src Port", "Timestamp", "Protocol",
]


def _clean_label(value: str) -> str:
    """Chuẩn hoá một nhãn: bỏ khoảng trắng thừa và sửa ký tự hỏng encoding."""
    text = str(value).strip()
    # 0x96 (latin-1 en-dash) và các biến thể của nó trong 'Web Attack — XSS'.
    for broken in ("\x96", "–", "—"):
        text = text.replace(broken, "-")
    # Gộp nhiều khoảng trắng liên tiếp thành một.
    return " ".join(text.split())


def load_raw(data_dir: Path) -> pd.DataFrame:
    """Đọc mọi CSV của CIC-IDS2017 trong thư mục, gắn thêm cột `day`."""
    csv_files = sorted(Path(data_dir).glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"Không thấy tệp .csv nào trong {data_dir}. "
            "Tải CIC-IDS2017 (thư mục MachineLearningCVE) rồi giải nén vào đây."
        )

    frames: List[pd.DataFrame] = []
    for path in csv_files:
        # latin-1 chứ không phải utf-8: nhãn 'Web Attack' chứa byte 0x96.
        frame = pd.read_csv(path, encoding="latin-1", low_memory=False)
        frame.columns = [str(c).strip() for c in frame.columns]

        day = next((d for prefix, d in FILE_TO_DAY.items() if path.stem.startswith(prefix)), None)
        if day is None:
            logger.warning("Không nhận ra ngày của tệp %s, gán 'unknown'", path.name)
            day = "unknown"
        frame["day"] = day

        logger.info("Đã đọc %-52s %8d dòng  (%s)", path.name, len(frame), day)
        frames.append(frame)

    combined = pd.concat(frames, ignore_index=True)
    logger.info("Tổng cộng %d dòng, %d cột", len(combined), combined.shape[1])
    return combined


def clean(
    df: pd.DataFrame,
    drop_columns: Optional[List[str]] = None,
    keep_destination_port: bool = False,
) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Làm sạch và tách thành (X, y, day).

    Trả về đặc trưng dạng float32 — giảm một nửa bộ nhớ so với float64, và toàn
    bộ bộ dữ liệu 2.8 triệu dòng vừa trong RAM của máy laptop.
    """
    df = df.copy()
    stats: Dict[str, int] = {}

    # --- Nhãn ---
    if LABEL_COLUMN not in df.columns:
        raise KeyError(f"Không tìm thấy cột nhãn {LABEL_COLUMN!r}. Có: {list(df.columns)[:10]}")
    labels = df[LABEL_COLUMN].map(_clean_label)
    days = df["day"] if "day" in df.columns else pd.Series(["unknown"] * len(df))

    features = df.drop(columns=[LABEL_COLUMN] + (["day"] if "day" in df.columns else []))

    # --- Cột trùng tên (Fwd Header Length.1) ---
    duplicated = [c for c in features.columns if c.endswith(".1")]
    if duplicated:
        features = features.drop(columns=duplicated)
        stats["cot_trung_ten"] = len(duplicated)

    # --- Cột định danh và cột bị loại theo yêu cầu ---
    to_drop = [c for c in IDENTIFIER_COLUMNS if c in features.columns]
    explicit = list(drop_columns) if drop_columns is not None else list(DEFAULT_DROP_COLUMNS)
    if keep_destination_port:
        explicit = [c for c in explicit if c != "Destination Port"]
    to_drop += [c for c in explicit if c in features.columns and c not in to_drop]
    if to_drop:
        features = features.drop(columns=to_drop)
        stats["cot_dinh_danh_bi_loai"] = len(to_drop)

    # --- Chỉ giữ cột số ---
    non_numeric = [c for c in features.columns if not pd.api.types.is_numeric_dtype(features[c])]
    if non_numeric:
        features = features.drop(columns=non_numeric)
        stats["cot_khong_phai_so"] = len(non_numeric)

    # --- Vô cực -> NaN -> bỏ dòng ---
    features = features.replace([np.inf, -np.inf], np.nan)
    bad_rows = features.isna().any(axis=1)
    stats["dong_bi_bo_do_nan_hoac_inf"] = int(bad_rows.sum())
    features = features[~bad_rows]
    labels = labels[~bad_rows]
    days = days[~bad_rows]

    # --- Cột hằng số ---
    constant = [c for c in features.columns if features[c].nunique(dropna=False) <= 1]
    if constant:
        features = features.drop(columns=constant)
        stats["cot_hang_so"] = len(constant)

    features = features.astype(np.float32)

    for name, value in stats.items():
        logger.info("  %-32s %d", name, value)
    logger.info(
        "Sau khi làm sạch: %d dòng, %d đặc trưng, %d lớp",
        len(features), features.shape[1], labels.nunique(),
    )

    return (
        features.reset_index(drop=True),
        labels.reset_index(drop=True),
        days.reset_index(drop=True),
    )


def to_binary(labels: pd.Series) -> pd.Series:
    """Quy về nhị phân: 0 = lành tính, 1 = tấn công."""
    return (labels != BENIGN_LABEL).astype(np.int8)


def split_by_day(
    X: pd.DataFrame, y: pd.Series, days: pd.Series
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Chia theo NGÀY: huấn luyện thứ Hai-Tư, kiểm thử thứ Năm-Sáu.

    Vì sao không dùng chia ngẫu nhiên: các luồng trong CIC-IDS2017 sinh ra theo
    phiên, nên hai luồng liên tiếp của cùng một phiên tấn công gần như giống hệt
    nhau. Chia ngẫu nhiên đặt luồng thứ nhất vào tập huấn luyện và luồng thứ hai
    vào tập kiểm thử -> mô hình "nhớ" chứ không "học", và F1 vọt lên ~0.999.

    Chia theo ngày cũng là một phép thử khắc nghiệt hơn nhiều: các kiểu tấn công
    của thứ Năm-Sáu (Web Attack, Infiltration, Bot, PortScan, DDoS) HOÀN TOÀN
    không xuất hiện trong tập huấn luyện. Nói cách khác, ta đang đo xem mô hình
    có phát hiện được kiểu tấn công CHƯA TỪNG THẤY hay không — đúng tình huống
    một SMB gặp phải ngoài đời. Con số sẽ thấp hơn nhiều so với chia ngẫu nhiên,
    và đó chính là điều đáng báo cáo.
    """
    train_mask = days.isin(TRAIN_DAYS)
    test_mask = days.isin(TEST_DAYS)

    if not train_mask.any() or not test_mask.any():
        raise ValueError(
            "Không chia được theo ngày — thiếu dữ liệu của một trong hai nhóm ngày. "
            f"Các ngày có mặt: {sorted(days.unique())}"
        )

    return X[train_mask], X[test_mask], y[train_mask], y[test_mask]


def summarize_labels(labels: pd.Series, days: Optional[pd.Series] = None) -> pd.DataFrame:
    """Bảng phân bố lớp — dùng trực tiếp trong báo cáo."""
    counts = labels.value_counts()
    table = pd.DataFrame({
        "so_luong": counts,
        "ty_le_phan_tram": (counts / len(labels) * 100).round(4),
    })
    if days is not None:
        table["ngay"] = [
            ", ".join(sorted(days[labels == label].unique())) for label in table.index
        ]
    return table


def main() -> int:
    parser = argparse.ArgumentParser(description="Tiền xử lý CIC-IDS2017")
    parser.add_argument("--data-dir", type=Path, default=Path("data/raw"),
                        help="Thư mục chứa các tệp CSV của CIC-IDS2017")
    parser.add_argument("--out", type=Path, default=Path("data/processed"),
                        help="Nơi ghi dữ liệu đã làm sạch (định dạng parquet)")
    parser.add_argument("--keep-destination-port", action="store_true",
                        help="Giữ cột Destination Port (KHÔNG khuyến nghị, xem chú thích)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")

    raw = load_raw(args.data_dir)
    X, y, days = clean(raw, keep_destination_port=args.keep_destination_port)

    print("\n=== Phân bố nhãn ===")
    print(summarize_labels(y, days).to_string())

    args.out.mkdir(parents=True, exist_ok=True)
    X.to_parquet(args.out / "features.parquet", index=False)
    pd.DataFrame({"label": y, "day": days}).to_parquet(args.out / "labels.parquet", index=False)
    print(f"\nĐã ghi dữ liệu đã làm sạch vào {args.out}")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
