"""Unit test cho tiền xử lý CIC-IDS2017 (lớp 2).

Mỗi test ở đây tương ứng với một chỗ BẨN có thật trong bộ dữ liệu gốc. Nếu bước
làm sạch bỏ sót bất kỳ chỗ nào, mô hình vẫn huấn luyện được và vẫn ra số đẹp —
nhưng số đó sai. Đó là lý do phần này phải có test, dù nó chỉ là "xử lý dữ liệu".
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from preprocess import (
    BENIGN_LABEL,
    TEST_DAYS,
    TRAIN_DAYS,
    _clean_label,
    clean,
    load_raw,
    split_by_day,
    summarize_labels,
    to_binary,
)
from synthetic import generate


@pytest.fixture(scope="module")
def synthetic_dir(tmp_path_factory):
    """Sinh một bộ dữ liệu tổng hợp nhỏ, mang đủ các lỗi của bộ thật."""
    directory = tmp_path_factory.mktemp("cic_synthetic")
    generate(directory, rows_per_day=600, seed=7)
    return directory


@pytest.fixture(scope="module")
def raw(synthetic_dir):
    return load_raw(synthetic_dir)


# ---------------------------------------------------------------------------
# Chuẩn hoá nhãn
# ---------------------------------------------------------------------------
class TestChuanHoaNhan:
    def test_sua_nhan_hong_encoding(self):
        """0x96 trong latin-1 là dấu gạch ngang — đọc bằng UTF-8 sẽ ra rác."""
        assert _clean_label("Web Attack \x96 Brute Force") == "Web Attack - Brute Force"

    def test_bo_khoang_trang_thua(self):
        assert _clean_label("  BENIGN  ") == "BENIGN"

    def test_gop_nhieu_khoang_trang_lien_tiep(self):
        assert _clean_label("DoS    Hulk") == "DoS Hulk"


# ---------------------------------------------------------------------------
# Đọc dữ liệu
# ---------------------------------------------------------------------------
class TestDocDuLieu:
    def test_doc_du_tam_tep_va_gan_ngay(self, raw):
        assert set(raw["day"].unique()) == {
            "monday", "tuesday", "wednesday", "thursday", "friday"
        }

    def test_thu_muc_rong_bao_loi_ro_rang(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="CIC-IDS2017"):
            load_raw(tmp_path)

    def test_ten_cot_da_duoc_bo_khoang_trang(self, raw):
        assert "Flow Duration" in raw.columns
        assert " Flow Duration" not in raw.columns


# ---------------------------------------------------------------------------
# Làm sạch — từng test là một lỗi có thật của bộ dữ liệu
# ---------------------------------------------------------------------------
class TestLamSach:
    def test_bo_cot_trung_ten(self, raw):
        """`Fwd Header Length` xuất hiện hai lần; giữ cả hai là nhân đôi trọng số."""
        assert "Fwd Header Length.1" in raw.columns   # bộ thô đúng là có
        X, _, _ = clean(raw)
        assert "Fwd Header Length.1" not in X.columns
        assert "Fwd Header Length" in X.columns

    def test_khong_con_vo_cuc_hay_nan(self, raw):
        """`Flow Bytes/s` chia cho thời lượng luồng; luồng dài 0 sinh ra inf."""
        assert np.isinf(raw["Flow Bytes/s"]).any(), "dữ liệu thử phải có inf mới kiểm được"
        X, _, _ = clean(raw)
        assert np.isfinite(X.values).all()

    def test_bo_cot_hang_so(self, raw):
        """Bộ thật có hàng chục cột toàn 0 — chúng chỉ làm nhiễu độ quan trọng đặc trưng."""
        X, _, _ = clean(raw)
        for column in ("Bwd PSH Flags", "Fwd URG Flags", "CWE Flag Count"):
            assert column not in X.columns

    def test_bo_destination_port_theo_mac_dinh(self, raw):
        """Cột này rò rỉ nhãn — xem chú thích trong preprocess.py."""
        X, _, _ = clean(raw)
        assert "Destination Port" not in X.columns

    def test_giu_duoc_destination_port_khi_yeu_cau(self, raw):
        X, _, _ = clean(raw, keep_destination_port=True)
        assert "Destination Port" in X.columns

    def test_bo_cot_nhan_khoi_dac_trung(self, raw):
        X, y, _ = clean(raw)
        assert "Label" not in X.columns
        assert "day" not in X.columns
        assert len(X) == len(y)

    def test_ep_kieu_float32_de_tiet_kiem_bo_nho(self, raw):
        X, _, _ = clean(raw)
        assert all(dtype == np.float32 for dtype in X.dtypes)

    def test_nhan_duoc_chuan_hoa_sau_khi_lam_sach(self, raw):
        _, y, _ = clean(raw)
        assert not any("\x96" in label for label in y.unique())
        assert any(label.startswith("Web Attack -") for label in y.unique())

    def test_thieu_cot_nhan_bao_loi_ro_rang(self):
        with pytest.raises(KeyError, match="Label"):
            clean(pd.DataFrame({"a": [1, 2], "day": ["monday", "monday"]}))

    def test_chi_so_duoc_danh_lai_lien_tuc(self, raw):
        """Sau khi bỏ dòng NaN, chỉ số phải liền mạch — nếu không, việc lọc theo
        mặt nạ boolean ở bước chia tập sẽ lệch hàng."""
        X, y, days = clean(raw)
        assert list(X.index) == list(range(len(X)))
        assert list(y.index) == list(range(len(y)))
        assert list(days.index) == list(range(len(days)))


# ---------------------------------------------------------------------------
# Nhãn nhị phân
# ---------------------------------------------------------------------------
class TestNhanNhiPhan:
    def test_lanh_tinh_thanh_0_tan_cong_thanh_1(self):
        labels = pd.Series([BENIGN_LABEL, "DoS Hulk", BENIGN_LABEL, "PortScan"])
        assert list(to_binary(labels)) == [0, 1, 0, 1]

    def test_du_lieu_that_van_con_ca_hai_lop(self, raw):
        _, labels, _ = clean(raw)
        y = to_binary(labels)
        assert y.sum() > 0
        assert (y == 0).sum() > 0


# ---------------------------------------------------------------------------
# Chia tập theo ngày — quyết định phương pháp luận quan trọng nhất
# ---------------------------------------------------------------------------
class TestChiaTapTheoNgay:
    def test_chia_dung_theo_nhom_ngay(self, raw):
        X, labels, days = clean(raw)
        y = to_binary(labels)
        X_train, X_test, y_train, y_test = split_by_day(X, y, days)

        assert len(X_train) + len(X_test) == len(X)
        assert len(X_train) == len(y_train)
        assert len(X_test) == len(y_test)
        assert len(X_train) > 0 and len(X_test) > 0

    def test_khong_co_dong_nao_lot_ca_hai_tap(self, raw):
        """Kiểm tra rò rỉ trực tiếp: không dòng nào được nằm ở cả hai bên."""
        X, labels, days = clean(raw)
        y = to_binary(labels)
        X_train, X_test, _, _ = split_by_day(X, y, days)
        assert set(X_train.index).isdisjoint(set(X_test.index))

    def test_tap_kiem_thu_chua_kieu_tan_cong_chua_tung_thay(self, raw):
        """Đây chính là điều làm phép chia theo ngày khắc nghiệt và đáng báo cáo.

        Các họ tấn công của thứ Năm-Sáu (Web Attack, Bot, PortScan, DDoS) hoàn
        toàn vắng mặt ở thứ Hai-Tư. Mô hình phải TỔNG QUÁT HOÁ, không được nhớ.
        """
        _, labels, days = clean(raw)
        train_attacks = set(labels[days.isin(TRAIN_DAYS)].unique()) - {BENIGN_LABEL}
        test_attacks = set(labels[days.isin(TEST_DAYS)].unique()) - {BENIGN_LABEL}

        assert test_attacks, "tập kiểm thử phải có tấn công"
        chua_tung_thay = test_attacks - train_attacks
        assert chua_tung_thay == test_attacks, (
            "MỌI kiểu tấn công ở tập kiểm thử đều phải là kiểu chưa từng thấy; "
            f"bị lọt: {test_attacks & train_attacks}"
        )

    def test_thieu_du_lieu_mot_nhom_ngay_thi_bao_loi(self):
        X = pd.DataFrame({"a": [1.0, 2.0, 3.0]})
        y = pd.Series([0, 1, 0])
        days = pd.Series(["monday", "tuesday", "wednesday"])   # không có thứ Năm/Sáu
        with pytest.raises(ValueError, match="Không chia được theo ngày"):
            split_by_day(X, y, days)


# ---------------------------------------------------------------------------
# Bảng phân bố lớp cho báo cáo
# ---------------------------------------------------------------------------
def test_bang_phan_bo_lop_co_du_cot(raw):
    _, labels, days = clean(raw)
    table = summarize_labels(labels, days)

    assert {"so_luong", "ty_le_phan_tram", "ngay"} <= set(table.columns)
    assert table["so_luong"].sum() == len(labels)
    assert BENIGN_LABEL in table.index


def test_lop_cuc_hiem_van_ton_tai_sau_lam_sach(raw):
    """Heartbleed chỉ có 11 mẫu trong bộ thật. Bước làm sạch không được xoá sạch
    lớp hiếm — chính chúng phơi bày giới hạn của phương pháp trong báo cáo."""
    _, labels, _ = clean(raw)
    counts = labels.value_counts()
    hiem = counts[counts < 50]
    assert len(hiem) > 0, "phải còn ít nhất một lớp cực hiếm để báo cáo"
