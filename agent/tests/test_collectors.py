"""Unit test cho bộ thu thập của agent (lớp 1).

Test quan trọng nhất ở đây là `TestKhongCanTroHeThong`. Nó bảo vệ một tính chất
mà một sản phẩm an ninh BẮT BUỘC phải có: **agent không được cản trở hoạt động
bình thường của máy nó đang bảo vệ**.

Tính chất đó đã từng bị vi phạm thật. Khi chạy demo đầu tiên trên stack thật,
`ransomware_sim.py` chết giữa chừng với `WinError 32` — vì agent mở file để tính
entropy đúng lúc tiến trình kia đổi tên file. Người dùng cuối sẽ chỉ thấy "cài
phần mềm bảo mật này vào là máy hỏng", và gỡ nó ngay.
"""
from __future__ import annotations

import math
import os
import threading

import pytest

from mini_soc_agent.collectors import (
    NetworkCollector,
    ProcessCollector,
    file_entropy,
    shannon_entropy,
)


# ---------------------------------------------------------------------------
# Entropy — tín hiệu chính của bộ phát hiện ransomware
# ---------------------------------------------------------------------------
class TestEntropy:
    def test_du_lieu_rong_tra_ve_khong(self):
        assert shannon_entropy(b"") == 0.0

    def test_byte_lap_lai_co_entropy_bang_khong(self):
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_du_lieu_ngau_nhien_gan_toi_da(self):
        """Dữ liệu đã mã hoá trông như ngẫu nhiên: entropy tiệm cận 8.0."""
        assert shannon_entropy(os.urandom(100_000)) > 7.9

    def test_van_ban_thap_hon_nhieu_so_voi_du_lieu_ma_hoa(self):
        """Đây chính là cơ sở để phân biệt ransomware với việc ghi file thường."""
        text = ("Tai lieu kinh doanh quan trong cua cong ty. " * 500).encode("utf-8")
        assert shannon_entropy(text) < 6.0

    def test_hai_gia_tri_bang_nhau_cho_dung_mot_bit(self):
        assert math.isclose(shannon_entropy(b"AB" * 500), 1.0, abs_tol=1e-9)

    def test_doc_entropy_cua_file_that(self, tmp_path):
        target = tmp_path / "ngau_nhien.bin"
        target.write_bytes(os.urandom(70_000))
        assert file_entropy(str(target)) > 7.9

    def test_file_khong_ton_tai_tra_ve_none(self, tmp_path):
        assert file_entropy(str(tmp_path / "khong_co.bin")) is None

    def test_file_rong_tra_ve_khong(self, tmp_path):
        target = tmp_path / "rong.txt"
        target.write_bytes(b"")
        assert file_entropy(str(target)) == 0.0


# ---------------------------------------------------------------------------
# HỒI QUY: agent không được cản trở hệ thống
# ---------------------------------------------------------------------------
class TestKhongCanTroHeThong:
    def test_doc_entropy_khong_chan_doi_ten_file(self, tmp_path):
        """Đổi tên file phải luôn thành công, kể cả khi agent đang đọc nó.

        Trên Windows, `open()` của Python không đặt cờ FILE_SHARE_DELETE, nên
        file đang mở thì không đổi tên được. Đây chính là lỗi đã làm hỏng lần
        demo đầu tiên, và test này sẽ bắt được nếu nó quay lại.
        """
        target = tmp_path / "du_lieu.bin"
        target.write_bytes(os.urandom(200_000))

        stop = threading.Event()
        read_count = [0]

        def doc_lien_tuc():
            while not stop.is_set():
                file_entropy(str(target))
                read_count[0] += 1

        reader = threading.Thread(target=doc_lien_tuc, daemon=True)
        reader.start()

        loi_doi_ten = []
        try:
            for i in range(150):
                tam = tmp_path / f"du_lieu_{i}.locked"
                try:
                    os.rename(target, tam)
                    os.rename(tam, target)
                except PermissionError as exc:
                    loi_doi_ten.append(exc)
                    break
        finally:
            stop.set()
            reader.join(timeout=5)

        assert read_count[0] > 0, "luồng đọc chưa chạy — test không kiểm được gì"
        assert not loi_doi_ten, (
            f"agent chặn thao tác đổi tên của tiến trình khác: {loi_doi_ten[0]}"
        )

    def test_doc_entropy_khong_chan_xoa_file(self, tmp_path):
        """Tương tự với việc xoá — ransomware và phần mềm hợp lệ đều xoá file."""
        stop = threading.Event()
        target = tmp_path / "tam.bin"
        target.write_bytes(os.urandom(120_000))

        def doc_lien_tuc():
            while not stop.is_set():
                file_entropy(str(target))

        reader = threading.Thread(target=doc_lien_tuc, daemon=True)
        reader.start()

        loi_xoa = []
        try:
            for _ in range(80):
                try:
                    os.remove(target)
                except PermissionError as exc:
                    loi_xoa.append(exc)
                    break
                except FileNotFoundError:
                    pass
                target.write_bytes(os.urandom(120_000))
        finally:
            stop.set()
            reader.join(timeout=5)

        assert not loi_xoa, f"agent chặn thao tác xoá file: {loi_xoa[0]}"


# ---------------------------------------------------------------------------
# Bộ thu thập tiến trình
# ---------------------------------------------------------------------------
class TestProcessCollector:
    def test_dung_event_theo_dung_schema(self):
        info = {
            "pid": 4321, "ppid": 1000, "name": "powershell.exe",
            "exe": r"C:\Windows\System32\powershell.exe",
            "cmdline": ["powershell.exe", "-nop", "-enc", "AAA"],
            "username": "MAY\\alice",
        }
        event = ProcessCollector._to_event(info)

        assert event["event_type"] == "process_create"
        assert {"timestamp", "host", "platform", "data"} <= set(event)
        assert event["data"]["command_line"] == "powershell.exe -nop -enc AAA"
        assert event["data"]["pid"] == 4321

    def test_cmdline_rong_khong_gay_loi(self):
        event = ProcessCollector._to_event({"pid": 1, "name": "init", "cmdline": None})
        assert event["data"]["command_line"] == ""


# ---------------------------------------------------------------------------
# Bộ thu thập mạng
# ---------------------------------------------------------------------------
class TestNetworkCollector:
    @pytest.fixture
    def collector(self):
        return NetworkCollector(emit=lambda _event: None)

    @pytest.mark.parametrize("ip", [
        "10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1",
        "172.16.0.1", "172.31.255.255",
    ])
    def test_dia_chi_noi_bo_bi_bo_qua(self, collector, ip):
        assert collector._is_external(ip) is False

    @pytest.mark.parametrize("ip", [
        "8.8.8.8", "1.1.1.1", "203.0.113.9",
        # 172.15 và 172.32 NẰM NGOÀI dải riêng 172.16.0.0/12 — đây là chỗ mà
        # cách cắt chuỗi ngây thơ ("172." là nội bộ) sẽ nhận nhầm.
        "172.15.0.1", "172.32.0.1",
    ])
    def test_dia_chi_ben_ngoai_duoc_ghi_nhan(self, collector, ip):
        assert collector._is_external(ip) is True

    def test_ip_hong_dinh_dang_khong_gay_loi(self, collector):
        assert collector._is_external("172.khong-phai-so.1") is True
