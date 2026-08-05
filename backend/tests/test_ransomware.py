"""Unit test cho bộ phát hiện hành vi ransomware (lớp 2).

Nửa số test ở đây là các ca ÂM TÍNH — những thao tác hợp lệ nhưng "trông giống"
ransomware. Đó mới là phần khó và là phần quyết định hệ thống có dùng được thật
hay không: một bộ phát hiện bắt được ransomware nhưng cũng kêu mỗi lần người
dùng giải nén file zip thì sẽ bị tắt sau đúng một tuần.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.detection import normalize
from app.detection.ransomware import RansomwareDetector


def write_event(path: str, entropy=None, pid=None, host="MAY-NAN-NHAN",
                old_path=None) -> dict:
    """Dựng một event ghi file đã chuẩn hoá (normalizer tự suy ra file_ext)."""
    data = {"file_path": path}
    if entropy is not None:
        data["entropy"] = entropy
    if pid is not None:
        data["pid"] = pid
    if old_path is not None:
        data["old_file_path"] = old_path
    return normalize({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "platform": "windows",
        "event_type": "file_modify",
        "data": data,
    })


def feed(detector, events, start=0.0, step=0.1):
    """Nạp lần lượt các event, mỗi event cách nhau `step` giây."""
    drafts = []
    for i, event in enumerate(events):
        drafts.extend(detector.observe(event, now=start + i * step))
    return drafts


@pytest.fixture
def detector():
    return RansomwareDetector()


# ===========================================================================
# CA DƯƠNG TÍNH — phải phát hiện được
# ===========================================================================
class TestPhaiPhatHien:
    def test_ransomware_kinh_dien_sinh_canh_bao_critical(self, detector):
        """20 file, entropy sát 8.0, đuôi .locked, nhiều thư mục."""
        events = [
            write_event(f"C:\\Users\\alice\\Documents\\thu_muc_{i % 4}\\bao_cao_{i}.docx.locked",
                        entropy=7.97)
            for i in range(20)
        ]
        drafts = feed(detector, events)

        assert len(drafts) == 1
        alert = drafts[0]
        assert alert.severity == "critical"
        assert alert.source == "ransomware"
        assert alert.technique == "T1486"
        assert alert.confidence >= 0.85

    def test_dong_ransomware_moi_voi_duoi_la_van_bi_bat(self, detector):
        """Đuôi .xyz chưa từng thấy — phải bắt được nhờ entropy, không nhờ danh sách đuôi."""
        events = [
            write_event(f"D:\\dulieu\\ke_toan\\so_sach_{i}.xlsx.xyz2026", entropy=7.99)
            for i in range(15)
        ]
        drafts = feed(detector, events)

        assert len(drafts) == 1
        assert drafts[0].severity in ("high", "critical")
        # Chính tín hiệu "đuôi lạ dùng chung + entropy cao" phải đóng góp điểm.
        # Con số là 10 chứ không phải 15: cảnh báo phát ra ngay khi chạm ngưỡng,
        # không đợi ransomware mã hoá xong toàn bộ (xem test phát hiện sớm bên dưới).
        assert drafts[0].evidence["uniform_unknown_extension_files"] == 10

    def test_bang_chung_giai_thich_duoc_tung_tin_hieu(self, detector):
        events = [
            write_event(f"C:\\data\\dir{i % 6}\\file_{i}.txt.locked", entropy=7.95)
            for i in range(20)
        ]
        drafts = feed(detector, events)
        evidence = drafts[0].evidence

        # Tổng đóng góp của bốn tín hiệu phải bằng đúng điểm cuối — nếu lệch thì
        # phần "giải thích" đang nói dối về cách điểm được tính.
        tong = sum(s["contribution"] for s in evidence["signals"].values())
        assert abs(tong - evidence["score"]) < 0.01

        assert set(evidence["signals"]) == {"entropy", "write_rate", "extension", "dir_spread"}
        assert evidence["files_written"] == 10       # chạm ngưỡng là báo ngay
        assert evidence["high_entropy_files"] == 10
        assert evidence["distinct_directories"] == 6
        assert evidence["mean_entropy"] == 7.95

    def test_phat_hien_som_ngay_tai_file_thu_muoi(self, detector):
        """Giá trị thực tế của bộ này nằm ở chỗ báo SỚM.

        Ransomware thật mã hoá hàng nghìn file. Báo ở file thứ 10 nghĩa là còn
        kịp cô lập máy; báo sau khi mã hoá xong thì chỉ còn là biên bản khám nghiệm.
        """
        events = [
            write_event(f"C:\\data\\dir{i % 4}\\file_{i}.locked", entropy=7.96)
            for i in range(200)
        ]

        for i, event in enumerate(events):
            drafts = detector.observe(event, now=i * 0.05)
            if drafts:
                assert i == 9, f"phải báo ở file thứ 10 (chỉ số 9), thực tế ở chỉ số {i}"
                # Dưới nửa giây kể từ file đầu tiên bị mã hoá.
                assert drafts[0].evidence["window_span_seconds"] <= 0.5
                break
        else:
            pytest.fail("không sinh cảnh báo nào")

    def test_lan_qua_nhieu_thu_muc_lam_tang_diem(self, detector_factory=RansomwareDetector):
        mot_thu_muc = feed(detector_factory(), [
            write_event(f"C:\\data\\file_{i}.locked", entropy=7.9) for i in range(20)
        ])
        nhieu_thu_muc = feed(detector_factory(), [
            write_event(f"C:\\data\\dir{i}\\file_{i}.locked", entropy=7.9) for i in range(20)
        ])
        assert nhieu_thu_muc[0].evidence["score"] > mot_thu_muc[0].evidence["score"]


# ===========================================================================
# CA ÂM TÍNH — KHÔNG được báo động
# ===========================================================================
class TestKhongDuocBaoDong:
    def test_giai_nen_zip_khong_bi_bao_dong(self, detector):
        """30 file .txt entropy thấp, ghi rất nhanh, cùng một thư mục.

        Đây là ca sát thủ với rule T1486 thuần đếm số lượng: nó sẽ báo động.
        Bộ phát hiện hành vi phải im lặng vì entropy nói rõ đây là văn bản.
        """
        events = [
            write_event(f"C:\\Users\\alice\\Downloads\\giai_nen\\tai_lieu_{i}.txt", entropy=4.8)
            for i in range(30)
        ]
        assert feed(detector, events, step=0.05) == []

    def test_chep_thu_muc_video_khong_bi_bao_dong(self, detector):
        """File .mp4 vốn dĩ entropy ~7.9 — cao là bình thường, không phải mã hoá."""
        events = [
            write_event(f"E:\\Media\\phim\\tap_{i:02d}.mp4", entropy=7.92)
            for i in range(25)
        ]
        assert feed(detector, events, step=0.2) == []

    def test_trinh_bien_dich_ghi_hang_loat_khong_bi_bao_dong(self, detector):
        events = [
            write_event(f"D:\\Code\\build\\obj\\module_{i}.obj", entropy=6.1)
            for i in range(40)
        ]
        assert feed(detector, events, step=0.02) == []

    def test_it_file_khong_bao_dong_du_entropy_cao(self, detector):
        """Dưới ngưỡng 10 file: mã hoá vài file là việc hợp lệ hàng ngày."""
        events = [
            write_event(f"C:\\secret\\note_{i}.txt.locked", entropy=7.99)
            for i in range(9)
        ]
        assert feed(detector, events) == []

    def test_ghi_thua_thot_trong_thoi_gian_dai_khong_bao_dong(self, detector):
        """20 file entropy cao nhưng rải trên 10 phút — vượt xa cửa sổ 30 giây."""
        events = [write_event(f"C:\\backup\\sao_luu_{i}.gpg", entropy=7.98) for i in range(20)]
        assert feed(detector, events, step=30.0) == []

    def test_hai_tien_trinh_deu_duoi_nguong_khong_bao_dong(self, detector):
        """Gom theo PID: mỗi tiến trình 8 file, không tiến trình nào đủ 10."""
        events = []
        for i in range(8):
            events.append(write_event(f"C:\\a\\f{i}.locked", entropy=7.9, pid=1111))
            events.append(write_event(f"C:\\b\\f{i}.locked", entropy=7.9, pid=2222))
        assert feed(detector, events) == []

    def test_mot_tien_trinh_vuot_nguong_thi_bao_dong(self, detector):
        """Cùng số event như trên, nhưng dồn vào một PID -> phải báo động."""
        events = [
            write_event(f"C:\\a\\f{i}.locked", entropy=7.9, pid=1111) for i in range(16)
        ]
        drafts = feed(detector, events)
        assert len(drafts) == 1
        assert drafts[0].evidence["group_key"] == "MAY-NAN-NHAN:1111"


# ===========================================================================
# Hành vi vận hành
# ===========================================================================
class TestVanHanh:
    def test_khong_lap_canh_bao_khi_ransomware_ghi_hang_nghin_file(self, detector):
        """Ransomware thật ghi hàng nghìn file — không được sinh hàng nghìn cảnh báo."""
        events = [
            write_event(f"C:\\data\\dir{i % 8}\\file_{i}.locked", entropy=7.96)
            for i in range(500)
        ]
        drafts = feed(detector, events, step=0.02)
        # 500 file trong 10 giây, cửa sổ 30 giây -> đúng một cảnh báo.
        assert len(drafts) == 1

    def test_bo_qua_event_khong_phai_ghi_file(self, detector):
        event = normalize({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "X", "platform": "windows",
            "event_type": "process_create",
            "data": {"process_name": "cmd.exe"},
        })
        assert detector.observe(event, now=1.0) == []

    def test_event_thieu_duong_dan_file_khong_gay_loi(self, detector):
        event = normalize({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "X", "platform": "windows",
            "event_type": "file_modify", "data": {},
        })
        assert detector.observe(event, now=1.0) == []

    def test_thieu_entropy_thi_giam_cap_chu_khong_bao_bua(self, detector):
        """Agent chạy với --no-entropy: không được suy diễn bừa thành báo động."""
        events = [
            write_event(f"C:\\data\\dir{i % 3}\\file_{i}.locked")  # không có entropy
            for i in range(20)
        ]
        drafts = feed(detector, events)
        # Đuôi .locked nằm trong danh sách đã biết nên vẫn đủ điểm báo, nhưng
        # tín hiệu entropy phải bằng 0 vì không có dữ liệu để khẳng định.
        assert len(drafts) == 1
        assert drafts[0].evidence["signals"]["entropy"]["value"] == 0.0
        assert drafts[0].evidence["mean_entropy"] is None

    def test_event_trung_lap_khong_lam_loang_tin_hieu(self, detector):
        """HỒI QUY: nhiều event cho cùng một file không được kéo điểm xuống.

        watchdog trên Windows bắn nhiều `on_modified` cho một lần ghi, và một số
        event chộp đúng lúc file mới ghi dở nên entropy thấp. Khi chạy demo thật,
        20 file sinh ra 86 event, tỉ lệ entropy cao tụt từ ~1.0 xuống 0.21 và
        điểm rơi từ mức "high" xuống sát ngưỡng báo động.

        Tín hiệu phải tính trên FILE, không trên EVENT.
        """
        events = []
        for i in range(15):
            path = f"C:\\data\\dir{i % 4}\\tai_lieu_{i}.locked"
            # Ba event cho mỗi file, mô phỏng đúng hành vi của watchdog:
            # tạo file (rỗng), ghi dở, và ghi xong.
            events.append(write_event(path, entropy=0.0))
            events.append(write_event(path, entropy=3.2))
            events.append(write_event(path, entropy=7.96))

        drafts = feed(detector, events, step=0.02)
        assert len(drafts) == 1

        evidence = drafts[0].evidence
        # Báo ngay khi đủ 10 FILE riêng biệt, không đợi hết 15 file.
        assert evidence["files_written"] == 10
        # Số event thô phải lớn hơn hẳn số file — chính khoảng chênh này là thứ
        # từng làm loãng các tỉ lệ trước khi có bước gộp.
        assert evidence["raw_file_events"] > evidence["files_written"] * 2

        # Đây mới là khẳng định cốt lõi. Tính trên FILE, gần như mọi file đều kết
        # thúc với entropy cao -> tín hiệu ~1.0. Nếu tính trên EVENT thô thì chỉ
        # khoảng 1/3 số event có entropy cao, tín hiệu tụt xuống ~0.33 và điểm
        # rơi khỏi mức nghiêm trọng — đúng cái đã xảy ra khi chạy demo thật.
        assert evidence["signals"]["entropy"]["value"] >= 0.9
        assert drafts[0].severity in ("high", "critical")

    def test_doi_ten_khong_bi_dem_thanh_hai_file(self, detector):
        """HỒI QUY: file trước và sau khi đổi tên là MỘT, không phải hai.

        Ransomware ghi đè nội dung rồi đổi đuôi. Bộ theo dõi file thấy cả đường
        dẫn cũ (nội dung gốc, entropy thấp) lẫn đường dẫn mới (đã mã hoá, entropy
        cao). Đếm thành hai file thì một nửa số "file" luôn có entropy thấp, và
        tín hiệu entropy vĩnh viễn không vượt quá 0.5.

        Đo được trên demo thật: 20 file .locked entropy 7.96, nhưng 81 event .txt
        của chính chúng kéo tỉ lệ xuống 7/26 và điểm từ critical còn medium.
        """
        events = []
        for i in range(12):
            goc = f"C:\\data\\dir{i % 4}\\tai_lieu_{i}.txt"
            moi = goc + ".locked"
            # Ghi đè nội dung (đọc được lúc còn là bản gốc, entropy thấp)...
            events.append(write_event(goc, entropy=3.9))
            # ...rồi đổi tên sang đuôi mới, lúc này nội dung đã mã hoá.
            events.append(write_event(moi, entropy=7.97, old_path=goc))

        drafts = feed(detector, events, step=0.03)
        assert len(drafts) == 1

        evidence = drafts[0].evidence
        # Nhiều event nhưng chỉ 10 file riêng biệt tại thời điểm chạm ngưỡng.
        assert evidence["files_written"] == 10
        assert evidence["raw_file_events"] > evidence["files_written"]

        # Tín hiệu entropy phải ở mức cao. Không đòi đúng 1.0: file vừa chạm
        # ngưỡng có thể mới chỉ được ghi đè mà chưa kịp đổi tên, nên nó còn mang
        # entropy của nội dung gốc. Đó là hành vi ĐÚNG — tại thời điểm chấm điểm,
        # hệ thống chưa thể biết file đó sắp được đổi đuôi.
        assert evidence["signals"]["entropy"]["value"] >= 0.9
        assert drafts[0].severity in ("high", "critical")

    def test_doi_ten_nhieu_lan_van_lan_ra_dung_mot_file(self, detector):
        """Chuỗi a -> b -> c phải quy về đúng một danh tính, không phải ba."""
        events = []
        for i in range(11):
            a = f"C:\\data\\f{i}.txt"
            b = a + ".tmp"
            c = a + ".locked"
            events.append(write_event(a, entropy=3.5))
            events.append(write_event(b, entropy=7.9, old_path=a))
            events.append(write_event(c, entropy=7.95, old_path=b))

        drafts = feed(detector, events, step=0.02)
        assert len(drafts) == 1
        # 33 event, 3 đường dẫn cho mỗi file — nếu chuỗi đổi tên không được lần
        # ra thì con số này sẽ là 30 thay vì 10.
        assert drafts[0].evidence["files_written"] == 10
        assert drafts[0].evidence["signals"]["entropy"]["value"] >= 0.9

    def test_mot_file_bi_ghi_nhieu_lan_khong_bi_bao_dong(self, detector):
        """HỒI QUY: ngưỡng phải đếm file riêng biệt, không đếm event.

        Một tiến trình ghi đi ghi lại đúng MỘT file (ví dụ file log đang được
        append) sẽ dễ dàng vượt ngưỡng 10 event, nhưng đó không phải ransomware.
        """
        events = [
            write_event("C:\\logs\\ung_dung.locked", entropy=7.99) for _ in range(40)
        ]
        assert feed(detector, events, step=0.05) == []

    def test_reset_xoa_sach_trang_thai(self, detector):
        events = [write_event(f"C:\\a\\f{i}.locked", entropy=7.9) for i in range(9)]
        feed(detector, events)
        detector.reset()
        # Sau reset, 9 event nữa vẫn chưa đủ ngưỡng 10 -> chứng tỏ bộ đếm đã về 0.
        assert feed(detector, events, start=100.0) == []


# ===========================================================================
# Tích hợp với đường ống
# ===========================================================================
def test_cam_duoc_vao_pipeline_va_bat_tat_duoc():
    from app.detection import DetectionPipeline

    events = [
        write_event(f"C:\\data\\dir{i % 4}\\f{i}.locked", entropy=7.96) for i in range(20)
    ]

    tat = DetectionPipeline(enable_ransomware=False, enable_ml_network=False)
    nguon_khi_tat = {d.source for e in events for d in tat.process(e, now=events.index(e) * 0.1)}
    assert "ransomware" not in nguon_khi_tat

    bat = DetectionPipeline(enable_ransomware=True, enable_ml_network=False)
    drafts = []
    for i, event in enumerate(events):
        drafts.extend(bat.process(event, now=i * 0.1))

    sources = {d.source for d in drafts}
    # Cả rule T1486 lẫn bộ phân tích hành vi đều phải lên tiếng, và chúng bổ sung
    # cho nhau: rule cho biết "có cụm", hành vi cho biết "vì sao đó là mã hoá".
    assert sources == {"rule", "ransomware"}
