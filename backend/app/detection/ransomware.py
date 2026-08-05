"""Phát hiện ransomware sớm bằng phân tích hành vi — lớp 2.

Vì sao cần bộ này khi đã có rule T1486?

Rule T1486 chỉ đếm "bao nhiêu file bị sửa trong 5 giây". Nó bắt được ransomware,
nhưng cũng kêu ầm lên khi người dùng giải nén một file zip lớn, khi trình biên
dịch ghi hàng trăm file .obj, hay khi phần mềm sao lưu chạy. Ở một SMB không có
người trực SOC, cảnh báo giả nhiều đồng nghĩa với việc cảnh báo bị bỏ qua — và
lúc đó hệ thống trở nên vô dụng.

Bộ phát hiện này chấm điểm trên **bốn tín hiệu độc lập** thay vì một:

1. **Entropy** — ransomware ghi ra dữ liệu đã mã hoá, entropy Shannon sát 8.0.
   Văn bản, mã nguồn, tài liệu Office giải nén ra đều dưới ~6.5. Đây là tín hiệu
   mạnh nhất và là lý do agent tính sẵn entropy ngay trên endpoint.
2. **Tốc độ ghi** — người dùng không sửa 30 file trong 3 giây, phần mềm thì có.
3. **Đuôi file** — ransomware đổi đuôi hàng loạt sang một đuôi lạ dùng chung.
4. **Độ lan thư mục** — ransomware quét ngang qua nhiều thư mục, còn phần lớn
   tác vụ hợp lệ chỉ làm việc trong một cây thư mục.

Điểm số là tổ hợp có trọng số của bốn tín hiệu, và **từng thành phần đều được ghi
vào bằng chứng**. Người phân tích (và lớp 3 khi tóm tắt) nhìn thấy chính xác vì
sao máy báo động — chứ không phải một con số từ hộp đen. Với một hệ thống mà
người dùng không có chuyên môn an ninh, giải thích được quan trọng ngang với
phát hiện được.
"""
from __future__ import annotations

import logging
import ntpath
import posixpath
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from .draft import AlertDraft

logger = logging.getLogger(__name__)

# --- Ngưỡng, đặt tên rõ ràng để chỉnh được mà không phải đọc lại công thức ---

# Entropy Shannon từ mức này trở lên được coi là "trông như dữ liệu đã mã hoá".
# 7.0/8.0 là ngưỡng thận trọng: dữ liệu ngẫu nhiên thật đạt ~7.99, còn văn bản
# tiếng Việt/Anh nằm quanh 4.5-5.5, mã nguồn ~5.0, tài liệu Office ~6.0.
HIGH_ENTROPY_THRESHOLD = 7.0

# Tốc độ ghi (file/giây) mà tại đó tín hiệu này đạt mức tối đa.
WRITE_RATE_SATURATION = 5.0

# Số thư mục khác nhau mà tại đó tín hiệu lan toả đạt tối đa.
DIR_SPREAD_SATURATION = 5

# Dưới ngưỡng này thì không bao giờ chấm điểm — vài file bị sửa là chuyện thường.
MIN_FILES_IN_WINDOW = 10

# Cửa sổ quan sát, tính bằng giây.
DEFAULT_WINDOW_SECONDS = 30.0

# Trọng số của bốn tín hiệu. Entropy nặng nhất vì nó là tín hiệu khó giả nhất:
# ransomware buộc phải ghi ra dữ liệu entropy cao, đó là bản chất của việc mã hoá.
WEIGHTS = {
    "entropy": 0.40,
    "write_rate": 0.25,
    "extension": 0.25,
    "dir_spread": 0.10,
}

# Ngưỡng quy đổi điểm ra mức nghiêm trọng.
SEVERITY_THRESHOLDS = [(0.85, "critical"), (0.60, "high"), (0.40, "medium")]

# Đuôi file mà các dòng ransomware phổ biến hay dùng. Danh sách này KHÔNG phải
# cơ chế phát hiện chính (dòng mới luôn dùng đuôi mới) — nó chỉ là một trong bốn
# tín hiệu, nên bỏ sót đuôi lạ vẫn không làm hỏng việc phát hiện.
KNOWN_RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".crypto", ".enc", ".cerber", ".locky",
    ".zepto", ".odin", ".wannacry", ".wncry", ".wcry", ".ryk", ".ryuk",
    ".conti", ".lockbit", ".abcd", ".djvu", ".stop", ".makop", ".phobos",
    ".mado", ".coot", ".nppp", ".vvoa", ".egregor", ".darkside", ".revil",
    ".sodinokibi", ".maze", ".sekhmet", ".doppel", ".pysa", ".avaddon",
}

# Đuôi file bản thân đã là dữ liệu nén/mã hoá. Ghi những file này ra entropy cao
# là chuyện BÌNH THƯỜNG, nên chúng bị loại khỏi tín hiệu entropy — nếu không thì
# việc chép một thư mục ảnh hay video sẽ luôn bị báo động.
NATURALLY_HIGH_ENTROPY_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".tar", ".cab",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".flac", ".m4a", ".webm",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt",
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".jar", ".apk",
}

WATCHED_EVENT_TYPES = ("file_modify", "file_create")


def _dirname(path: str) -> str:
    return ntpath.dirname(path) if "\\" in path else posixpath.dirname(path)


class _FileWrite:
    """Một lần ghi file trong cửa sổ quan sát."""

    __slots__ = ("at", "entropy", "ext", "directory", "path", "old_path", "identity")

    def __init__(
        self,
        at: float,
        entropy: Optional[float],
        ext: str,
        directory: str,
        path: str,
        old_path: Optional[str] = None,
    ):
        self.at = at
        self.entropy = entropy
        self.ext = ext
        self.directory = directory
        self.path = path
        # Đường dẫn trước khi đổi tên, nếu event này là một thao tác đổi tên.
        self.old_path = old_path
        # Danh tính ổn định của file, gán lại ở `_resolve_identity`.
        self.identity = path


def _resolve_identity(writes: List[_FileWrite]) -> None:
    """Gán cho mỗi file một danh tính ổn định, xuyên qua các lần đổi tên.

    `tai_lieu_00.txt` và `tai_lieu_00.txt.locked` là CÙNG một file — ransomware
    đổi tên chứ không tạo file mới. Đếm chúng thành hai file làm hỏng mọi tín
    hiệu dạng tỉ lệ: các event của đường dẫn cũ mang entropy của nội dung GỐC
    (chưa mã hoá), nên chúng kéo tỉ lệ "file entropy cao" xuống.

    Điều này đã đo được khi chạy demo thật: 20 file .locked đều có entropy 7.96,
    nhưng 81 event .txt của cùng những file đó (đọc trước lúc đổi tên) kéo tỉ lệ
    xuống còn 7/26 và điểm rơi từ "critical" xuống "medium".

    Ta lần theo chuỗi đổi tên: mỗi lần thấy đường dẫn cũ, mọi bản ghi của nó
    được gán về danh tính của đường dẫn mới.
    """
    identity: Dict[str, str] = {}
    for write in writes:
        if not write.old_path:
            continue
        # Đường dẫn cũ (và mọi thứ đã trỏ tới nó) giờ mang danh tính đường dẫn mới.
        root = identity.get(write.path, write.path)
        identity[write.old_path] = root
        for source, target in list(identity.items()):
            if target == write.old_path:
                identity[source] = root

    for write in writes:
        write.identity = identity.get(write.path, write.path)


def _distinct_files(writes: List[_FileWrite]) -> List[_FileWrite]:
    """Gộp nhiều event của cùng một file thành một, giữ bản có entropy cao nhất.

    Vì sao bắt buộc phải có bước này: watchdog (và các API theo dõi file của hệ
    điều hành nói chung) bắn NHIỀU sự kiện cho một lần ghi — tạo file, ghi nội
    dung, cập nhật metadata. Nhiều sự kiện trong số đó chộp đúng lúc file mới
    ghi được một phần, nên entropy đo được thấp.

    Đo trên event thô thì các tín hiệu dạng tỉ lệ bị loãng nghiêm trọng: khi
    chạy demo thật, 20 file sinh ra 86 event và tỉ lệ entropy cao tụt từ ~1.0
    xuống 0.21, kéo điểm từ mức "high" xuống sát ngưỡng báo động.

    Phát biểu đúng phải là "bao nhiêu phần trăm số FILE ghi ra có entropy cao",
    chứ không phải "bao nhiêu phần trăm số EVENT". Lấy entropy lớn nhất cho mỗi
    file chính là lấy trạng thái sau khi ghi xong.
    """
    _resolve_identity(writes)

    best: Dict[str, _FileWrite] = {}
    for write in writes:
        current = best.get(write.identity)
        if current is None:
            best[write.identity] = write
            continue
        # Giữ bản có entropy cao nhất; nếu thiếu entropy thì giữ bản mới nhất.
        if write.entropy is not None and (
            current.entropy is None or write.entropy > current.entropy
        ):
            best[write.identity] = write
        elif current.entropy is None and write.at > current.at:
            best[write.identity] = write
    return list(best.values())


class RansomwareDetector:
    """Chấm điểm hành vi ghi file theo cửa sổ trượt, gom theo tiến trình.

    Gom theo `(host, pid)` khi agent cung cấp được PID, ngược lại lùi về `host`.
    Agent tham chiếu dùng watchdog nên KHÔNG biết PID — đây chính là hạn chế đã
    ghi trong README, và là lý do agent mức kernel sẽ cải thiện đáng kể độ chính
    xác mà không cần đổi một dòng nào của bộ phát hiện này.
    """

    def __init__(
        self,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        min_files: int = MIN_FILES_IN_WINDOW,
        alert_threshold: float = 0.40,
    ):
        self.window_seconds = window_seconds
        self.min_files = min_files
        self.alert_threshold = alert_threshold
        self._windows: Dict[str, Deque[_FileWrite]] = defaultdict(deque)
        self._cooldown: Dict[str, float] = {}

    # -- Trợ giúp -----------------------------------------------------------
    @staticmethod
    def _group_key(event: dict) -> str:
        data = event.get("data", {}) or {}
        host = str(event.get("host", "unknown"))
        pid = data.get("pid")
        return f"{host}:{pid}" if pid else host

    @staticmethod
    def _severity_for(score: float) -> str:
        for threshold, severity in SEVERITY_THRESHOLDS:
            if score >= threshold:
                return severity
        return "low"

    # -- Tính bốn tín hiệu --------------------------------------------------
    def _compute_signals(
        self, raw_writes: List[_FileWrite]
    ) -> Tuple[Dict[str, float], Dict[str, object]]:
        # Mọi tín hiệu tỉ lệ được tính trên FILE riêng biệt, không trên event thô.
        writes = _distinct_files(raw_writes)
        total = len(writes)
        raw_event_count = len(raw_writes)

        # 1) Entropy — chỉ xét những file mà entropy cao là BẤT THƯỜNG.
        #    File .zip/.jpg/.mp4 vốn dĩ entropy cao nên bị loại khỏi mẫu.
        judgeable = [
            w for w in writes
            if w.entropy is not None and w.ext not in NATURALLY_HIGH_ENTROPY_EXTENSIONS
        ]
        high_entropy = [w for w in judgeable if w.entropy >= HIGH_ENTROPY_THRESHOLD]
        entropy_signal = len(high_entropy) / len(judgeable) if judgeable else 0.0

        # 2) Tốc độ ghi trong khoảng thời gian thực tế của cửa sổ.
        #    Mốc thời gian lấy từ event THÔ (đã theo thứ tự thời gian); danh sách
        #    sau khi gộp không còn giữ thứ tự nên không dùng để đo khoảng thời gian.
        span = max(raw_writes[-1].at - raw_writes[0].at, 0.001)
        write_rate = total / span
        rate_signal = min(1.0, write_rate / WRITE_RATE_SATURATION)

        # 3) Đuôi file — hai dạng: đuôi ransomware đã biết, hoặc một đuôi lạ
        #    dùng chung cho gần như mọi file (dòng mới đặt đuôi riêng của nó).
        known_ransom = sum(1 for w in writes if w.ext in KNOWN_RANSOM_EXTENSIONS)
        ext_counts: Dict[str, int] = defaultdict(int)
        for w in writes:
            if w.ext:
                ext_counts[w.ext] += 1

        uniform_unknown = 0
        if ext_counts:
            dominant_ext, dominant_count = max(ext_counts.items(), key=lambda kv: kv[1])
            is_unknown_ext = (
                dominant_ext not in NATURALLY_HIGH_ENTROPY_EXTENSIONS
                and dominant_ext not in KNOWN_RANSOM_EXTENSIONS
                and dominant_count / total >= 0.8   # gần như mọi file cùng một đuôi
                and len(ext_counts) <= 2
            )
            if is_unknown_ext:
                # BẮT BUỘC có entropy cao đi kèm. Nếu không, tín hiệu này sẽ kêu
                # mỗi khi có thao tác ghi hàng loạt hợp lệ cùng một đuôi thường —
                # giải nén zip ra 200 file .txt, trình biên dịch ghi .obj, phần
                # mềm sao lưu ghi .bak. Ransomware thì luôn kèm entropy cao, vì
                # ghi dữ liệu đã mã hoá chính là bản chất của nó.
                #
                # Hệ quả đã biết: chạy agent với --no-entropy sẽ vô hiệu hoá tín
                # hiệu này, bộ phát hiện chỉ còn tốc độ + độ lan. Rule T1486 vẫn
                # đứng đó làm lưới đỡ.
                uniform_unknown = sum(
                    1 for w in writes
                    if w.ext == dominant_ext
                    and w.entropy is not None
                    and w.entropy >= HIGH_ENTROPY_THRESHOLD
                )

        ext_signal = min(1.0, max(known_ransom, uniform_unknown) / total)

        # 4) Độ lan thư mục.
        distinct_dirs = len({w.directory for w in writes})
        spread_signal = min(1.0, max(0, distinct_dirs - 1) / DIR_SPREAD_SATURATION)

        signals = {
            "entropy": entropy_signal,
            "write_rate": rate_signal,
            "extension": ext_signal,
            "dir_spread": spread_signal,
        }
        details = {
            "files_written": total,
            # Giữ lại số event thô để thấy mức nhiễu của bộ theo dõi file. Chênh
            # lệch lớn giữa hai con số này là dấu hiệu agent đang bắn trùng nhiều.
            "raw_file_events": raw_event_count,
            "window_span_seconds": round(span, 2),
            "write_rate_per_second": round(write_rate, 2),
            "high_entropy_files": len(high_entropy),
            "entropy_judgeable_files": len(judgeable),
            "mean_entropy": (
                round(sum(w.entropy for w in judgeable) / len(judgeable), 2) if judgeable else None
            ),
            "known_ransom_extension_files": known_ransom,
            "uniform_unknown_extension_files": uniform_unknown,
            "distinct_directories": distinct_dirs,
        }
        return signals, details

    # -- API chính ----------------------------------------------------------
    def observe(self, event: dict, now: float) -> List[AlertDraft]:
        """Nạp một event ghi file và trả về cảnh báo nếu hành vi đủ đáng ngờ."""
        if event.get("event_type") not in WATCHED_EVENT_TYPES:
            return []

        data = event.get("data", {}) or {}
        file_path = str(data.get("file_path", ""))
        if not file_path:
            return []

        key = self._group_key(event)
        window = self._windows[key]
        window.append(
            _FileWrite(
                at=now,
                entropy=data.get("entropy"),
                ext=str(data.get("file_ext", "")).lower(),
                directory=_dirname(file_path),
                path=file_path,
                old_path=data.get("old_file_path"),
            )
        )

        while window and now - window[0].at > self.window_seconds:
            window.popleft()

        if len(window) < self.min_files:
            return []

        # Mỗi cửa sổ chỉ báo một lần: ransomware ghi hàng nghìn file, không thể
        # để nó sinh ra hàng nghìn cảnh báo giống hệt nhau.
        if now - self._cooldown.get(key, float("-inf")) < self.window_seconds:
            return []

        writes = list(window)
        signals, details = self._compute_signals(writes)

        # Ngưỡng phải được kiểm lại trên số FILE riêng biệt. Kiểm tra ở trên chỉ
        # đếm event thô — mà một file duy nhất bị ghi 10 lần cũng đủ vượt qua nó,
        # rồi mọi tỉ lệ sẽ được tính trên đúng một file và mất hết ý nghĩa.
        if details["files_written"] < self.min_files:
            return []

        score = sum(WEIGHTS[name] * value for name, value in signals.items())

        if score < self.alert_threshold:
            return []

        self._cooldown[key] = now
        severity = self._severity_for(score)

        evidence = {
            "score": round(score, 3),
            # Đóng góp của từng tín hiệu vào điểm cuối — đây là phần "giải thích được".
            "signals": {
                name: {
                    "value": round(value, 3),
                    "weight": WEIGHTS[name],
                    "contribution": round(WEIGHTS[name] * value, 3),
                }
                for name, value in signals.items()
            },
            "group_key": key,
            **details,
        }
        sample = [w for w in writes][:5]
        evidence["sample_files"] = [f"{w.directory}  (*{w.ext or 'khong duoi'})" for w in sample]

        logger.info(
            "Hành vi ransomware: điểm=%.2f mức=%s nhóm=%s file=%d entropy_cao=%d",
            score, severity, key, details["files_written"], details["high_entropy_files"],
        )

        return [
            AlertDraft(
                source="ransomware",
                rule_id="BEHAVIOR-ransomware-encryption",
                title=(
                    f"Hành vi mã hoá hàng loạt (điểm {score:.2f}) — "
                    f"{details['files_written']} file, "
                    f"{details['high_entropy_files']} file entropy cao"
                ),
                severity=severity,
                technique="T1486",
                technique_name="Data Encrypted for Impact",
                tactic="Impact",
                host=str(event.get("host", "")),
                evidence=evidence,
                confidence=round(score, 3),
            )
        ]

    def reset(self) -> None:
        """Xoá toàn bộ trạng thái — dùng trong test và khi nạp lại cấu hình."""
        self._windows.clear()
        self._cooldown.clear()
