# Mini-SOC — Báo cáo kỹ thuật

**Đề tài:** Nền tảng giám sát và phòng thủ an ninh mạng tích hợp AI cho doanh nghiệp vừa và nhỏ
**Tác giả:** Trần Ngọc Đăng Khoa — Sinh viên An ninh hệ thống, HUIT
**Mã nguồn:** https://github.com/lil-godb369/Mini_SOC

---

## 1. Tóm tắt

Mini-SOC là một hệ thống giám sát an ninh (SOC) thu nhỏ, hướng tới doanh nghiệp vừa và nhỏ
(SMB) — nhóm chiếm phần lớn doanh nghiệp nhưng gần như không có ngân sách cho một trung tâm
SOC truyền thống. Hệ thống triển khai đầy đủ một vòng đời phát hiện xâm nhập:

```
THU THẬP → PHÁT HIỆN → ĐÁNH GIÁ → CẢNH BÁO
```

Ba bộ phát hiện độc lập cùng tồn tại trong lớp 2: **rule engine ánh xạ MITRE ATT&CK**,
**mô hình học máy trên lưu lượng mạng**, và **bộ phát hiện hành vi ransomware**. Cả ba đều
phát ra cùng một cấu trúc cảnh báo (`AlertDraft`), nhờ đó tầng trình bày và tầng thông báo
không phải biết cảnh báo đến từ đâu.

**Kết quả:** 152 test tự động chạy trong ~25 giây, không cần cơ sở dữ liệu hay hạ tầng ngoài;
toàn bộ nền tảng khởi động bằng một lệnh `docker compose up`.

---

## 2. Bối cảnh và mục tiêu

### 2.1 Vấn đề

Một SOC truyền thống gồm SIEM, log management, EDR, SOAR — chi phí giấy phép và nhân sự
thường vượt xa năng lực của doanh nghiệp dưới 200 nhân sự. Hệ quả là nhóm này thường chỉ có
tường lửa và phần mềm diệt virus, không có khả năng phát hiện xâm nhập có chủ đích.

### 2.2 Mục tiêu

| Mục tiêu | Tiêu chí đo |
|---|---|
| Nhẹ | Chạy trọn trên máy 4 nhân, ~2 GB RAM, không GPU |
| Chi phí thấp | Toàn bộ thành phần mã nguồn mở, không phí giấy phép |
| Phát hiện được tấn công thật | Chứng minh bằng kịch bản mô phỏng ATT&CK |
| Dễ triển khai | Một lệnh `docker compose up`, không cần cấu hình phức tạp |
| Kiểm chứng được | Bộ test chạy được mà không cần hạ tầng |

### 2.3 Yêu cầu phi chức năng

- Mỗi bộ phát hiện **bật/tắt độc lập** (do SMB có nhu cầu khác nhau).
- Lõi phát hiện **không phụ thuộc cơ sở dữ liệu** để có thể kiểm thử độc lập.
- Mọi cảnh báo phải mang **kỹ thuật ATT&CK, mức độ nghiêm trọng và bằng chứng** đi kèm.

---

## 3. Kiến trúc

Hệ thống chia 6 lớp, trong đó lớp 1–2 là phần đã hoàn thiện:

| Lớp | Chức năng | Trạng thái |
|---|---|---|
| 1 | Thu thập: agent endpoint (process, file, network, registry) | ✅ |
| 2 | Phát hiện: rule ATT&CK + ML mạng + hành vi ransomware | ✅ |
| 3 | Trợ lý AI: tóm tắt cảnh báo, ẩn danh hoá trước khi gọi LLM | ⬜ |
| 4 | Quét chủ động: SQLi/XSS, security header | ⬜ |
| 5 | Honeypot: SSH/HTTP giả | ⬜ |
| 6 | Con người: phát hiện và mô phỏng phishing | ⬜ |

### 3.1 Luồng dữ liệu

```
Agent (máy được giám sát)
   │  JSON + API key, qua HTTPS
   ▼
FastAPI /api/v1/ingest
   │  XADD
   ▼
Redis Stream  ──►  Worker (consumer group, ACK)
                      │
                      ▼
                DetectionPipeline
                ├── RuleEngine (5 rule ATT&CK)
                ├── Correlator (N event / X giây)
                ├── RansomwareDetector (entropy + IO)
                └── ML network (RandomForest / IsolationForest)
                      │  AlertDraft
                      ▼
                PostgreSQL (JSONB)
                      │
                      ▼
        FastAPI /api/v1/alerts  ──►  Dashboard / Telegram / Webhook
```

### 3.2 Quyết định kiến trúc

**PostgreSQL JSONB thay vì Elasticsearch.** Elasticsearch cần khoảng 2 GB JVM heap — mâu
thuẫn trực tiếp với mục tiêu "nhẹ cho SMB". Với quy mô vài triệu event, JSONB kèm index
BRIN là đủ và tiết kiệm hơn một bậc về RAM.

**Redis Streams thay vì Kafka.** Kafka cần trên 1 GB RAM và phải vận hành riêng. Redis
Streams cung cấp đúng những gì đồ án cần — consumer group, ACK, lưu bền — trong khoảng 50 MB.

**Một image dùng chung cho `api` và `worker`.** Hai service chỉ khác lệnh chạy. Dùng chung
image loại bỏ hoàn toàn nguy cơ lệch phiên bản giữa hai bên, vì worker cần đúng module
phát hiện mà API đang dùng.

---

## 4. Thiết kế chi tiết lớp phát hiện

### 4.1 Rule engine và định dạng rule

Rule được viết bằng YAML, tách hoàn toàn khỏi mã nguồn. Một rule gồm: định danh kỹ thuật
ATT&CK, tactic, mức độ nghiêm trọng, loại event áp dụng, và điều kiện khớp.

Hai kiểu logic:

- `single` — một event là đủ (ví dụ: dòng lệnh PowerShell chứa `-enc` hoặc `downloadstring`).
- `threshold` — cần N event trong X giây (ví dụ: cụm lệnh do thám, hàng loạt file bị mã hoá).

**5 rule hiện có:**

| Rule | Kỹ thuật | Tactic | Mức độ |
|---|---|---|---|
| Suspicious PowerShell | T1059.001 | Execution | high |
| Discovery command cluster | T1057 | Discovery | medium |
| Credential access | T1003 | Credential Access | high |
| Persistence via autostart | T1547.001 | Persistence | high |
| Ransomware file encryption | T1486 | Impact | critical |

### 4.2 Correlator — phát hiện có trạng thái

Kỹ thuật như T1057 hay T1486 chỉ đáng ngờ khi xuất hiện **thành cụm**. Correlator giữ một
cửa sổ trượt riêng cho mỗi cặp (rule, nhóm), với nhóm xác định qua trường `group_by`
(PID cha, tên tiến trình, host…).

Hai cải tiến so với bản gốc PyEDR:

1. **Đồng hồ được tiêm vào** qua tham số `now` thay vì gọi `time.monotonic()` bên trong.
   Nhờ vậy unit test kiểm được chính xác ranh giới cửa sổ mà không phải `sleep`, và khi
   phát lại pcap/log cũ thì tương quan vẫn đúng theo thời gian của dữ liệu.
2. **Giới hạn kích thước state** (`MAX_TRACKED_GROUPS = 50 000`): một máy bị tấn công có thể
   sinh ra hàng nghìn giá trị nhóm (mỗi PID một nhóm), nên nhóm im lặng quá lâu bị dọn để
   không rò rỉ bộ nhớ.

### 4.3 Phát hiện hành vi ransomware

Không dựa vào chữ ký — điều đó vô dụng với ransomware biến thể mới. Thay vào đó dùng bốn
tín hiệu hành vi:

1. **Entropy nội dung file** — file bị mã hoá có entropy gần mức tối đa.
2. **Tốc độ ghi** — số file bị sửa trong một đơn vị thời gian.
3. **Phần mở rộng file** — xuất hiện đuôi lạ hàng loạt.
4. **Độ lan thư mục** — số thư mục khác nhau bị ảnh hưởng.

Điểm mấu chốt: rule T1486 **gom theo host, không theo PID**, vì `watchdog` cho biết file nào
bị đổi nhưng không cho biết tiến trình nào gây ra.

### 4.4 Mô hình học máy trên lưu lượng mạng

Đường ống huấn luyện tách khỏi image backend: `ml/train.py` chạy trên máy dev, sinh artifact
rồi mount **chỉ đọc** vào worker. Nguyên tắc: worker không bao giờ được phép ghi đè lên mô
hình đã huấn luyện.

Ba thuật toán được so sánh: RandomForest, XGBoost, IsolationForest. Dữ liệu CIC-IDS2017 được
chia **theo ngày** chứ không chia ngẫu nhiên — vì chia ngẫu nhiên sẽ để rò rỉ dữ liệu của
cùng một phiên tấn công vào cả tập train lẫn tập test, làm điểm số bị thổi phồng.

### 4.5 Một cấu trúc cảnh báo duy nhất

Mọi bộ phát hiện trả về `AlertDraft`, gồm: rule/nguồn, kỹ thuật ATT&CK, tactic, mức độ,
bằng chứng (các trường có ích cho người phân tích), và thời điểm.

Nhờ vậy khi bổ sung lớp 5 (honeypot) hay lớp 4 (quét lỗ hổng), tầng dashboard và tầng thông
báo **không phải sửa một dòng nào**.

---

## 5. Bảo mật của chính hệ thống

Một công cụ bảo mật mà bản thân không bảo mật thì không có giá trị. Các quyết định:

| Thành phần | Cơ chế | Lý do |
|---|---|---|
| Mật khẩu người dùng | Argon2id | Mật khẩu entropy thấp cần hàm băm chậm, có muối |
| API key của agent | SHA-256 | Key ngẫu nhiên 256-bit; cần băm tất định để tra cứu qua index |
| Phiên đăng nhập | JWT (HS256) | Không lưu trạng thái phiên ở server |
| Đăng ký agent | Token enrol dùng một lần | Agent nhận API key riêng sau lần đăng ký đầu |
| Bí mật cấu hình | Biến môi trường, `.env` nằm trong `.gitignore` | Không có bí mật nào trong mã nguồn |

---

## 6. Kiểm thử

### 6.1 Chiến lược

Nguyên tắc: **bộ test nào đòi hạ tầng mới chạy được thì rốt cuộc sẽ không ai chạy.** Vì vậy:

- SQLite tạm thay cho PostgreSQL.
- Redis giả (in-memory) thay cho Redis thật.
- Dữ liệu tổng hợp có **cùng hình dạng, kể cả cùng lỗi**, với dữ liệu thật.

### 6.2 Kết quả

```
152 passed in 23.24s
```

| Nhóm test | Nội dung |
|---|---|
| `test_detection.py` | Rule engine, correlator, ranh giới cửa sổ |
| `test_ransomware.py` | Entropy, tốc độ ghi, độ lan thư mục |
| `test_ml_network.py` | Tiền xử lý, suy luận, ngưỡng cảnh báo |
| `test_api.py` | Xác thực, phân quyền, các endpoint |
| `test_e2e_flow.py` | Từ ingest → phát hiện → cảnh báo |
| `test_collectors.py` | Bộ thu thập của agent |
| `test_preprocess.py` | Đường ống huấn luyện ML |

CI (GitHub Actions) chạy lại toàn bộ trên mỗi lần push, kèm một job `compileall` để bắt lỗi
cú pháp trên mọi tệp nguồn.

---

## 7. Hạn chế và đánh giá trung thực

Đây là phần quan trọng nhất khi bảo vệ: **những điểm dưới đây đã được đo, không phải phỏng đoán.**

1. **Thăm dò tiến trình theo chu kỳ bỏ sót tiến trình sống ngắn.** Đo được khi chạy demo
   thật: trong 6 lệnh do thám, agent chỉ bắt được `tasklist` và `systeminfo`; `whoami`,
   `hostname`, `ipconfig`, `net` sống dưới 100 ms nên lọt qua khe giữa hai lần quét. Rule
   T1057 cần 4 tiến trình nên **không kích hoạt**. Giảm nhẹ bằng `--poll-interval 0.25`,
   nhưng chỉ agent mức kernel (ETW/eBPF) mới bảo đảm không bỏ sót.

2. **Rule T1486 gom theo host**, nên giải nén một file zip lớn có thể tạo cảnh báo giả.
   Lớp entropy của Tuần 2 giảm thiểu việc này.

3. **Rule T1003 chỉ dựa trên dòng lệnh**, nên né được bằng cách đổi tên tệp thực thi. Phát
   hiện đáng tin cậy cần telemetry mở handle tới `lsass.exe`.

4. **Dùng `create_all` thay vì Alembic migration.** Chấp nhận được khi schema còn mới; lên
   production phải đổi.

5. **Docker Desktop trên Windows không bắt được lưu lượng mạng thật của host** (container
   chạy trong VM WSL2). Lớp 2 demo bằng phát lại pcap.

6. **Bộ theo dõi file bắn nhiều event cho một lần ghi**: 20 file bị mã hoá sinh 29–86 event.
   Đã gộp theo danh tính file nhưng đây vẫn là nguồn nhiễu vốn có của theo dõi tầng người dùng.

7. **Mô hình ML mạng chưa có số liệu thực nghiệm.** Đường ống huấn luyện đã chạy đầu-cuối
   nhưng mới trên dữ liệu tổng hợp. Mọi con số trong báo cáo phải chạy lại trên CIC-IDS2017 gốc.

### 7.1 Bài học

Hạn chế số 1 là bài học lớn nhất của đồ án: **thiết kế đúng trên giấy không đủ**. Rule T1057
được viết đúng, test đơn vị đều xanh, nhưng khi chạy trên máy thật nó không kích hoạt vì giả
định "agent nhìn thấy mọi tiến trình" là sai. Chỉ có chạy demo thật mới phát hiện ra.

---

## 8. Hướng phát triển

| Ưu tiên | Hạng mục |
|---|---|
| Cao | Dashboard React realtime qua SSE — hiện chưa có giao diện |
| Cao | Lớp 3: trợ lý AI tóm tắt cảnh báo tiếng Việt, có ẩn danh hoá dữ liệu |
| Trung bình | Agent mức kernel (ETW trên Windows) để không bỏ sót tiến trình ngắn |
| Trung bình | Chạy lại mô hình ML trên CIC-IDS2017 gốc và công bố số liệu |
| Thấp | Alembic migration, honeypot, quét lỗ hổng web |

---

## 9. Kết luận

Mini-SOC chứng minh rằng một hệ phát hiện xâm nhập có ích **không cần** Elasticsearch, Kafka
hay GPU. Ba bộ phát hiện độc lập, một cấu trúc cảnh báo chung, và một bộ test chạy được
trong 25 giây là đủ để tạo ra một vòng lặp phát hiện hoàn chỉnh.

Giá trị lớn nhất của đồ án không nằm ở số tính năng, mà ở chỗ **các hạn chế đã được đo và
ghi lại trung thực** — bao gồm một rule không hoạt động như thiết kế. Đó là khác biệt giữa
một đồ án demo và một hệ thống có thể đánh giá được.
