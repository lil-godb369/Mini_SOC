# Kế hoạch hoàn thiện Mini_SOC

Mốc nền: `4312e81`. Phạm vi là đồ án giám sát endpoint Windows trong lab,
với FastAPI, Redis Streams, worker, PostgreSQL và dashboard cùng origin.
Tài liệu này phân biệt việc đã triển khai, đã kiểm thử tự động và đã kiểm chứng
trên máy thật. Không xem test giả lập là số liệu hiệu quả phát hiện thực tế.

## Thứ tự và tiêu chí nghiệm thu

### 1. Chốt phạm vi

- [x] Giữ luồng chính: thu thập → tiếp nhận → phát hiện → lưu → điều tra.
- [x] Chọn ML ngoại tuyến là mốc thực nghiệm trước; ML live là mốc riêng,
  chỉ nghiệm thu khi có nguồn `network_flow` và đặc trưng tương thích.
- [x] Chưa đưa scanner, honeypot, phishing, AI assistant hay tự động ứng phó
  vào tiêu chí hoàn thành lõi. Không quảng bá năng lực chưa kiểm chứng.
- [x] Giữ Python 3.9 tương thích, không thay `.venv` đang sử dụng.
- [x] Không reset DB, sửa secret hay chạy mô phỏng làm thay đổi máy khi chỉ
  kiểm thử phần mềm. Kiểm thử dùng DB tạm và fake Redis.

### 2. Độ tin cậy và vận hành

- [x] Agent idle vẫn cập nhật last_seen qua heartbeat có xác thực (test giả lập).
- [x] Key bị từ chối khiến agent dừng rõ ràng; có `--reenroll` để đăng ký lại.
  Thu hồi key không dẫn đến tự đăng ký lách thao tác quản trị.
- [x] Event của hai máy trùng PPID không bị gom chung; thiếu nhóm không tạo
  cụm giả. Giữ tương thích trường evidence hiện tại.
- [x] API xác thực hiển thị heartbeat worker, detector thực sự nạp được,
  pending/lag của nhóm; trạng thái không có dữ liệu phải là unknown.
- [x] Hàng đợi agent lưu bền trên đĩa, giới hạn dung lượng và đếm mất dữ liệu
  (kiểm thử SQLite tạm; chưa đo chi phí trên endpoint thực tế).
- [x] Định danh event và ghi idempotent; thử lại không nhân đôi bản ghi
  (kiểm thử DB tạm, bao gồm lost HTTP response/lost ACK/commit lỗi).
- [ ] Kiểm thử restart/mất mạng và ghi bằng chứng trên stack thật riêng biệt.
- [x] Dùng event time, checkpoint JSON theo host cùng transaction và giữ cooldown
  qua restart. Event ngược thứ tự được lưu và xét luật đơn nhưng bỏ tương quan.
  Chưa nghiệm thu scale nhiều worker hoặc reorder buffer.

### 3. Detection

- [x] Rule có ca dương/âm và kiểm tra evidence từ ingest tới API; xem
  `test_detection_contract.py` cùng các test tương quan/ransomware đã có.
- [ ] Kiểm chứng discovery/persistence thực tế, ghi rõ giới hạn polling.
- [x] Rà MITRE với nguồn chính thức; tách cron/scheduled task khỏi Run Key.
- [ ] Đo false positive trên tác vụ lành tính; tinh chỉnh PowerShell/credential.
- [ ] Ransomware: rename, file lặp, file nén, hoạt động chậm và nhiều thư mục.
- [ ] Công bố tiêu chí gom alert và cooldown; điểm heuristic không phải xác suất.

### 4. ML ngoại tuyến

- [ ] Kiểm tra nguồn dữ liệu thật và quyền sử dụng; không thay bằng synthetic
  rồi trình bày như kết quả thực nghiệm.
- [ ] Lưu cách chia train/test, feature schema, seed và phiên bản thư viện.
- [ ] Đánh giá precision/recall/F1/FPR, confusion matrix và hạn chế từng lớp.
- [ ] Xác minh module suy luận tương thích mô hình nhị phân/đa lớp.
- [ ] Ghi lệnh tái lập, artifact metadata và kết quả; không commit dữ liệu nặng.

### 5. Điều tra, bảo mật, vận hành và bàn giao

- [ ] Dashboard có context event, danh sách agent, ghi chú và audit trạng thái.
- [ ] Có export bằng chứng; dữ liệu không tin cậy vẫn hiển thị an toàn.
- [ ] Kiểm thử phân quyền, giới hạn đăng nhập/enroll và cấu hình secret.
- [ ] Hướng dẫn TLS, giới hạn cổng DB/Redis và quyền file key Windows.
- [ ] Migration không mất dữ liệu, retention, backup và thử restore.
- [ ] Đo tài nguyên agent, throughput, độ trễ event→alert với điều kiện đo rõ.
- [ ] Đồng bộ README/báo cáo; demo có thể lặp lại và có bước hoàn tác.

## Quy tắc ghi nhận kết quả

Chỉ đánh dấu hoàn thành khi có bằng chứng tương ứng. Mã nguồn có sẵn không
đồng nghĩa đã thử trên máy thật. Mỗi đợt thay đổi ghi phạm vi, lệnh kiểm tra,
kết quả và phần chưa giải quyết. Không commit/push tự động trong kế hoạch này.

## Các đợt thực hiện

1. Heartbeat, phục hồi đăng ký có chủ đích, cách ly tương quan theo host,
   quan sát worker; kiểm thử hồi quy trước khi thay đổi tiếp.
2. Lưu bền và idempotency, phương án thời gian/state; kiểm thử lỗi.
3. Detection và thực nghiệm ML; sau đó dashboard, bảo mật và bàn giao.

Đợt 1 đã triển khai và có test hồi quy cho heartbeat, key bị thu hồi,
đăng ký lại có chủ đích, ghi state lỗi, tách host và API quan sát worker.
Hướng dẫn và giới hạn: [OPERATIONS.md](OPERATIONS.md).
Chưa deploy stack live, chạy attack simulation, commit hoặc push trong đợt này.

Kết quả kiểm tra đợt 1: **165 passed** trên Python 3.9, gồm backend, ML và
agent; dùng SQLite tạm, Redis giả và mock HTTP. `git diff --check` thành công.
Lệnh tái lập trên Windows không thay `.venv` hiện có:

```powershell
uv run --no-project --python .venv/Scripts/python.exe --with greenlet==3.1.1 --with-requirements backend/requirements.txt --with-requirements agent/requirements.txt --with-requirements ml/requirements.txt python -m pytest
```

Pin greenlet ở lệnh kiểm thử để tránh build bản 3.2.5 trên Windows/Python 3.9
khi máy không có Visual C++ Build Tools. Đây chưa phải thay đổi dependency
production.

Đợt 2 bổ sung SQLite spool có giới hạn, scope theo server/key, UUID ổn định,
quarantine partial rejection và ledger chống ghi trùng trong cùng transaction.
Worker rollback state detector khi commit lỗi. Notification stream sau commit
vẫn best effort; state tương quan qua restart và thời gian backlog còn phải xử lý.
Chưa deploy hoặc thay đổi schema của database live trong đợt này.

Kết quả đợt 2: **181 passed** trên Python 3.9, cùng lệnh tái lập ở trên.
Bao gồm test tiến trình con `os._exit` sau append, restart sender/mất mạng,
lost HTTP response, lost Redis ACK, partial rejection, giới hạn lưu, lỗi đĩa,
đổi key và rollback state khi commit lỗi. `git diff --check` thành công.
Đây là kiểm thử lỗi có kiểm soát; chưa phải diễn tập trên stack live.

Đợt 3: **186 pytest passed** trên Python 3.9; bài Docker PG/Redis thật **PASS**
cho restart worker process, pending reclaim, UID retry, cooldown, checkpoint
ransomware và slow backlog. Xem [tests/integration/README.md](../tests/integration/README.md).
Stack kiểm thử độc lập đã được dọn sau khi chạy. Chưa triển khai lên stack chính,
chưa kiểm chứng mất mạng vật lý/Windows collector hoặc tải nhiều worker.

Đợt 4 detection: **210 pytest passed**, Docker integration **PASS**. Có 7 rule;
thu hẹp PowerShell/credential, tách persistence đúng mapping, yêu cầu process
enumeration khi phát T1057, hạ rule đếm file về Medium. Không sửa alert lịch sử.
Dry-run persistence đã sửa kỳ vọng, không tạo persistence thật trong đợt này.
Chi tiết và nguồn MITRE: [DETECTION.md](DETECTION.md). Đánh giá FPR trên dữ liệu
đại diện và collector live vẫn chưa hoàn tất; không xem fixture như thực nghiệm.
