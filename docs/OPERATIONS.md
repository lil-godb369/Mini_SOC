# Vận hành agent và quan sát worker

## Heartbeat và thu hồi key

Agent mới gọi `POST /api/v1/agents/heartbeat` ngay khi luồng gửi bắt đầu,
sau đó khoảng 60 giây một lần. Request dùng `X-API-Key`; không tạo event giả
và không tăng số event. Mất mạng/backoff có thể làm chu kỳ dài hơn.
`last_seen` thể hiện liên lạc có xác thực; dashboard coi agent online trong
5 phút. API phải được cập nhật trước agent để có endpoint heartbeat.

Khi ingest hoặc heartbeat trả 401, agent dừng collector và kết thúc với mã 4.
Không tự enroll lại: một agent bị quản trị viên thu hồi không được tự trở lại.
Kiểm tra nguyên nhân (thu hồi hay reset DB) trước khi cấp lại quyền.

Sau reset DB, dùng token enroll hợp lệ từ cấu hình local. Truyền token qua
`MINISOC_ENROLL_TOKEN` được cấp trong môi trường chạy; không chép giá trị bí mật
vào tài liệu, issue hoặc command được chia sẻ. Từ thư mục `agent`:

```powershell
uv run --no-project --python ..\.venv\Scripts\python.exe python -X utf8 -m mini_soc_agent.agent --server http://127.0.0.1:8000 --watch-dir ..\sandbox --poll-interval 0.25 --reenroll
```

`--reenroll` yêu cầu token, bỏ qua key lưu trước đó và chỉ thay state local sau
khi đăng ký thành công. Nó tạo bản ghi agent mới, KHÔNG tự thu hồi bản ghi cũ.
Nếu DB chưa reset, quản trị viên cần vô hiệu hóa bản ghi cũ qua API quản lý
agent. Key mới lưu vào file tạm cùng thư mục rồi thay thế nguyên tử; ghi lỗi
không làm mất file state cũ. Một lần enroll thành công trên server nhưng ghi
state thất bại vẫn có thể để lại bản ghi cần thu hồi thủ công.

State mới có `server_url`: agent từ chối dùng nhầm với server khác. State cũ
chưa có trường này vẫn đọc được để tương thích; dùng file riêng cho mỗi server.
`--state-file` cho phép chỉ định đường dẫn. Quyền ACL Windows vẫn cần được
siết khi triển khai; `chmod` không thay thế việc đó.

## Worker và hàng đợi

`GET /api/v1/stats/worker` yêu cầu JWT của người dùng dashboard.

- `status=observed`: có ít nhất một heartbeat worker chưa hết TTL 90 giây.
  Đây không phải cam kết mọi detector hoặc luồng dữ liệu đều khỏe.
- `status=unknown`: chưa có worker mới được quan sát hoặc heartbeat đã hết hạn.
- `workers[].detectors`: module thực sự được khởi tạo trong worker, bao gồm
  trường hợp cấu hình bật ML nhưng không nạp được mô hình.
- `acknowledged_messages`: số message đã ACK trong vòng đời tiến trình,
  gồm cả message hỏng bị loại; không phải số event hợp lệ.
- `last_batch_at`: thời điểm gần nhất có lô message được ACK; null khi chưa có.
- `queue.length`: chiều dài stream còn được Redis giữ, gồm cả message đã ACK.
- `queue.pending`: đã giao cho consumer nhưng chưa ACK.
- `queue.lag`: message chưa được giao cho nhóm; là số lượng, không phải độ trễ
  tính theo giây. Null nghĩa chưa có hoặc Redis không cung cấp số liệu.
- HTTP 503: không đọc được quan sát; không lộ chi tiết kết nối nội bộ.

Worker công bố quan sát mỗi vòng đọc (thông thường khoảng 2 giây lúc idle).
Nếu ghi quan sát thất bại nhưng stream vẫn dùng được, phát hiện vẫn tiếp tục.
`/health` chỉ kiểm tra API/DB/Redis; không thay thế endpoint này.

## Lưu bền event và gửi lại

Agent mới ghi SQLite trước khi `send()` trả về, tại
`<state-file>.spool.sqlite3` (mặc định cạnh `agent.json`). Không lưu API key
trong spool, nhưng payload có thể chứa thông tin nhạy cảm về máy; bảo vệ thư
mục bằng ACL Windows. Đừng commit/chia sẻ file này.

- Tối đa 20.000 dòng và 64 MiB payload; file DB giới hạn 32.768 page (với
  page mặc định 4 KiB là 128 MiB). File journal cần thêm dung lượng tạm.
- Khi đầy, giữ dữ liệu cũ, bỏ event mới và tăng `dropped_full` lưu bền.
- SQLite commit đồng bộ có I/O trên collector; mạng vẫn chạy ở luồng gửi riêng.
  Không còn cam kết collector hoàn toàn không chặn. Cần đo chi phí ở bước hiệu năng.
- Mỗi event được gán `event_uid` UUID một lần trước commit. Retry giữ ID đó.
- Hàng đợi được chia scope theo server và key. Sau reenroll, dữ liệu scope cũ
  được giữ nhưng KHÔNG tự gửi bằng key mới. Dữ liệu đó vẫn chiếm giới hạn lưu.
- HTTP lỗi, mất mạng, phản hồi sai hoặc 401 không xóa event đã commit.
- HTTP 200 hợp lệ: xóa các event server chấp nhận; các event bị từ chối được
  đánh dấu quarantine và giữ payload để điều tra, không retry vô hạn.
- API trả `rejected_indices` để xác định đúng vị trí bị từ chối. Nếu API cũ
  trả partial rejection không có indices, agent giữ nguyên lô để tránh mất dữ liệu.
- Chính sách timestamp hiện vẫn ±1 giờ. Event offline lâu hơn có thể bị từ
  chối và quarantine; lưu bền KHÔNG đồng nghĩa được ingest bất kể tuổi dữ liệu.
- Schema sai gây HTTP 422 sẽ giữ lô để sửa nguyên nhân, chưa tự sửa payload.
- Lỗi ghi/đọc spool khiến agent dừng với mã 5. Event chưa commit khi ổ đĩa
  hỏng hoặc tiến trình chết giữa thao tác ghi không được bảo đảm giữ lại.

Xem số lượng, không gửi HTTP hay in key (từ thư mục `agent`):

```powershell
uv run --no-project --python ..\.venv\Scripts\python.exe python -m mini_soc_agent.agent --server http://127.0.0.1:8000 --spool-status
```

`pending` là scope đang chọn, `retained_other_scope` là dòng chờ của scope
khác, `quarantined` là dòng bị từ chối trên mọi scope. Các dòng quarantine và
scope cũ cần được kiểm tra/xuất trước khi dọn; chưa có tự động xóa/retention.

## Chống ghi trùng ở worker

API giữ `event_uid`. Worker ghi bảng mới `processed_messages` cùng transaction
với event/alert, trước khi ACK Redis. Startup `init_db()` tạo thêm bảng, không
thay hoặc xóa cột/bản ghi cũ. Cần triển khai API trước agent mới để API không
bỏ trường `event_uid` hoặc thiếu thông tin partial acknowledgement.

- Có UID: khóa idempotency là `(agent_id, event_uid)`, kể cả hai message Redis
  khác nhau. UID phải duy nhất cho mỗi quan sát; cùng UID nhưng payload khác
  vẫn coi là retry, bản commit đầu tiên thắng.
- Agent cũ không UID: chống phát lại cùng Redis stream/message ID; không chống
  một HTTP request được gửi lại thành message mới.
- Ghi lỗi: rollback cả lô và phục hồi state detector trong RAM trước khi retry.
- Gửi notification stream lỗi sau commit: vẫn ACK vì event/alert đã ở DB;
  dashboard polling vẫn đọc được. Notification stream hiện best effort,
  chưa có transactional outbox đảm bảo giao thông báo.
- Dữ liệu đã tồn tại trước ledger không được tự dò và gộp trùng ngược lại.
- Ledger tăng theo số event; chưa có retention. Xóa ledger trong khi còn retry
  sẽ làm mất khả năng chống trùng tương ứng.

Không tuyên bố exactly-once toàn hệ thống: Redis AOF, stream trimming, phần cứng
lưu trữ và dữ liệu chưa commit vẫn có giới hạn riêng.

## Checkpoint và thời gian event

Worker mới dùng `event.timestamp` (epoch giây) thay vì tốc độ đọc hàng đợi.
Các event cách nhau 20 giây không bị tính thành cụm 15 giây dù xử lý sát nhau.

Bảng mới `detection_states` lưu JSON theo host, gồm cửa sổ rule, file write
đang quan sát, cooldown và watermark. Checkpoint, event, alert và receipt được
commit cùng transaction. Worker mới đọc lại checkpoint; không dùng pickle.
PG khóa dòng host khi cập nhật. Thay đổi rule/cấu hình detector làm reset phần
state không tương thích qua fingerprint; watermark vẫn được giữ. Khi thay đổi
thuật toán/định dạng state, cần tăng `checkpoint.VERSION`.

Watermark là timestamp lớn nhất đã xử lý trên host. Event cũ hơn watermark:

- Vẫn lưu event, vẫn chạy rule một-event và ML nếu có.
- Không cộng vào cửa sổ rule ngưỡng/ransomware, không lùi watermark/cooldown.
- Có `data._soc_timing` ghi nhận `late` và `stateful_skipped` để điều tra.
- Chấp nhận timestamp bằng watermark, vì một lô có thể có cùng timestamp.

Đây là chính sách không chờ event đến muộn. Có thể bỏ sót tương quan khi agent
gửi lệch thứ tự hoặc clock nhảy; không khẳng định đã giải quyết mọi trường hợp
out-of-order. Chính sách ingest ±1 giờ vẫn giữ nguyên. Checkpoint được dọn theo
event-time, không tự xóa vì worker tạm dừng, để còn xử lý backlog hợp lệ.

## Giới hạn còn lại

- Chưa chứng minh phân phối nhiều worker đồng thời, reorder buffer hoặc load
  cao. Chỉ dùng một worker cho demo; kiểm thử restart không chứng minh scale.
- Checkpoint/ledger chưa có retention; dữ liệu có thể tăng theo số host/event.
- Checkpoint khôi phục fail-closed nếu dữ liệu hỏng; cần kiểm tra lỗi thay vì
  bỏ checkpoint thủ công, vì có thể làm mất lịch sử cửa sổ/cooldown.
- Nhóm tương quan giờ có host và không gom event thiếu trường group_by.
  Evidence `group_value` giữ giá trị gốc để tương thích API.
- Quan sát worker cần Redis cho phép SET/GET/SCAN cùng các lệnh stream.
- Có test SQLite/fake Redis và test Docker PG/Redis riêng. Bài Docker dùng
  subprocess worker qua transaction thật; chưa chạy Windows collector thực,
  lỗi mạng vật lý hay kill daemon giữa lúc commit.

Kế hoạch và tiêu chí đầy đủ: [KE-HOACH-HOAN-THIEN.md](KE-HOACH-HOAN-THIEN.md).
