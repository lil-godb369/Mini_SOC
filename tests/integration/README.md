# Kiểm chứng độ tin cậy trên PostgreSQL/Redis thật

Từ repo root, Docker Desktop đang chạy:

```powershell
docker compose -p minisoc-reliability -f tests/integration/compose.yml run --build --rm verify
docker compose -p minisoc-reliability -f tests/integration/compose.yml down
```

Stack chỉ có dữ liệu kiểm thử trong tmpfs, không mở cổng host, không đọc `.env`
và không mount volume của stack chính. Các chuỗi xác thực trong compose là
giá trị công khai chỉ dùng cho stack tạm này. Không dùng cấu hình này để deploy.
`down` hủy dữ liệu kiểm thử và cần được chạy sau mỗi lần thử trước khi chạy lại.

Kiểm chứng:

1. FastAPI qua TestClient → Redis → worker subprocess → PG.
2. Worker commit 3 event rồi tiến trình kết thúc mà chưa ACK; XAUTOCLAIM giao
   lại cho consumer khác, không tăng số event/alert.
3. Event thứ 4 ở interpreter mới kích hoạt rule từ checkpoint; retry UID và
   event thứ 5 không tạo alert lặp vì cooldown đã lưu.
4. 9 file ở tiến trình trước + file thứ 10 ở tiến trình mới tạo alert hành vi.
5. Các event cách nhau 20 giây xử lý nhanh không kích hoạt rule burst.
6. API thống kê đọc được pending bằng 0 từ Redis thật.
7. Ca dương/âm PowerShell, Run key, scheduled task, cron và credential đi qua
   API → Redis → subprocess → PG → API evidence, không thực thi lệnh trong payload.

Kết quả đã chạy: **PASS**, 2026-11-10. Bộ pytest Python 3.9: **210 passed**.
Không coi bài này là kiểm chứng Windows collector, socket HTTP thực, mất điện,
khả năng phát hiện ransomware thực tế hoặc scale nhiều worker. Không thay đổi
deployment chính, không reset DB demo.
