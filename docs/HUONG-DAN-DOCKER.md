# Hướng dẫn Docker cho Mini-SOC

> Đây là hướng dẫn **vận hành hàng ngày**: bật, kiểm tra, debug, tắt.
> Nếu máy bạn chưa cài Docker, đọc [`cai-dat-docker.md`](cai-dat-docker.md) trước.

Toàn bộ lệnh dưới đây chạy trong thư mục dự án:

```powershell
cd "D:\Code\System Sercurity\mini-soc"
```

---

## 1. Docker là gì (hiểu trong 30 giây)

| Khái niệm | Ví dụ dễ hiểu |
|---|---|
| **Image** | Cái khuôn / bộ cài đã đóng gói sẵn. Giống file `.exe` nhưng chứa cả một hệ điều hành mini |
| **Container** | Một tiến trình **đang chạy** từ image đó. Giống lúc bạn bấm `.exe` |
| **Volume** | Ổ cứng riêng của container. Xóa container thì **dữ liệu vẫn còn** |
| **Compose** | File `docker-compose.yml` mô tả nhiều container chạy chung thành một hệ |

Khác với máy ảo: container **không** khởi động cả một Windows/Linux riêng — nó dùng
chung nhân của máy bạn, nên nhẹ hơn hàng chục lần.

---

## 2. Stack của dự án gồm những gì

```
docker-compose.yml
├── postgres   → CSDL: users / agents / events / alerts      (cổng 5432)
├── redis      → hàng đợi event (Redis Streams)              (cổng 6379)
├── api        → FastAPI: nhận event, trả cảnh báo           (cổng 8000)
└── worker     → vòng lặp phát hiện: rule + ML + ransomware  (không mở cổng)
```

Luồng chạy:

```
Agent (máy thật)  --HTTP-->  api  --XADD-->  redis  -->  worker  -->  postgres
                                                                        ↑
                                              api đọc cảnh báo từ đây --┘
```

**Vì sao `worker` không có cổng?** Vì nó không nhận kết nối từ ngoài — nó chỉ **hút**
event từ Redis rồi ghi kết quả vào Postgres.

**Vì sao `api` và `worker` dùng chung một image?** Hai service chỉ khác lệnh chạy.
Dùng chung image loại bỏ hoàn toàn nguy cơ lệch phiên bản, vì worker cần đúng module
phát hiện mà API đang dùng.

---

## 3. Sáu lệnh phải thuộc

| Lệnh | Làm gì | Khi nào dùng |
|---|---|---|
| `docker compose up -d` | Bật toàn bộ stack, chạy nền | Mỗi lần mở máy |
| `docker compose ps` | Xem container nào đang chạy | Kiểm tra trước khi demo |
| `docker compose logs -f worker` | Xem log realtime của worker | Khi cảnh báo không hiện |
| `docker compose stop` | Tắt nhưng **giữ dữ liệu** | Hết giờ làm |
| `docker compose start` | Bật lại từ trạng thái đã tắt | Hôm sau |
| `docker compose down` | Xóa container (giữ volume) | Khi cần làm lại cấu hình |

Thêm một lệnh **nguy hiểm**, chỉ dùng khi thật sự muốn xóa sạch:

```powershell
docker compose down -v      # ⚠️ -v = xóa luôn CSDL, mất hết event/alert
```

---

## 4. Quy trình làm việc hàng ngày

### Bước 1 — Bật Docker Desktop

Đợi góc dưới trái hiện **Engine running**. Nếu chưa bật, mọi lệnh sẽ báo:

```
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
```

### Bước 2 — Bật stack

```powershell
docker compose up -d
```

### Bước 3 — Kiểm tra "khỏe"

```powershell
docker compose ps
```

Cột `STATUS` phải ghi `Up (healthy)`. Nếu chỉ ghi `Up` hoặc `restarting`, xem log:

```powershell
docker compose logs --tail 50 api
```

### Bước 4 — Kiểm tra API sống

```powershell
curl http://127.0.0.1:8000/health
```

Kết quả đúng:

```json
{"status":"ok","version":"0.1.0","checks":{"api":"ok","database":"ok","redis":"ok"}}
```

### Bước 5 — Làm việc

Mở <http://127.0.0.1:8000/docs> để xem API tự sinh (Swagger UI).

### Bước 6 — Tắt

```powershell
docker compose stop
```

---

## 5. Bốn chỗ cần "chui vào" để debug

```powershell
# Xem log worker (nơi phát hiện chạy)
docker compose logs -f worker

# Vào thẳng PostgreSQL bằng SQL
docker compose exec postgres psql -U minisoc -d minisoc
#   rồi gõ:  select count(*) from alerts;      \q để thoát

# Vào Redis xem hàng đợi
docker compose exec redis redis-cli
#   rồi gõ:  XLEN minisoc:events

# Vào trong container API (shell)
docker compose exec api sh
```

> `exec` = "chạy một lệnh bên trong container **đang chạy**".
> Khác `docker compose run` — lệnh đó tạo container **mới**.

---

## 6. Sửa code thì phải làm gì

Đây là chỗ nhiều bạn sai nhất:

| Bạn sửa gì | Cần làm gì |
|---|---|
| Code trong `backend/` | `docker compose up -d --build` ← **phải build lại** |
| File `.env` | `docker compose up -d` (Compose tự tạo lại container) |
| `docker-compose.yml` | `docker compose up -d` |
| Code trong `agent/` | Không cần Docker — agent chạy trực tiếp bằng Python trên máy thật |

**Vì sao?** Vì code đã được **copy vào image** lúc build. Sửa file trên máy bạn
không tự động vào trong container.

---

## 7. Lỗi kinh điển và cách xử lý

### `Bind for 0.0.0.0:6379 failed: port is already allocated`

Đã có thứ khác chiếm cổng — thường là **chính stack của bạn đang chạy**. Kiểm tra:

```powershell
docker compose ps
Get-NetTCPConnection -LocalPort 6379 -State Listen
```

Nếu stack đang chạy rồi thì **không cần `up` nữa**. Chỉ `up -d` khi nó đang tắt.

### Container `restarting` liên tục

```powershell
docker compose logs --tail 100 api
```

Phần lớn là do thiếu `.env` hoặc sai `DATABASE_URL`.

### Mất toàn bộ cảnh báo sau khi `down -v`

Đúng như thiết kế — `-v` xóa volume. Lần sau dùng `down` (không có `-v`).

### `docker: command not found`

Docker Desktop chưa chạy, hoặc bạn chưa mở terminal mới sau khi cài.

### Agent không gửi được event

```powershell
# Agent có đang chạy?
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like "*mini_soc_agent*" }

# API có nhận không?
docker compose logs --tail 30 api
```

Nhớ: agent chạy **ngoài** Docker, trên máy thật. Docker Desktop trên Windows chạy
container trong VM WSL2 nên **không thấy được tiến trình của Windows host**.

---

## 8. Kịch bản demo khi bảo vệ đồ án

```powershell
# --- Terminal 1: bật hệ thống ---
docker compose up -d
docker compose ps                    # cho hội đồng thấy 4 container healthy
curl http://127.0.0.1:8000/health

# --- Terminal 2: chạy agent ---
cd agent
python -m mini_soc_agent.agent --server http://127.0.0.1:8000 --watch-dir ..\sandbox

# --- Terminal 3: tấn công ---
cd attack_sim
python discovery.py
python ransomware_sim.py

# --- Quay lại Terminal 1: cho hội đồng xem cảnh báo ---
docker compose logs -f worker
```

Sau đó mở <http://127.0.0.1:8000/docs> → `GET /api/v1/alerts` → thấy `T1486 critical`.

> Nếu console Windows báo `UnicodeEncodeError: 'charmap' codec can't encode`,
> đặt trước khi chạy:
> ```powershell
> $env:PYTHONIOENCODING = "utf-8"; $env:PYTHONUTF8 = "1"
> ```

---

## 9. Dọn ổ đĩa (khi Docker ngốn dung lượng)

```powershell
docker system df          # xem cái gì đang chiếm chỗ
docker system prune -f    # xóa container/image không dùng
docker builder prune -f   # xóa cache build
```

Nếu máy từng chạy nhiều bản Mini-SOC song song, kiểm tra:

```powershell
docker compose ls -a      # liệt kê mọi project compose + đường dẫn file
```

Mỗi dòng là một bản độc lập. Bản nào nằm trong thư mục tạm thì xóa được:

```powershell
cd <đường-dẫn-bản-tạm>
docker compose down -v
```

---

## 10. Tóm lại một câu

> **Image là bản cài, container là bản đang chạy, volume là dữ liệu.**
> `up -d` để bật, `ps` để kiểm tra, `logs` để soi lỗi, `stop` để tắt,
> `down -v` để xóa sạch.
