# Hướng dẫn chạy Mini-SOC

Tài liệu này hướng dẫn chạy hệ thống từ đầu và trình diễn khả năng phát hiện tấn
công. Mọi lệnh đều đã được kiểm chứng trên chính máy này.

---

## Phần 0 — Trạng thái hiện tại

Máy bạn **đã được cài đặt xong**:

| Thành phần | Trạng thái |
|---|---|
| Docker Desktop + WSL2 | ✅ Đã cài, kho dữ liệu ở `D:\DockerData` |
| 4 container | ✅ Đang chạy |
| Môi trường Python (`.venv`) | ✅ Đã cài đủ thư viện |
| File `.env` | ✅ Đã tạo với khoá bí mật ngẫu nhiên |
| Sandbox | ✅ Sạch, 20 file `.txt` |

Nếu vừa khởi động lại máy, xem [Phần 5 — Khởi động lại từ đầu](#phần-5--khởi-động-lại-từ-đầu).

---

## Phần 1 — Lấy thông tin đăng nhập

Mật khẩu quản trị và token đăng ký agent nằm trong `.env`. Lấy ra bằng:

```powershell
cd "D:\Code\System Sercurity\mini-soc"

# Mật khẩu đăng nhập dashboard
(Select-String -Path .env -Pattern '^ADMIN_PASSWORD=(.+)$').Matches.Groups[1].Value

# Token để agent đăng ký lần đầu
(Select-String -Path .env -Pattern '^AGENT_ENROLL_TOKEN=(.+)$').Matches.Groups[1].Value
```

Tài khoản đăng nhập: **`admin@minisoc.local`**

> `.env` nằm trong `.gitignore` — đừng commit lên git.

---

## Phần 2 — Kiểm tra hệ thống đang chạy

```powershell
cd "D:\Code\System Sercurity\mini-soc"
docker compose ps
```

Kết quả mong đợi: 4 dịch vụ `running`, trong đó `api`, `postgres`, `redis` là
`healthy`.

Kiểm tra sức khoẻ:

```powershell
curl http://127.0.0.1:8000/health
```

Phải trả về:

```json
{"status":"ok","checks":{"api":"ok","database":"ok","redis":"ok"}}
```

**Tài liệu API tự sinh:** mở trình duyệt vào <http://127.0.0.1:8000/docs> — bạn
thử được mọi endpoint ngay trên giao diện đó.

---

## Phần 3 — Chạy demo phát hiện tấn công

Cần **2 cửa sổ PowerShell** chạy song song.

### Cửa sổ 1 — Agent (để nguyên, không tắt)

```powershell
cd "D:\Code\System Sercurity\mini-soc\agent"
..\.venv\Scripts\python.exe -m mini_soc_agent.agent `
    --server http://127.0.0.1:8000 `
    --watch-dir ..\sandbox `
    --poll-interval 0.25
```

Lần đầu chạy trên một máy mới, thêm `--enroll-token <TOKEN>` (lấy ở Phần 1).
Máy này đã đăng ký rồi nên không cần nữa — API key đã được lưu lại.

Thấy dòng này là agent đã sẵn sàng:

```
[agent] Agent đang chạy. Nhấn Ctrl+C để dừng.
```

> `--poll-interval 0.25` cho agent quét tiến trình 4 lần/giây. Mặc định là 0.5s,
> nhưng khi demo thì quét dày hơn sẽ bắt được nhiều tiến trình ngắn hơn.

### Cửa sổ 2 — Mô phỏng tấn công

```powershell
cd "D:\Code\System Sercurity\mini-soc\attack_sim"

# T1057 — cụm lệnh do thám
..\.venv\Scripts\python.exe discovery.py

# T1547.001 — duy trì truy cập (chạy khô, không đổi gì trên máy)
..\.venv\Scripts\python.exe persistence_sim.py

# T1486 — ransomware mã hoá hàng loạt (CHỈ trong thư mục sandbox)
..\.venv\Scripts\python.exe ransomware_sim.py
```

### Xem cảnh báo

Mở **cửa sổ thứ 3**:

```powershell
cd "D:\Code\System Sercurity\mini-soc"
docker compose logs -f worker
```

Bạn sẽ thấy:

```
CẢNH BÁO [HIGH]     PowerShell / trình thông dịch lệnh đáng ngờ   T1059.001
CẢNH BÁO [CRITICAL] Nghi vấn ransomware (sửa đổi file hàng loạt)  T1486
CẢNH BÁO [HIGH]     Hành vi mã hoá hàng loạt (điểm 0.78)          T1486
```

### ⚠️ Hoàn tác sau khi demo ransomware

```powershell
cd "D:\Code\System Sercurity\mini-soc\attack_sim"
..\.venv\Scripts\python.exe ransomware_sim.py --restore
```

Kịch bản này chỉ ghi trong thư mục `sandbox/` và có chốt chặn từ chối chạy nếu
bạn trỏ ra ngoài thư mục dự án.

---

## Phần 4 — Xem cảnh báo qua API

Chưa có dashboard web (Tuần 3), nên tạm xem qua API. Dán cả khối này vào
PowerShell:

```powershell
cd "D:\Code\System Sercurity\mini-soc"
$pw  = (Select-String -Path .env -Pattern '^ADMIN_PASSWORD=(.+)$').Matches.Groups[1].Value
$tok = (Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/auth/login" `
        -Method Post -ContentType "application/json" `
        -Body (@{email="admin@minisoc.local"; password=$pw} | ConvertTo-Json)).access_token
$h = @{ Authorization = "Bearer $tok" }

# Danh sách cảnh báo
$alerts = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/alerts?limit=20" -Headers $h
$alerts.items | Select-Object severity, source, technique, title | Format-Table -AutoSize

# Thống kê tổng quan
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/stats/overview" -Headers $h |
    Select-Object total_events, total_alerts, open_alerts, agents_online
```

### Xem bằng chứng giải thích được của cảnh báo ransomware

Đây là điểm đáng trình bày nhất khi bảo vệ — hệ thống nói rõ **vì sao** nó báo động:

```powershell
$r = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/alerts?source=ransomware" -Headers $h
$e = $r.items[0].evidence
Write-Output ("Diem tong: {0}" -f $e.score)
$e.signals.PSObject.Properties | ForEach-Object {
    [PSCustomObject]@{
        'Tin hieu' = $_.Name
        'Gia tri'  = $_.Value.value
        'Trong so' = $_.Value.weight
        'Dong gop' = $_.Value.contribution
    }
} | Format-Table -AutoSize
Write-Output ("{0} file, {1} file entropy cao, {2} file/giay" -f `
    $e.files_written, $e.high_entropy_files, $e.write_rate_per_second)
```

Kết quả mẫu đã đo được trên máy này:

| Tín hiệu | Giá trị | Trọng số | Đóng góp |
|---|---|---|---|
| entropy | 0.90 | 0.40 | 0.360 |
| write_rate | 0.978 | 0.25 | 0.245 |
| extension | 0.70 | 0.25 | 0.175 |
| dir_spread | 0.00 | 0.10 | 0.000 |
| **Tổng** | | | **0.78** → mức `high` |

---

## Phần 5 — Khởi động lại từ đầu

Sau khi tắt/bật máy:

```powershell
# 1. Mở Docker Desktop, chờ biểu tượng cá voi chuyển sang "Running"

# 2. Bật lại các container
cd "D:\Code\System Sercurity\mini-soc"
docker compose up -d

# 3. Kiểm tra
docker compose ps
curl http://127.0.0.1:8000/health
```

Dữ liệu (cảnh báo, event, tài khoản) được lưu trong Docker volume nên **không
mất** khi tắt máy.

### Dừng hệ thống

```powershell
docker compose stop           # dừng, giữ nguyên dữ liệu
docker compose down           # xoá container, VẪN giữ dữ liệu
docker compose down -v        # ⚠️ xoá cả dữ liệu, về trạng thái trắng
```

---

## Phần 6 — Chạy bộ test

```powershell
cd "D:\Code\System Sercurity\mini-soc"
.\.venv\Scripts\python.exe -m pytest
```

Kết quả mong đợi: **152 passed**.

Test **không cần** Docker, Postgres, Redis hay bộ dữ liệu CIC-IDS2017 — dùng
SQLite tạm, Redis giả và dữ liệu tổng hợp. Chạy hết dưới 10 giây.

Chạy riêng từng phần:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -v    # API + lõi phát hiện
.\.venv\Scripts\python.exe -m pytest agent/tests -v      # bộ thu thập của agent
.\.venv\Scripts\python.exe -m pytest ml/tests -v         # tiền xử lý dữ liệu
```

---

## Phần 7 — Bật/tắt từng module

Sửa `.env`:

```
ENABLE_RULE_ENGINE=true            # rule ATT&CK
ENABLE_RANSOMWARE_BEHAVIOR=true    # phân tích hành vi entropy
ENABLE_ML_NETWORK=false            # mô hình ML mạng (cần huấn luyện trước)
ENABLE_LLM_ASSISTANT=false         # trợ lý AI (Tuần 3)
```

⚠️ **Sau khi sửa `.env`, phải tạo lại container — `restart` KHÔNG đủ:**

```powershell
docker compose up -d --force-recreate worker
```

Lý do: biến môi trường được gắn vào container lúc **tạo**, không phải lúc khởi
động lại. Đây là chỗ rất dễ nhầm.

Kiểm tra module nào đang bật:

```powershell
docker compose logs worker --tail 5
```

Dòng cuối sẽ ghi rõ: `ransomware=bật, ml_mạng=tắt`.

---

## Phần 8 — Huấn luyện mô hình ML (tuỳ chọn)

Xem hướng dẫn đầy đủ ở [`ml/README.md`](ml/README.md). Tóm tắt:

```powershell
cd "D:\Code\System Sercurity\mini-soc\ml"

# Chạy thử ngay bằng dữ liệu tổng hợp (không cần tải gì)
..\.venv\Scripts\python.exe synthetic.py --out data/raw_synthetic --rows-per-day 20000
..\.venv\Scripts\python.exe train.py --data-dir data/raw_synthetic --out artifacts
```

⚠️ Số liệu từ dữ liệu tổng hợp **không được** đưa vào báo cáo. Muốn có số liệu
thật, tải **CIC-IDS2017** (thư mục `MachineLearningCSV`, ~500 MB) từ
<https://www.unb.ca/cic/datasets/ids-2017.html> vào `ml/data/raw/` rồi chạy:

```powershell
..\.venv\Scripts\python.exe train.py --task binary --split day --out artifacts
```

---

## Khắc phục sự cố

| Triệu chứng | Cách xử lý |
|---|---|
| `docker: command not found` | Mở cửa sổ PowerShell **mới** (PATH cũ chưa cập nhật) |
| Docker Desktop kẹt "Starting" | `wsl --shutdown` rồi mở lại Docker Desktop |
| `port is already allocated` | Đổi `API_PORT`/`POSTGRES_PORT`/`REDIS_PORT` trong `.env` |
| Container `api` bật rồi tắt ngay | `docker compose logs api` — thường do `DATABASE_URL` không khớp `POSTGRES_PASSWORD` |
| Agent báo `API key bị từ chối` | Xoá file trạng thái rồi đăng ký lại: `%PROGRAMDATA%\.mini-soc\agent.json` |
| Không thấy cảnh báo nào | Kiểm tra agent có trỏ đúng `--watch-dir ..\sandbox` không |
| Đổi `.env` mà không có tác dụng | Phải `docker compose up -d --force-recreate worker` |
| `no space left on device` | `docker system prune -a` (ổ C: đang hẹp) |

### Cảnh báo T1057 không xuất hiện?

Đây là **hạn chế đã biết**, không phải lỗi. Agent quét tiến trình theo chu kỳ nên
bỏ sót các lệnh sống dưới 100ms (`whoami`, `hostname`, `ipconfig`). Rule cần 4
tiến trình mới kích hoạt.

Chỉ agent mức kernel (ETW/eBPF) mới xử lý triệt để. Điều này đã ghi trong mục
"Hạn chế đã biết" của `README.md` — và bản thân nó là **bằng chứng thực nghiệm**
cho luận điểm "cần telemetry mức kernel", đáng đưa vào báo cáo.

---

## Tóm tắt lệnh hay dùng

```powershell
cd "D:\Code\System Sercurity\mini-soc"

docker compose up -d                        # bật hệ thống
docker compose ps                           # xem trạng thái
docker compose logs -f worker               # theo dõi cảnh báo trực tiếp
docker compose up -d --force-recreate worker # nạp lại .env
docker compose stop                         # tắt

.\.venv\Scripts\python.exe -m pytest        # chạy test
```
