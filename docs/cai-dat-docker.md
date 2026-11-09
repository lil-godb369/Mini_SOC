# Cài đặt Docker — trạng thái và các bước còn lại

> Cài xong rồi? Hướng dẫn **vận hành hàng ngày** (bật/tắt, xem log, debug, dọn ổ đĩa)
> nằm ở [`HUONG-DAN-DOCKER.md`](HUONG-DAN-DOCKER.md).

## Đã xong

| Thành phần | Trạng thái |
|---|---|
| WSL2 | ✅ Đã cài, phiên bản 2.7.11, mặc định version 2 |
| Docker Desktop | ✅ Đã cài, CLI 29.6.2 |
| Bộ cài | `D:\DockerDesktopInstaller.exe` (596 MB, chữ ký `CN=Docker Inc` hợp lệ) |
| Log cài đặt | `D:\install-docker.log` |

## ⚠️ Còn lại: khởi động lại máy

WSL2 chưa hoạt động cho tới khi reboot. Lưu hết việc đang làm rồi khởi động lại.

## Sau khi khởi động lại — chạy đúng thứ tự

### Bước 1 — Chuyển kho dữ liệu Docker sang ổ D

**Làm bước này TRƯỚC khi kéo image.** Ổ C: chỉ còn ~5.7 GB sau khi cài Docker;
để mặc định thì mọi image và volume sẽ tiếp tục ghi vào C: cho tới khi hết đĩa.

Mở Docker Desktop một lần cho nó khởi tạo xong (biểu tượng cá voi ở khay hệ
thống chuyển sang trạng thái *Running*), rồi **thoát hẳn Docker Desktop**
(chuột phải biểu tượng → Quit Docker Desktop). Sau đó, trong PowerShell:

```powershell
wsl --manage docker-desktop --move D:\DockerData
```

Kiểm tra đã chuyển đúng chưa:

```powershell
wsl --list --verbose
[math]::Round((Get-PSDrive C).Free/1GB,1)   # phải tăng lên đáng kể
```

> Nếu lệnh `--move` báo lỗi "distribution is running", nghĩa là Docker Desktop
> chưa thoát hẳn. Chạy `wsl --shutdown` rồi thử lại.

Cách khác qua giao diện: **Docker Desktop → Settings → Resources → Advanced →
Disk image location → `D:\DockerData` → Apply & Restart**.

### Bước 2 — Dựng hệ thống

```powershell
cd "D:\Code\System Sercurity\mini-soc"
copy .env.example .env
```

Mở `.env`, đổi **4 giá trị bắt buộc** (xem README, mục "Cài đặt và chạy"):
`JWT_SECRET`, `POSTGRES_PASSWORD` (nhớ sửa cả trong `DATABASE_URL`),
`ADMIN_PASSWORD`, `AGENT_ENROLL_TOKEN`.

Sinh khoá ngẫu nhiên:

```powershell
py -c "import secrets; print(secrets.token_urlsafe(48))"
```

Rồi:

```powershell
docker compose up -d
docker compose ps          # cả 4 service phải healthy/running
curl http://127.0.0.1:8000/health
```

### Bước 3 — Chạy agent và demo

Xem README, mục "Chạy agent trên máy cần giám sát" và "Demo phát hiện tấn công".

## Khắc phục sự cố

| Triệu chứng | Nguyên nhân thường gặp |
|---|---|
| `docker: command not found` | Chưa reboot, hoặc PATH của cửa sổ terminal cũ chưa cập nhật — mở terminal mới |
| Docker Desktop kẹt ở "Starting" | WSL2 chưa sẵn sàng; chạy `wsl --shutdown` rồi mở lại Docker Desktop |
| `no space left on device` | Chưa làm Bước 1. Chạy `docker system prune -a` rồi chuyển kho sang D: |
| `port is already allocated` | Cổng 5432/6379/8000 đang bị chiếm; đổi `POSTGRES_PORT`/`REDIS_PORT`/`API_PORT` trong `.env` |
| Container `api` khởi động rồi tắt ngay | Xem `docker compose logs api` — hầu hết là do `DATABASE_URL` trong `.env` không khớp `POSTGRES_PASSWORD` |
