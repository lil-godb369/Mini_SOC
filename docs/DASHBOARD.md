# Dashboard Mini SOC

## Sử dụng

Tại gốc repo:

```powershell
docker compose up -d --build api worker
```

Mở http://127.0.0.1:8000/dashboard/ và đăng nhập bằng tài khoản đang có trong CSDL.
Tài khoản đầu tiên được tạo từ `ADMIN_EMAIL` / `ADMIN_PASSWORD` khi CSDL chưa có
user. Không gửi `.env` hoặc mật khẩu lên GitHub.

- Chọn mức độ, trạng thái, nguồn, tên máy chính xác rồi nhấn **Áp dụng**.
- **Chi tiết** mở bằng chứng JSON và thông tin MITRE ATT&CK.
- Chọn **Đang điều tra** / **Đã xử lý** rồi nhấn **Lưu trạng thái**. Cập nhật
  được lưu trong PostgreSQL. Nếu không còn khớp bộ lọc, hàng sẽ biến mất khỏi bảng.
- **Xóa lọc** trở lại toàn bộ danh sách; mỗi trang có 20 cảnh báo.
- **Tự cập nhật 15s** tải lại dữ liệu khi tab đang hiển thị và không xem chi tiết.
- Hết phiên hoặc tải lại trang thì đăng nhập lại; token chỉ tồn tại trong bộ nhớ.
- Đăng xuất đóng chi tiết và bỏ token, không dừng agent/backend.

Các thẻ tổng quan không phụ thuộc bộ lọc: event/cảnh báo 24 giờ, cảnh báo chưa
đóng trên toàn thời gian, agent liên lạc trong 5 phút. Trạng thái “Đã xử lý” là
phân loại của người phân tích, không tự động diệt tiến trình hay khôi phục file.

Để dừng lab và giữ dữ liệu: dừng agent bằng Ctrl+C, rồi `docker compose stop`.

## Kiểm thử

Backend test chạy trong container riêng với SQLite/Redis giả, không dùng DB lab:

```powershell
docker compose build api
docker run --rm --mount "type=bind,source=${PWD},target=/workspace,readonly" -w /workspace mini-soc-api python -m pytest -p no:cacheprovider backend/tests
```

Browser test cần API đã bật, Node.js và Playwright (chỉ là dependency phát triển):

```powershell
cd tests/browser
npm ci
npx playwright install chromium
npm test
```

Trên Windows đã có Edge có thể thay bước tải Chromium bằng:

```powershell
$env:BROWSER_CHANNEL = "msedge"
npm test
```

Mặc định kiểm tra UI với API fixtures: đăng nhập sai/đúng, phân trang, bộ lọc,
bằng chứng chứa chuỗi HTML, cập nhật trạng thái, trạng thái trống, lỗi API,
hết phiên và màn hình điện thoại. Không sửa dữ liệu lab. Ảnh kiểm thử nằm trong
`tests/browser/artifacts/` (đã ignore).

`npm test -- --live` bổ sung kiểm tra đăng nhập/đọc cảnh báo/đăng xuất với Docker
thật, đọc thông tin quản trị từ `.env` cục bộ. Không đổi trạng thái cảnh báo thật.
Nếu mật khẩu đã được đổi trong CSDL, thông tin seed trong `.env` có thể không
đăng nhập được. Có thể dùng `BASE_URL` để đổi địa chỉ đích.

## Thiết kế và tham chiếu

HTML/CSS/JavaScript được đóng gói tại `backend/app/dashboard`, FastAPI phục vụ
cùng origin. Giữ nguyên JWT API, không thêm dependency frontend khi chạy.
Nội dung cảnh báo được chèn bằng `textContent`; dashboard có CSP chỉ cho script
và style cùng origin, chống nhúng iframe và `nosniff`.

Áp dụng các phần phù hợp từ ECC `security-review` và `e2e-testing`:
[nguồn, commit và giấy phép](reference/ecc/README.md). Không cài hooks hoặc cấu
hình toàn cục của ECC. Dashboard này vẫn là bản tối thiểu; chưa có SSE, thông
báo bên ngoài hay tự động ứng phó sự cố.
