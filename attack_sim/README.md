# Mô phỏng tấn công (lớp đỏ)

Hành vi rule đã được tinh chỉnh: xem [docs/DETECTION.md](../docs/DETECTION.md).
Dry-run persistence không kỳ vọng alert; file-burst hiện là Medium, chưa xác nhận
mã hóa. Bảng kỳ vọng dưới đây đã cập nhật; chưa đảm bảo collector polling bắt đủ event.

> ⚠️ **Đọc trước khi chạy.** Các kịch bản này tồn tại để CHỨNG MINH hệ thống phát
> hiện được, không phải để gây hại. Tất cả đều vô hại và có thể hoàn tác. Chỉ
> chạy trên máy của chính bạn hoặc máy ảo trong lab.

## Nguyên tắc an toàn

| Kịch bản | Kỹ thuật | Nó làm gì | Hoàn tác |
|---|---|---|---|
| `discovery.py` | T1057, T1082 | Chạy một loạt lệnh do thám **chỉ đọc** (`whoami`, `ipconfig`…) | Không cần — không thay đổi gì |
| `persistence_sim.py` | T1547.001 | Mặc định chỉ **in ra** lệnh tạo tự khởi động | `--for-real` mới ghi thật, và in sẵn lệnh gỡ |
| `ransomware_sim.py` | T1486 | XOR đảo ngược được các file **chỉ trong `sandbox/`** | `--restore` |

`ransomware_sim.py` sẽ **từ chối chạy** nếu đường dẫn sandbox nằm ngoài thư mục
làm việc hiện tại. Đây là chốt chặn cố ý: một lỗi gõ nhầm đường dẫn không được
phép biến kịch bản demo thành sự cố thật.

## Cách chạy

Cần agent đang chạy và trỏ vào cùng thư mục sandbox:

```powershell
# Cửa sổ 1 — agent
cd agent
python -m mini_soc_agent.agent --server http://127.0.0.1:8000 --watch-dir ..\sandbox

# Cửa sổ 2 — mô phỏng
cd attack_sim
python discovery.py
python ransomware_sim.py
python ransomware_sim.py --restore     # trả file về nguyên trạng
```

Xem cảnh báo hiện lên trong log của worker, hoặc gọi
`GET /api/v1/alerts` hoặc dashboard tại `/dashboard/`.

## Cảnh báo mong đợi

| Chạy | Cảnh báo mong đợi |
|---|---|
| `discovery.py` | `T1057-discovery-burst` (medium) và thường kèm `T1059.001-suspicious-powershell` (high) |
| `persistence_sim.py` | Dry-run: không kỳ vọng alert; chạy thật trên Windows cần collector bắt được reg add |
| `ransomware_sim.py` | `T1486-mass-file-encryption` (medium); heuristic có điểm/mức riêng nếu được bật |

Nếu cảnh báo **không** xuất hiện, xem mục "Khắc phục sự cố" trong README gốc —
thường là do agent chưa được trỏ đúng vào thư mục sandbox.
