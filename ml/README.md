# Lớp 2 — Phát hiện xâm nhập bằng học máy

Huấn luyện mô hình phát hiện tấn công trên lưu lượng mạng, dùng bộ dữ liệu
**CIC-IDS2017**.

## Chạy nhanh (không cần tải bộ dữ liệu thật)

Đường ống chạy được ngay bằng dữ liệu tổng hợp, để kiểm thử code trước khi bộ
dữ liệu 2.8 GB tải xong:

```powershell
cd ml
..\.venv\Scripts\python.exe -m pip install -r requirements.txt

..\.venv\Scripts\python.exe synthetic.py --out data/raw_synthetic --rows-per-day 20000
..\.venv\Scripts\python.exe train.py --data-dir data/raw_synthetic --processed-dir "" --out artifacts
```

> ⚠️ Số liệu chạy trên dữ liệu tổng hợp **không được** đưa vào báo cáo như kết
> quả thực nghiệm. Nó chỉ chứng minh đường ống chạy đúng.

## Chạy thật với CIC-IDS2017

### 1. Tải dữ liệu

Nguồn chính thức: <https://www.unb.ca/cic/datasets/ids-2017.html>

Tải thư mục **`MachineLearningCSV`** (khoảng 500 MB nén — đây là bản đã trích
xuất sẵn đặc trưng luồng, đủ dùng cho toàn bộ phần huấn luyện). Giải nén 8 tệp
CSV vào `ml/data/raw/`:

```
ml/data/raw/
├── Monday-WorkingHours.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
├── Wednesday-workingHours.pcap_ISCX.csv
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
├── Friday-WorkingHours-Morning.pcap_ISCX.csv
├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
└── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

### 2. Tiền xử lý (tuỳ chọn — giúp lần huấn luyện sau nhanh hơn nhiều)

```powershell
..\.venv\Scripts\python.exe preprocess.py --data-dir data/raw --out data/processed
```

### 3. Huấn luyện

```powershell
# Bài toán nhị phân, chia theo ngày — đây là kết quả chính đưa vào báo cáo
..\.venv\Scripts\python.exe train.py --task binary --split day --out artifacts

# Đa lớp, chia phân tầng — dùng cho bảng số liệu chi tiết từng kiểu tấn công
..\.venv\Scripts\python.exe train.py --task multiclass --split stratified --out artifacts_multiclass
```

Đầu ra trong `artifacts/`:

| Tệp | Nội dung |
|---|---|
| `random_forest.joblib` | Mô hình + danh sách đặc trưng + siêu dữ liệu |
| `xgboost.joblib` | " |
| `isolation_forest.joblib` | Đường cơ sở không giám sát |
| `metrics.json` | Toàn bộ số liệu, dán thẳng vào báo cáo |
| `confusion_matrix_*.png` | Ma trận nhầm lẫn |

### 4. Bật suy luận trong hệ thống

Trong `.env`:

```
ENABLE_ML_NETWORK=true
```

Rồi `docker compose restart worker`.

---

## Hai quyết định phương pháp luận cần bảo vệ được

Đây là hai chỗ hội đồng sẽ hỏi, và là lý do kết quả của đồ án này **thấp hơn**
con số 99,9% thường thấy trong các bài báo về CIC-IDS2017.

### 1. Chia theo NGÀY, không chia ngẫu nhiên

Các luồng trong CIC-IDS2017 sinh ra theo phiên. Hai luồng liên tiếp của cùng một
phiên tấn công gần như giống hệt nhau. Chia ngẫu nhiên đặt luồng thứ nhất vào
tập huấn luyện và luồng thứ hai vào tập kiểm thử — mô hình chỉ cần **nhớ**, và
F1 vọt lên ~0,999.

Chia theo ngày (huấn luyện thứ Hai–Tư, kiểm thử thứ Năm–Sáu) khắc nghiệt hơn
nhiều: các kiểu tấn công của tập kiểm thử (Web Attack, Infiltration, Bot,
PortScan, DDoS) **hoàn toàn không xuất hiện** khi huấn luyện. Ta đang đo đúng
thứ mà một SMB cần: mô hình có phát hiện được kiểu tấn công **chưa từng thấy**
hay không.

### 2. Bỏ cột `Destination Port`

Cột này tương quan gần như hoàn hảo với nhãn, vì trong CIC-IDS2017 mỗi họ tấn
công nhắm vào một dải cổng cố định. Giữ nó lại thì mô hình chỉ học
"cổng 21 = FTP-Patator" — đạt điểm rất cao mà không học được gì về **hành vi**.
Đưa mô hình đó ra mạng thật là sập ngay.

Muốn tự kiểm chứng ảnh hưởng của nó:

```powershell
..\.venv\Scripts\python.exe train.py --keep-destination-port --out artifacts_with_port
```

So `metrics.json` của hai lần chạy — chênh lệch chính là mức độ mô hình đang
"ăn gian". Đây là một thí nghiệm tốt để đưa vào báo cáo.

---

## Vì sao chọn mô hình cây tập hợp, không dùng deep learning

1. **Dữ liệu dạng bảng.** CIC-IDS2017 là đặc trưng thống kê của luồng, không
   phải ảnh hay chuỗi. Trên dữ liệu bảng, cây tập hợp (RandomForest, XGBoost)
   thắng mạng nơ-ron sâu một cách nhất quán trong tài liệu nghiên cứu.
2. **Không có GPU.** Huấn luyện RandomForest trên CPU mất vài phút; mạng sâu mất
   hàng giờ và không cho kết quả tốt hơn.
3. **Giải thích được.** Cây cho ra độ quan trọng đặc trưng, nên khi mô hình báo
   động ta còn biết nó dựa vào cái gì. Với người dùng SMB không có chuyên môn an
   ninh, đây không phải điều xa xỉ — đó là điều kiện để họ tin và hành động.

## Ba mô hình được so sánh

| Mô hình | Kiểu | Vai trò trong báo cáo |
|---|---|---|
| RandomForest | Có giám sát | Đường cơ sở, cho độ quan trọng đặc trưng |
| XGBoost | Có giám sát | Thường nhỉnh hơn vài phần trăm |
| IsolationForest | **Không giám sát** | Trả lời câu hỏi thực tế: SMB không có dữ liệu tấn công đã gán nhãn thì làm được đến đâu? |

## Số liệu nào cần đọc

`metrics.json` ghi nhiều chỉ số, nhưng khi trình bày hãy nhấn vào:

- **macro-F1** — đối xử mọi lớp như nhau, nên phơi bày việc bỏ sót lớp hiếm.
  Hơn 80% dữ liệu là lành tính, nên *accuracy* và *weighted-F1* luôn trông đẹp
  một cách sai lệch.
- **recall của lớp tấn công** — bỏ sót bao nhiêu phần trăm cuộc tấn công.
- **tỉ lệ báo động giả** — chỉ số quyết định hệ thống có dùng được ở SMB không.
  Người dùng không có đội SOC sẽ tắt hệ thống nếu nó kêu suốt ngày.

Bảng số liệu từng lớp trong `per_class` sẽ cho thấy các lớp cực hiếm
(Heartbleed 11 mẫu, Infiltration 36 mẫu trên 2,8 triệu dòng) gần như không thể
học được. **Hãy báo cáo thẳng điều đó** thay vì giấu sau con số trung bình —
đó là một phát hiện thật về giới hạn của phương pháp, không phải một thất bại.
